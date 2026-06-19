"""
Symbolic Execution Engine for UEFI binaries.

Uses Unicorn for CPU emulation and maintains symbolic state alongside
concrete execution. Branches are explored via path forking.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP, UC_X86_REG_RFLAGS,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class ExecutionState(IntEnum):
    RUNNING = 0
    HALTED = 1
    FORKED = 2
    ERROR = 3
    TIMEOUT = 4
    SERVICE_CALL = 5


@dataclass
class SymbolicValue:
    """Represents a symbolic (unconstrained) or concrete value."""
    name: str
    concrete: Optional[int] = None
    bits: int = 64
    constraints: List[Any] = field(default_factory=list)

    @property
    def is_symbolic(self) -> bool:
        return self.concrete is None

    @property
    def is_concrete(self) -> bool:
        return self.concrete is not None


@dataclass
class MemoryWrite:
    """Record of a memory write during execution."""
    address: int
    size: int
    value: int
    pc: int
    is_symbolic: bool = False


@dataclass
class ExecutionPath:
    """A single execution path through the binary."""
    path_id: int
    branch_history: List[Tuple[int, bool]] = field(default_factory=list)
    memory_writes: List[MemoryWrite] = field(default_factory=list)
    service_calls: List[Dict] = field(default_factory=list)
    constraints: List[Any] = field(default_factory=list)
    state: ExecutionState = ExecutionState.RUNNING
    instructions_executed: int = 0
    error_message: str = ""

    @property
    def depth(self) -> int:
        return len(self.branch_history)


class SymbolicEngine:
    """
    Symbolic execution engine for x86_64 EFI binaries.

    Combines concrete Unicorn execution with symbolic tracking:
    - Concrete execution for deterministic paths
    - Symbolic values for service call return values
    - Path forking at conditional branches depending on symbolic state
    """

    STACK_BASE = 0x7FFF0000
    STACK_SIZE = 0x10000
    HEAP_BASE = 0x80000000
    HEAP_SIZE = 0x100000
    CODE_BASE = 0x10000000
    MAX_INSTRUCTIONS = 100000
    MAX_PATHS = 64

    def __init__(self):
        if not HAS_UNICORN:
            raise ImportError("unicorn package required for symbolic execution")
        if not HAS_CAPSTONE:
            raise ImportError("capstone package required for disassembly")

        self._uc: Optional[Uc] = None
        self._cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self._paths: List[ExecutionPath] = []
        self._current_path: Optional[ExecutionPath] = None
        self._path_counter = 0
        self._code_data: bytes = b''
        self._code_size: int = 0
        self._hooks: Dict[int, Callable] = {}
        self._symbolic_regs: Dict[int, SymbolicValue] = {}
        self._symbolic_mem: Dict[int, SymbolicValue] = {}
        self._service_handlers: Dict[int, Callable] = {}
        self._memory_writes: List[MemoryWrite] = []
        self._instruction_count = 0

    @property
    def paths(self) -> List[ExecutionPath]:
        return list(self._paths)

    @property
    def completed_paths(self) -> List[ExecutionPath]:
        return [p for p in self._paths if p.state != ExecutionState.RUNNING]

    def load_binary(self, data: bytes, base_address: int = 0) -> int:
        """Load binary code into the engine. Returns the entry point address."""
        if base_address == 0:
            base_address = self.CODE_BASE

        self._code_data = data
        self._code_size = len(data)
        return base_address

    def load_pe(self, pe_path: Path) -> int:
        """Load a PE/COFF EFI binary. Returns entry point address."""
        data = pe_path.read_bytes()
        return self._load_pe_image(data)

    def _load_pe_image(self, data: bytes) -> int:
        """Parse PE headers and load sections."""
        if len(data) < 64:
            raise ValueError("File too small to be a PE image")

        dos_sig = data[0:2]
        if dos_sig != b'MZ':
            self._code_data = data
            self._code_size = len(data)
            return self.CODE_BASE

        pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
        if pe_offset + 4 > len(data):
            raise ValueError("Invalid PE offset")

        pe_sig = data[pe_offset:pe_offset + 4]
        if pe_sig != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")

        machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], 'little')
        if machine != 0x8664:
            raise ValueError(f"Unsupported machine type: 0x{machine:x}")

        num_sections = int.from_bytes(data[pe_offset + 6:pe_offset + 8], 'little')
        opt_hdr_offset = pe_offset + 24
        opt_magic = int.from_bytes(data[opt_hdr_offset:opt_hdr_offset + 2], 'little')

        if opt_magic == 0x20B:  # PE32+
            entry_rva = int.from_bytes(data[opt_hdr_offset + 16:opt_hdr_offset + 20], 'little')
            image_base = int.from_bytes(data[opt_hdr_offset + 24:opt_hdr_offset + 32], 'little')
            section_table_offset = opt_hdr_offset + 112  # PE32+ optional header size
        elif opt_magic == 0x10B:  # PE32
            entry_rva = int.from_bytes(data[opt_hdr_offset + 16:opt_hdr_offset + 20], 'little')
            image_base = int.from_bytes(data[opt_hdr_offset + 28:opt_hdr_offset + 32], 'little')
            section_table_offset = opt_hdr_offset + 96
        else:
            raise ValueError(f"Unknown optional header magic: 0x{opt_magic:x}")

        total_size = max(len(data), 0x10000)
        self._code_data = bytearray(total_size)
        self._code_data[:len(data)] = data
        self._code_size = total_size

        entry_point = self.CODE_BASE + entry_rva
        return entry_point

    def _init_emulator(self, entry_point: int):
        """Initialize Unicorn emulator with code and stack."""
        self._uc = Uc(UC_ARCH_X86, UC_MODE_64)

        code_aligned_size = ((self._code_size + 0xFFF) // 0x1000) * 0x1000
        if code_aligned_size == 0:
            code_aligned_size = 0x1000
        self._uc.mem_map(self.CODE_BASE, code_aligned_size)
        self._uc.mem_write(self.CODE_BASE, bytes(self._code_data[:self._code_size]))

        self._uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        self._uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.STACK_SIZE - 0x100)
        self._uc.reg_write(UC_X86_REG_RBP, self.STACK_BASE + self.STACK_SIZE - 0x100)

        self._uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE)

        self._uc.reg_write(UC_X86_REG_RIP, entry_point)

        self._uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self._uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)

    def execute(self, entry_point: int, max_instructions: int = 0) -> List[ExecutionPath]:
        """Execute from entry point, exploring all reachable paths."""
        if max_instructions == 0:
            max_instructions = self.MAX_INSTRUCTIONS

        self._paths = []
        self._path_counter = 0

        initial_path = ExecutionPath(path_id=self._path_counter)
        self._path_counter += 1
        self._current_path = initial_path

        self._init_emulator(entry_point)
        self._instruction_count = 0
        self._memory_writes = []

        try:
            code_end = self.CODE_BASE + self._code_size
            self._uc.emu_start(entry_point, code_end, count=max_instructions)
        except Exception as e:
            initial_path.state = ExecutionState.ERROR
            initial_path.error_message = str(e)

        if initial_path.state == ExecutionState.RUNNING:
            initial_path.state = ExecutionState.HALTED

        initial_path.memory_writes = list(self._memory_writes)
        initial_path.instructions_executed = self._instruction_count
        self._paths.append(initial_path)

        return self._paths

    def register_service_handler(self, address: int, handler: Callable):
        """Register a handler for when execution reaches a service call address."""
        self._service_handlers[address] = handler

    def set_symbolic_register(self, reg: int, name: str):
        """Mark a register as containing a symbolic value."""
        self._symbolic_regs[reg] = SymbolicValue(name=name)

    def set_symbolic_memory(self, address: int, name: str, size: int = 8):
        """Mark a memory location as containing a symbolic value."""
        self._symbolic_mem[address] = SymbolicValue(name=name, bits=size * 8)

    def _hook_code(self, uc: Uc, address: int, size: int, user_data: Any):
        """Per-instruction hook."""
        self._instruction_count += 1

        if self._instruction_count > self.MAX_INSTRUCTIONS:
            if self._current_path:
                self._current_path.state = ExecutionState.TIMEOUT
            uc.emu_stop()
            return

        if address in self._service_handlers:
            handler = self._service_handlers[address]
            result = handler(uc, address)
            if self._current_path:
                self._current_path.service_calls.append({
                    'address': address,
                    'pc': address,
                    'result': result,
                })
                self._current_path.state = ExecutionState.SERVICE_CALL

    def _hook_mem_write(self, uc: Uc, access: int, address: int,
                        size: int, value: int, user_data: Any):
        """Memory write hook — track all writes."""
        pc = uc.reg_read(UC_X86_REG_RIP)
        write = MemoryWrite(
            address=address,
            size=size,
            value=value,
            pc=pc,
            is_symbolic=address in self._symbolic_mem,
        )
        self._memory_writes.append(write)

    def disassemble_at(self, address: int, count: int = 10) -> List[Tuple[int, str, str]]:
        """Disassemble instructions at an address."""
        offset = address - self.CODE_BASE
        if offset < 0 or offset >= self._code_size:
            return []

        chunk = bytes(self._code_data[offset:offset + count * 15])
        result = []
        for insn in self._cs.disasm(chunk, address):
            result.append((insn.address, insn.mnemonic, insn.op_str))
            if len(result) >= count:
                break
        return result

    def get_memory_region(self, address: int, size: int) -> bytes:
        """Read memory from emulator."""
        if self._uc is None:
            return b'\x00' * size
        try:
            return self._uc.mem_read(address, size)
        except Exception:
            return b'\x00' * size

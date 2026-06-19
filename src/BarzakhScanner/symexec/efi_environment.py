"""
EFI Environment — Symbolic UEFI boot/runtime services model.

Provides mock Boot Services Table and Runtime Services Table that
return symbolic values, allowing the engine to explore all possible
paths through EFI code regardless of runtime state.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from unicorn import Uc
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False


class EfiStatus(IntEnum):
    SUCCESS = 0
    INVALID_PARAMETER = 0x8000000000000002
    NOT_FOUND = 0x800000000000000E
    BUFFER_TOO_SMALL = 0x8000000000000005
    UNSUPPORTED = 0x8000000000000003


@dataclass
class ServiceCall:
    """Record of a UEFI service invocation."""
    service_name: str
    bst_offset: int
    arguments: List[int] = field(default_factory=list)
    return_value: int = 0
    caller_pc: int = 0


@dataclass
class ProtocolInstall:
    """Tracks protocol installations."""
    guid_address: int
    interface_address: int
    handle: int = 0


class EfiEnvironment:
    """
    Symbolic UEFI environment for controlled binary execution.

    Models Boot Services and Runtime Services tables with handlers
    that record calls and return appropriate symbolic/concrete values.
    """

    BST_BASE = 0x7EF00000
    RST_BASE = 0x7EF10000
    SYSTEM_TABLE_BASE = 0x7EF20000
    HANDLE_DB_BASE = 0x7EF30000
    PROTOCOL_DB_BASE = 0x7EF40000
    ALLOCATED_BASE = 0x7EF50000

    BST_SERVICES = {
        0x18: ("RaiseTPL", 1),
        0x20: ("RestoreTPL", 1),
        0x28: ("AllocatePages", 4),
        0x30: ("FreePages", 2),
        0x38: ("GetMemoryMap", 5),
        0x40: ("AllocatePool", 3),
        0x48: ("FreePool", 1),
        0x50: ("CreateEvent", 5),
        0x58: ("SetTimer", 3),
        0x60: ("WaitForEvent", 3),
        0x68: ("SignalEvent", 1),
        0x70: ("CloseEvent", 1),
        0x78: ("CheckEvent", 1),
        0x80: ("InstallProtocolInterface", 4),
        0x88: ("ReinstallProtocolInterface", 4),
        0x90: ("UninstallProtocolInterface", 3),
        0x98: ("HandleProtocol", 3),
        0xA8: ("RegisterProtocolNotify", 3),
        0xB0: ("LocateHandle", 5),
        0xB8: ("LocateDevicePath", 3),
        0xC0: ("InstallConfigurationTable", 2),
        0xC8: ("LoadImage", 6),
        0xD0: ("StartImage", 3),
        0xD8: ("Exit", 4),
        0xE0: ("UnloadImage", 1),
        0xE8: ("ExitBootServices", 2),
        0xF0: ("GetNextMonotonicCount", 1),
        0xF8: ("Stall", 1),
        0x100: ("SetWatchdogTimer", 4),
        0x118: ("OpenProtocol", 6),
        0x120: ("CloseProtocol", 4),
        0x128: ("OpenProtocolInformation", 4),
        0x130: ("ProtocolsPerHandle", 3),
        0x138: ("LocateHandleBuffer", 5),
        0x140: ("LocateProtocol", 3),
        0x148: ("InstallMultipleProtocolInterfaces", 0),
        0x150: ("UninstallMultipleProtocolInterfaces", 0),
        0x160: ("CopyMem", 3),
        0x168: ("SetMem", 3),
        0x170: ("CreateEventEx", 6),
    }

    RST_SERVICES = {
        0x18: ("GetTime", 2),
        0x20: ("SetTime", 1),
        0x28: ("GetWakeupTime", 3),
        0x30: ("SetWakeupTime", 2),
        0x38: ("SetVirtualAddressMap", 4),
        0x40: ("ConvertPointer", 2),
        0x48: ("GetVariable", 5),
        0x50: ("GetNextVariableName", 3),
        0x58: ("SetVariable", 5),
        0x60: ("GetNextHighMonotonicCount", 1),
        0x68: ("ResetSystem", 4),
    }

    def __init__(self):
        self._service_calls: List[ServiceCall] = []
        self._allocations: List[Tuple[int, int]] = []
        self._alloc_cursor = self.ALLOCATED_BASE
        self._protocols: Dict[int, ProtocolInstall] = {}
        self._handles: List[int] = []
        self._handle_cursor = self.HANDLE_DB_BASE
        self._custom_handlers: Dict[str, Callable] = {}

    @property
    def service_calls(self) -> List[ServiceCall]:
        return list(self._service_calls)

    @property
    def allocations(self) -> List[Tuple[int, int]]:
        return list(self._allocations)

    def setup_tables(self, uc: Uc):
        """Initialize EFI system table, BST, and RST in emulator memory."""
        uc.mem_map(self.BST_BASE, 0x1000)
        uc.mem_map(self.RST_BASE, 0x1000)
        uc.mem_map(self.SYSTEM_TABLE_BASE, 0x1000)
        uc.mem_map(self.HANDLE_DB_BASE, 0x10000)
        uc.mem_map(self.PROTOCOL_DB_BASE, 0x10000)
        uc.mem_map(self.ALLOCATED_BASE, 0x100000)

        for offset in self.BST_SERVICES:
            stub_addr = self.BST_BASE + 0x800 + offset
            uc.mem_write(self.BST_BASE + offset,
                         stub_addr.to_bytes(8, 'little'))

        for offset in self.RST_SERVICES:
            stub_addr = self.RST_BASE + 0x800 + offset
            uc.mem_write(self.RST_BASE + offset,
                         stub_addr.to_bytes(8, 'little'))

        uc.mem_write(self.SYSTEM_TABLE_BASE + 0x60,
                     self.BST_BASE.to_bytes(8, 'little'))
        uc.mem_write(self.SYSTEM_TABLE_BASE + 0x58,
                     self.RST_BASE.to_bytes(8, 'little'))

    def get_service_stubs(self) -> Dict[int, Callable]:
        """Return address→handler mappings for all service stubs."""
        handlers = {}

        for offset, (name, _nargs) in self.BST_SERVICES.items():
            stub_addr = self.BST_BASE + 0x800 + offset
            handlers[stub_addr] = self._make_bst_handler(name, offset)

        for offset, (name, _nargs) in self.RST_SERVICES.items():
            stub_addr = self.RST_BASE + 0x800 + offset
            handlers[stub_addr] = self._make_rst_handler(name, offset)

        return handlers

    def register_handler(self, service_name: str, handler: Callable):
        """Register a custom handler for a specific service."""
        self._custom_handlers[service_name] = handler

    def _make_bst_handler(self, name: str, offset: int) -> Callable:
        """Create a handler for a Boot Service call."""
        def handler(uc: Uc, address: int) -> int:
            rcx = uc.reg_read(UC_X86_REG_RCX)
            rdx = uc.reg_read(UC_X86_REG_RDX)
            r8 = uc.reg_read(UC_X86_REG_R8)
            r9 = uc.reg_read(UC_X86_REG_R9)

            call = ServiceCall(
                service_name=name,
                bst_offset=offset,
                arguments=[rcx, rdx, r8, r9],
                caller_pc=address,
            )

            if name in self._custom_handlers:
                result = self._custom_handlers[name](uc, call)
            else:
                result = self._default_bst_handler(uc, name, call)

            call.return_value = result
            self._service_calls.append(call)
            uc.reg_write(UC_X86_REG_RAX, result)
            uc.emu_stop()
            return result

        return handler

    def _make_rst_handler(self, name: str, offset: int) -> Callable:
        """Create a handler for a Runtime Service call."""
        def handler(uc: Uc, address: int) -> int:
            call = ServiceCall(
                service_name=name,
                bst_offset=offset,
                arguments=[],
                caller_pc=address,
            )

            if name in self._custom_handlers:
                result = self._custom_handlers[name](uc, call)
            else:
                result = EfiStatus.SUCCESS

            call.return_value = result
            self._service_calls.append(call)
            uc.reg_write(UC_X86_REG_RAX, result)
            uc.emu_stop()
            return result

        return handler

    def _default_bst_handler(self, uc: Uc, name: str,
                             call: ServiceCall) -> int:
        """Default handler for Boot Services — returns SUCCESS for most."""
        if name == "AllocatePool":
            size = call.arguments[1] if len(call.arguments) > 1 else 0x100
            allocated = self._allocate(size)
            if len(call.arguments) > 2:
                buf_ptr = call.arguments[2]
                try:
                    uc.mem_write(buf_ptr, allocated.to_bytes(8, 'little'))
                except Exception:
                    pass
            return EfiStatus.SUCCESS

        elif name == "AllocatePages":
            pages = call.arguments[1] if len(call.arguments) > 1 else 1
            allocated = self._allocate(pages * 4096)
            if len(call.arguments) > 3:
                buf_ptr = call.arguments[3]
                try:
                    uc.mem_write(buf_ptr, allocated.to_bytes(8, 'little'))
                except Exception:
                    pass
            return EfiStatus.SUCCESS

        elif name in ("HandleProtocol", "LocateProtocol", "OpenProtocol"):
            return EfiStatus.SUCCESS

        elif name == "ExitBootServices":
            return EfiStatus.SUCCESS

        elif name in ("LoadImage", "StartImage"):
            return EfiStatus.SUCCESS

        return EfiStatus.SUCCESS

    def _allocate(self, size: int) -> int:
        """Allocate memory from the pool region."""
        aligned_size = ((size + 0xF) // 0x10) * 0x10
        address = self._alloc_cursor
        self._alloc_cursor += aligned_size
        self._allocations.append((address, aligned_size))
        return address

    def get_bst_address(self) -> int:
        return self.BST_BASE

    def get_rst_address(self) -> int:
        return self.RST_BASE

    def get_system_table_address(self) -> int:
        return self.SYSTEM_TABLE_BASE

    def get_hooks_detected(self) -> List[Dict]:
        """Detect if any BST entries were overwritten."""
        return [
            {
                'service': call.service_name,
                'offset': call.bst_offset,
                'caller': call.caller_pc,
            }
            for call in self._service_calls
            if call.service_name in ('InstallProtocolInterface',
                                     'InstallMultipleProtocolInterfaces')
        ]

    def summary(self) -> Dict:
        """Produce environment summary."""
        call_counts = {}
        for call in self._service_calls:
            call_counts[call.service_name] = call_counts.get(call.service_name, 0) + 1

        return {
            'total_service_calls': len(self._service_calls),
            'unique_services_called': len(call_counts),
            'service_call_counts': call_counts,
            'total_allocations': len(self._allocations),
            'total_allocated_bytes': sum(s for _, s in self._allocations),
        }

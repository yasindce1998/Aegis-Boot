"""
Breakpoint Engine - GDB stub integration for UEFI breakpoints.

Uses QEMU's built-in GDB stub to set hardware breakpoints at
UEFI-relevant addresses (DXE dispatch, BST writes, etc.)

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple


class BreakpointType(Enum):
    SOFTWARE = 0  # INT3 / software breakpoint
    HARDWARE_EXEC = 1  # Hardware execution breakpoint
    HARDWARE_WRITE = 2  # Hardware write watchpoint
    HARDWARE_READ = 3  # Hardware read watchpoint
    HARDWARE_ACCESS = 4  # Hardware access (r/w) watchpoint


@dataclass
class Breakpoint:
    """A debugger breakpoint/watchpoint."""
    bp_id: int
    address: int
    bp_type: BreakpointType
    size: int = 1
    enabled: bool = True
    hit_count: int = 0
    condition: Optional[str] = None
    label: str = ""


@dataclass
class BreakpointHit:
    """Information about a breakpoint being triggered."""
    breakpoint: Breakpoint
    pc: int
    registers: Dict[str, int] = field(default_factory=dict)
    timestamp: float = 0.0
    stack_top: bytes = b''


class GDBProtocolError(Exception):
    """GDB remote protocol error."""
    pass


class BreakpointEngine:
    """
    GDB remote protocol client for QEMU's GDB stub.

    Provides breakpoint management, single-stepping, and register
    access for monitoring UEFI execution.
    """

    DEFAULT_GDB_PORT = 1234
    RECV_SIZE = 4096

    def __init__(self, host: str = "localhost", port: int = DEFAULT_GDB_PORT):
        self._host = host
        self._port = port
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._breakpoints: Dict[int, Breakpoint] = {}
        self._next_bp_id = 1
        self._callbacks: List[Callable[[BreakpointHit], None]] = []
        self._halted = False

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def halted(self) -> bool:
        return self._halted

    def connect(self, timeout: float = 5.0) -> None:
        """Connect to QEMU's GDB stub."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(timeout)
            self._sock.connect((self._host, self._port))
            self._connected = True

            # Send initial halt to synchronize
            self._send_packet('?')
            resp = self._recv_packet()
            if resp and resp.startswith('S') or resp.startswith('T'):
                self._halted = True

        except socket.error as e:
            self._connected = False
            raise GDBProtocolError(f"GDB connection failed: {e}")

    def disconnect(self) -> None:
        """Disconnect from GDB stub."""
        if self._sock:
            try:
                self._send_packet('D')  # Detach
            except (socket.error, GDBProtocolError):
                pass
            try:
                self._sock.close()
            except socket.error:
                pass
        self._sock = None
        self._connected = False

    def add_breakpoint(
        self,
        address: int,
        bp_type: BreakpointType = BreakpointType.SOFTWARE,
        size: int = 1,
        label: str = "",
    ) -> Breakpoint:
        """Set a breakpoint/watchpoint at the given address."""
        if not self._connected:
            raise GDBProtocolError("Not connected")

        bp = Breakpoint(
            bp_id=self._next_bp_id,
            address=address,
            bp_type=bp_type,
            size=size,
            label=label,
        )
        self._next_bp_id += 1

        # GDB Z packet: Z<type>,<addr>,<kind>
        cmd = f'Z{bp_type.value},{address:x},{size}'
        self._send_packet(cmd)
        resp = self._recv_packet()

        if resp != 'OK':
            raise GDBProtocolError(f"Failed to set breakpoint: {resp}")

        self._breakpoints[bp.bp_id] = bp
        return bp

    def remove_breakpoint(self, bp_id: int) -> None:
        """Remove a breakpoint by ID."""
        if bp_id not in self._breakpoints:
            return

        bp = self._breakpoints[bp_id]
        cmd = f'z{bp.bp_type.value},{bp.address:x},{bp.size}'
        self._send_packet(cmd)
        resp = self._recv_packet()

        del self._breakpoints[bp_id]

    def add_write_watchpoint(self, address: int, size: int = 8, label: str = "") -> Breakpoint:
        """Convenience: set a write watchpoint."""
        return self.add_breakpoint(address, BreakpointType.HARDWARE_WRITE, size, label)

    def add_exec_breakpoint(self, address: int, label: str = "") -> Breakpoint:
        """Convenience: set an execution breakpoint."""
        return self.add_breakpoint(address, BreakpointType.HARDWARE_EXEC, 1, label)

    def add_callback(self, callback: Callable[[BreakpointHit], None]) -> None:
        """Register a callback for breakpoint hits."""
        self._callbacks.append(callback)

    def continue_execution(self) -> Optional[BreakpointHit]:
        """Resume execution until next breakpoint hit."""
        if not self._connected:
            raise GDBProtocolError("Not connected")

        self._send_packet('c')
        self._halted = False

        resp = self._recv_packet()
        if resp and (resp.startswith('S') or resp.startswith('T')):
            self._halted = True
            return self._handle_stop(resp)
        return None

    def single_step(self) -> Optional[BreakpointHit]:
        """Execute a single instruction."""
        if not self._connected:
            raise GDBProtocolError("Not connected")

        self._send_packet('s')
        resp = self._recv_packet()
        if resp and (resp.startswith('S') or resp.startswith('T')):
            self._halted = True
            return self._handle_stop(resp)
        return None

    def read_registers(self) -> Dict[str, int]:
        """Read all general-purpose registers."""
        if not self._connected:
            raise GDBProtocolError("Not connected")

        self._send_packet('g')
        resp = self._recv_packet()
        if not resp:
            return {}

        return self._parse_x86_64_registers(resp)

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory at the given address."""
        if not self._connected:
            raise GDBProtocolError("Not connected")

        cmd = f'm{address:x},{size:x}'
        self._send_packet(cmd)
        resp = self._recv_packet()

        if not resp or resp.startswith('E'):
            return b'\x00' * size

        try:
            return bytes.fromhex(resp)
        except ValueError:
            return b'\x00' * size

    def get_pc(self) -> int:
        """Get current program counter."""
        regs = self.read_registers()
        return regs.get('rip', 0)

    def list_breakpoints(self) -> List[Breakpoint]:
        """List all active breakpoints."""
        return list(self._breakpoints.values())

    def _handle_stop(self, response: str) -> Optional[BreakpointHit]:
        """Handle a stop reply and find the matching breakpoint."""
        pc = self.get_pc()

        # Find matching breakpoint
        hit_bp = None
        for bp in self._breakpoints.values():
            if bp.address == pc or (
                bp.bp_type in (BreakpointType.HARDWARE_WRITE, BreakpointType.HARDWARE_ACCESS)
            ):
                hit_bp = bp
                bp.hit_count += 1
                break

        if not hit_bp:
            # Create a synthetic breakpoint for unknown stops
            hit_bp = Breakpoint(bp_id=0, address=pc, bp_type=BreakpointType.SOFTWARE)

        regs = self.read_registers()
        stack_data = self.read_memory(regs.get('rsp', 0), 64) if 'rsp' in regs else b''

        hit = BreakpointHit(
            breakpoint=hit_bp,
            pc=pc,
            registers=regs,
            timestamp=time.time(),
            stack_top=stack_data,
        )

        for callback in self._callbacks:
            callback(hit)

        return hit

    def _send_packet(self, data: str) -> None:
        """Send a GDB protocol packet."""
        checksum = sum(ord(c) for c in data) & 0xFF
        packet = f'${data}#{checksum:02x}'
        try:
            self._sock.sendall(packet.encode('ascii'))
        except socket.error as e:
            raise GDBProtocolError(f"Send failed: {e}")

    def _recv_packet(self) -> Optional[str]:
        """Receive a GDB protocol packet."""
        try:
            # Read until we get a complete packet
            buf = b''
            while True:
                chunk = self._sock.recv(self.RECV_SIZE)
                if not chunk:
                    return None
                buf += chunk

                # Look for packet markers
                decoded = buf.decode('ascii', errors='replace')
                start = decoded.find('$')
                end = decoded.find('#', start + 1 if start >= 0 else 0)

                if start >= 0 and end >= 0 and end + 2 < len(decoded):
                    # Send ACK
                    self._sock.sendall(b'+')
                    return decoded[start + 1:end]

                # Handle simple '+' ACK responses
                if decoded.strip() == '+':
                    buf = b''
                    continue

                if len(buf) > self.RECV_SIZE * 4:
                    return None

        except socket.timeout:
            return None
        except socket.error as e:
            raise GDBProtocolError(f"Receive failed: {e}")

    @staticmethod
    def _parse_x86_64_registers(hex_data: str) -> Dict[str, int]:
        """Parse x86_64 register data from GDB 'g' response."""
        # GDB x86_64 register order (8 bytes each):
        # RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS, CS, SS, DS, ES, FS, GS
        reg_names = [
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
            'rip', 'eflags',
        ]

        regs = {}
        for i, name in enumerate(reg_names):
            offset = i * 16  # 8 bytes = 16 hex chars
            if offset + 16 > len(hex_data):
                break
            hex_val = hex_data[offset:offset + 16]
            # GDB sends in target byte order (little-endian for x86)
            try:
                raw = bytes.fromhex(hex_val)
                regs[name] = int.from_bytes(raw, byteorder='little')
            except ValueError:
                pass

        return regs

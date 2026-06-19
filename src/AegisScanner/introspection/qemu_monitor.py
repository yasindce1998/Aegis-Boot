"""
QMP Client - QEMU Machine Protocol interface for live VM interaction.

Provides async-capable communication with QEMU's QMP socket for memory
reads, register queries, and VM state control.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import json
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class QMPError(Exception):
    """QMP protocol or connection error."""
    pass


class QMPClient:
    """
    QEMU Machine Protocol client.

    Connects to QEMU's QMP socket and provides methods for:
    - Memory reads/writes (physical and virtual)
    - Register access
    - VM state control (pause/resume/stop)
    - Human monitor commands (for features not in QMP)
    """

    RECV_BUF_SIZE = 65536
    DEFAULT_TIMEOUT = 5.0

    def __init__(self, socket_path: Optional[str] = None, host: str = "localhost", port: int = 4444):
        self._socket_path = socket_path
        self._host = host
        self._port = port
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._negotiated = False
        self._event_queue: List[Dict] = []

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        """Connect to QMP socket and perform capability negotiation."""
        try:
            if self._socket_path:
                self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self._sock.settimeout(timeout)

            if self._socket_path:
                self._sock.connect(self._socket_path)
            else:
                self._sock.connect((self._host, self._port))

            self._connected = True

            # Read QMP greeting
            greeting = self._recv_response()
            if "QMP" not in greeting:
                raise QMPError(f"Invalid QMP greeting: {greeting}")

            # Negotiate capabilities
            self._send_command({"execute": "qmp_capabilities"})
            resp = self._recv_response()
            if "return" not in resp:
                raise QMPError(f"Capability negotiation failed: {resp}")

            self._negotiated = True

        except socket.error as e:
            self._connected = False
            raise QMPError(f"Connection failed: {e}")

    def disconnect(self) -> None:
        """Close QMP connection."""
        if self._sock:
            try:
                self._sock.close()
            except socket.error:
                pass
        self._sock = None
        self._connected = False
        self._negotiated = False

    def execute(self, command: str, arguments: Optional[Dict] = None) -> Dict:
        """Execute a QMP command and return the response."""
        if not self._negotiated:
            raise QMPError("Not connected or not negotiated")

        cmd: Dict[str, Any] = {"execute": command}
        if arguments:
            cmd["arguments"] = arguments

        self._send_command(cmd)
        return self._recv_response()

    def read_physical_memory(self, address: int, size: int) -> bytes:
        """Read physical memory via human-monitor-command."""
        # Use pmemsave to a temporary path, then read it
        # For small reads, use 'xp' command which returns hex
        if size <= 1024:
            return self._read_memory_xp(address, size)
        else:
            return self._read_memory_pmemsave(address, size)

    def _read_memory_xp(self, address: int, size: int) -> bytes:
        """Read memory using QMP human-monitor-command with xp."""
        # xp /NXB address — reads N bytes in hex
        words = (size + 3) // 4
        cmd_str = f"xp /{words}xw {address:#x}"
        result = self.human_command(cmd_str)
        return self._parse_xp_output(result, size)

    def _read_memory_pmemsave(self, address: int, size: int) -> bytes:
        """Read memory using pmemsave command."""
        import tempfile
        import os

        tmp_path = Path(tempfile.mktemp(suffix='.bin'))
        try:
            cmd_str = f"pmemsave {address:#x} {size} {tmp_path}"
            self.human_command(cmd_str)
            time.sleep(0.1)  # Give QEMU time to write
            if tmp_path.exists():
                return tmp_path.read_bytes()
            return b'\x00' * size
        finally:
            if tmp_path.exists():
                os.unlink(tmp_path)

    def write_physical_memory(self, address: int, data: bytes) -> None:
        """Write to physical memory (for testing/injection)."""
        hex_data = data.hex()
        # Use GDB stub or custom monitor command
        for i in range(0, len(data), 4):
            chunk = data[i:i+4]
            val = int.from_bytes(chunk, byteorder='little')
            cmd_str = f"set_pmem {address + i:#x} 4 {val:#x}"
            self.human_command(cmd_str)

    def get_registers(self, cpu_index: int = 0) -> Dict[str, int]:
        """Get CPU register state."""
        cmd_str = "info registers"
        result = self.human_command(cmd_str)
        return self._parse_registers(result)

    def pause_vm(self) -> None:
        """Pause VM execution."""
        resp = self.execute("stop")
        if "error" in resp:
            raise QMPError(f"Failed to pause: {resp['error']}")

    def resume_vm(self) -> None:
        """Resume VM execution."""
        resp = self.execute("cont")
        if "error" in resp:
            raise QMPError(f"Failed to resume: {resp['error']}")

    def query_status(self) -> Dict:
        """Query VM run status."""
        resp = self.execute("query-status")
        if "return" in resp:
            return resp["return"]
        return {}

    def human_command(self, command: str) -> str:
        """Execute a human monitor command via QMP."""
        resp = self.execute("human-monitor-command", {
            "command-line": command
        })
        if "return" in resp:
            return resp["return"]
        if "error" in resp:
            raise QMPError(f"Monitor command failed: {resp['error']}")
        return ""

    def query_memory_size(self) -> int:
        """Query total VM memory size."""
        result = self.human_command("info mtree -f")
        # Parse memory tree for RAM size
        for line in result.split('\n'):
            if 'ram' in line.lower() and '-' in line:
                parts = line.strip().split()
                for p in parts:
                    if '-' in p and all(c in '0123456789abcdef-' for c in p.lower()):
                        start, end = p.split('-')
                        return int(end, 16) - int(start, 16)
        return 0

    def get_events(self) -> List[Dict]:
        """Return queued events and clear the queue."""
        events = list(self._event_queue)
        self._event_queue.clear()
        return events

    def _send_command(self, cmd: Dict) -> None:
        """Send a JSON command over the socket."""
        data = json.dumps(cmd).encode('utf-8') + b'\r\n'
        try:
            self._sock.sendall(data)
        except socket.error as e:
            raise QMPError(f"Send failed: {e}")

    def _recv_response(self) -> Dict:
        """Receive and parse a JSON response, queuing events."""
        try:
            buf = b''
            while True:
                chunk = self._sock.recv(self.RECV_BUF_SIZE)
                if not chunk:
                    raise QMPError("Connection closed")
                buf += chunk

                # Try to parse complete JSON objects
                try:
                    obj = json.loads(buf.decode('utf-8'))
                    if "event" in obj:
                        self._event_queue.append(obj)
                        buf = b''
                        continue
                    return obj
                except json.JSONDecodeError:
                    # Might be partial, or multiple objects
                    lines = buf.decode('utf-8', errors='replace').split('\n')
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            if "event" in obj:
                                self._event_queue.append(obj)
                            else:
                                return obj
                        except json.JSONDecodeError:
                            continue
                    if len(buf) > self.RECV_BUF_SIZE * 4:
                        raise QMPError("Response too large")

        except socket.timeout:
            raise QMPError("Response timeout")
        except socket.error as e:
            raise QMPError(f"Receive failed: {e}")

    @staticmethod
    def _parse_xp_output(output: str, size: int) -> bytes:
        """Parse the hex output from xp command into bytes."""
        result = bytearray()
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('(qemu)'):
                continue
            # Format: "addr: 0xVALUE 0xVALUE ..."
            parts = line.split(':')
            if len(parts) < 2:
                continue
            hex_values = parts[1].strip().split()
            for hv in hex_values:
                hv = hv.strip()
                if hv.startswith('0x'):
                    val = int(hv, 16)
                    result.extend(struct.pack('<I', val))

        return bytes(result[:size])

    @staticmethod
    def _parse_registers(output: str) -> Dict[str, int]:
        """Parse register dump from 'info registers' output."""
        regs = {}
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            # x86_64 format: "RAX=0000000000000000 RBX=..."
            parts = line.split()
            for part in parts:
                if '=' in part:
                    name, _, val = part.partition('=')
                    try:
                        regs[name.lower()] = int(val, 16)
                    except ValueError:
                        pass
        return regs

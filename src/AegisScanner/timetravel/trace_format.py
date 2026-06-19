"""
Trace Format - Binary trace format for recording UEFI execution events.

Defines the on-disk format for execution traces:
  (timestamp, event_type, PC, opcode/data, memory_access)

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Dict, Iterator, List, Optional


class TraceEventType(IntEnum):
    """Types of events recorded in a trace."""
    INSTRUCTION = 0
    MEMORY_WRITE = 1
    MEMORY_READ = 2
    IO_WRITE = 3
    IO_READ = 4
    INTERRUPT = 5
    EXCEPTION = 6
    BST_ACCESS = 7
    BOOT_SERVICE_CALL = 8
    RUNTIME_SERVICE_CALL = 9
    SMI_ENTRY = 10
    SMI_EXIT = 11
    MARKER = 12


class MemoryAccessType(IntEnum):
    """Memory access width."""
    BYTE = 1
    WORD = 2
    DWORD = 4
    QWORD = 8


TRACE_MAGIC = b'AGTT'  # Aegis Time Travel
TRACE_VERSION = 1

# Binary format per event (fixed 48 bytes):
# [8B timestamp_ns] [1B event_type] [1B access_type] [2B flags]
# [8B pc] [8B address] [8B value] [8B aux_data] [4B padding]
EVENT_STRUCT = struct.Struct('<QBBHQQQQi')
EVENT_SIZE = EVENT_STRUCT.size  # 48 bytes

# Header format (64 bytes):
# [4B magic] [2B version] [2B arch] [8B start_time_ns] [8B event_count]
# [8B bst_address] [8B first_pc] [16B reserved]
HEADER_STRUCT = struct.Struct('<4sHHQQQQ16s')
HEADER_SIZE = HEADER_STRUCT.size


class Architecture(IntEnum):
    X86_64 = 0
    AARCH64 = 1
    RISCV64 = 2


@dataclass
class TraceHeader:
    """Trace file header metadata."""
    magic: bytes = TRACE_MAGIC
    version: int = TRACE_VERSION
    arch: Architecture = Architecture.X86_64
    start_time_ns: int = 0
    event_count: int = 0
    bst_address: int = 0
    first_pc: int = 0

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(
            self.magic, self.version, self.arch,
            self.start_time_ns, self.event_count,
            self.bst_address, self.first_pc,
            b'\x00' * 16,
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'TraceHeader':
        magic, version, arch, start_ns, count, bst, first_pc, _ = HEADER_STRUCT.unpack(data)
        if magic != TRACE_MAGIC:
            raise ValueError(f"Invalid trace magic: {magic!r}")
        return cls(
            magic=magic, version=version, arch=Architecture(arch),
            start_time_ns=start_ns, event_count=count,
            bst_address=bst, first_pc=first_pc,
        )


@dataclass
class TraceEvent:
    """A single trace event."""
    timestamp_ns: int
    event_type: TraceEventType
    access_type: MemoryAccessType = MemoryAccessType.QWORD
    flags: int = 0
    pc: int = 0
    address: int = 0
    value: int = 0
    aux_data: int = 0

    def pack(self) -> bytes:
        return EVENT_STRUCT.pack(
            self.timestamp_ns, self.event_type, self.access_type,
            self.flags, self.pc, self.address, self.value,
            self.aux_data, 0,
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'TraceEvent':
        ts, etype, atype, flags, pc, addr, val, aux, _ = EVENT_STRUCT.unpack(data)
        return cls(
            timestamp_ns=ts, event_type=TraceEventType(etype),
            access_type=MemoryAccessType(atype), flags=flags,
            pc=pc, address=addr, value=val, aux_data=aux,
        )

    @property
    def is_memory_write(self) -> bool:
        return self.event_type == TraceEventType.MEMORY_WRITE

    @property
    def is_bst_access(self) -> bool:
        return self.event_type == TraceEventType.BST_ACCESS


class TraceWriter:
    """Writes trace events to a binary file."""

    def __init__(self, path: Path, header: Optional[TraceHeader] = None):
        self._path = Path(path)
        self._header = header or TraceHeader(start_time_ns=time.time_ns())
        self._file: Optional[BinaryIO] = None
        self._count = 0

    @property
    def event_count(self) -> int:
        return self._count

    @property
    def path(self) -> Path:
        return self._path

    def open(self) -> None:
        self._file = open(self._path, 'wb')
        self._file.write(self._header.pack())

    def write_event(self, event: TraceEvent) -> None:
        if not self._file:
            raise RuntimeError("Trace file not open")
        self._file.write(event.pack())
        self._count += 1

    def close(self) -> None:
        if self._file:
            # Update header with final count
            self._header.event_count = self._count
            self._file.seek(0)
            self._file.write(self._header.pack())
            self._file.close()
            self._file = None

    def __enter__(self) -> 'TraceWriter':
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()


class TraceReader:
    """Reads trace events from a binary file."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._file: Optional[BinaryIO] = None
        self._header: Optional[TraceHeader] = None

    @property
    def header(self) -> Optional[TraceHeader]:
        return self._header

    @property
    def event_count(self) -> int:
        return self._header.event_count if self._header else 0

    def open(self) -> TraceHeader:
        self._file = open(self._path, 'rb')
        header_data = self._file.read(HEADER_SIZE)
        if len(header_data) < HEADER_SIZE:
            raise ValueError("Truncated trace file")
        self._header = TraceHeader.unpack(header_data)
        return self._header

    def read_event(self) -> Optional[TraceEvent]:
        if not self._file:
            raise RuntimeError("Trace file not open")
        data = self._file.read(EVENT_SIZE)
        if len(data) < EVENT_SIZE:
            return None
        return TraceEvent.unpack(data)

    def iter_events(self) -> Iterator[TraceEvent]:
        while True:
            event = self.read_event()
            if event is None:
                break
            yield event

    def seek_event(self, index: int) -> Optional[TraceEvent]:
        if not self._file:
            raise RuntimeError("Trace file not open")
        offset = HEADER_SIZE + (index * EVENT_SIZE)
        self._file.seek(offset)
        return self.read_event()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self) -> 'TraceReader':
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()

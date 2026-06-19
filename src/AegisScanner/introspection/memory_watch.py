"""
Memory Watcher - Periodic memory polling for change detection.

Monitors specified memory regions for modifications, detecting BST pointer
overwrites and payload injection in real-time.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from .qemu_monitor import QMPClient, QMPError


class ChangeType(Enum):
    POINTER_MODIFIED = "pointer_modified"
    DATA_WRITTEN = "data_written"
    REGION_ZEROED = "region_zeroed"
    CODE_INJECTED = "code_injected"


@dataclass
class MemoryRegion:
    """A memory region to monitor."""
    name: str
    base_address: int
    size: int
    poll_interval: float = 1.0
    detect_code_injection: bool = False
    pointer_offsets: List[int] = field(default_factory=list)


@dataclass
class MemoryChange:
    """A detected memory change."""
    region_name: str
    address: int
    offset: int
    change_type: ChangeType
    old_value: bytes
    new_value: bytes
    timestamp: float = 0.0

    @property
    def old_value_int(self) -> int:
        if len(self.old_value) <= 8:
            return int.from_bytes(self.old_value, byteorder='little')
        return 0

    @property
    def new_value_int(self) -> int:
        if len(self.new_value) <= 8:
            return int.from_bytes(self.new_value, byteorder='little')
        return 0


class MemoryWatcher:
    """
    Polls memory regions via QMP and detects changes.

    Monitors BST pointer tables, runtime memory regions, and
    code sections for unauthorized modifications.
    """

    # x86_64 instruction patterns indicating code injection
    CODE_PATTERNS = [
        b'\x48\xb8',  # MOV RAX, imm64
        b'\xff\x25',  # JMP [rip+offset]
        b'\xe9',      # JMP rel32
        b'\x68',      # PUSH imm32 (part of push/ret)
        b'\x48\x89',  # MOV reg, reg
    ]

    # EFI Boot Services Table offsets (x86_64, UEFI 2.10)
    BST_OFFSETS = {
        0x40: "RaiseTPL",
        0x48: "RestoreTPL",
        0x50: "AllocatePages",
        0x58: "FreePages",
        0x60: "GetMemoryMap",
        0x68: "AllocatePool",
        0x70: "FreePool",
        0x80: "CreateEvent",
        0x90: "SetTimer",
        0x98: "WaitForEvent",
        0xA0: "SignalEvent",
        0xA8: "CloseEvent",
        0xC0: "LoadImage",
        0xC8: "StartImage",
        0xD0: "Exit",
        0xD8: "UnloadImage",
        0xE0: "ExitBootServices",
        0x100: "SetWatchdogTimer",
        0x140: "HandleProtocol",
        0x160: "RegisterProtocolNotify",
        0x168: "LocateHandle",
        0x198: "InstallConfigurationTable",
        0x1A0: "LoadImage2",
    }

    def __init__(self, qmp_client: QMPClient):
        self._qmp = qmp_client
        self._regions: Dict[str, MemoryRegion] = {}
        self._snapshots: Dict[str, bytes] = {}
        self._callbacks: List[Callable[[MemoryChange], None]] = []
        self._running = False
        self._change_log: List[MemoryChange] = []

    def add_region(self, region: MemoryRegion) -> None:
        """Add a memory region to monitor."""
        self._regions[region.name] = region

    def remove_region(self, name: str) -> None:
        """Remove a monitored region."""
        self._regions.pop(name, None)
        self._snapshots.pop(name, None)

    def add_callback(self, callback: Callable[[MemoryChange], None]) -> None:
        """Register a callback for memory changes."""
        self._callbacks.append(callback)

    def add_bst_watch(self, bst_address: int) -> None:
        """Add a watch on EFI Boot Services Table pointers."""
        region = MemoryRegion(
            name="BST",
            base_address=bst_address,
            size=0x1B0,  # Full BST size
            poll_interval=0.5,
            pointer_offsets=list(self.BST_OFFSETS.keys()),
        )
        self.add_region(region)

    def take_snapshot(self, region_name: Optional[str] = None) -> None:
        """Take a snapshot of one or all monitored regions."""
        regions = [self._regions[region_name]] if region_name else self._regions.values()

        for region in regions:
            try:
                data = self._qmp.read_physical_memory(region.base_address, region.size)
                self._snapshots[region.name] = data
            except QMPError:
                pass

    def check_changes(self) -> List[MemoryChange]:
        """Check all regions for changes since last snapshot."""
        changes = []

        for name, region in self._regions.items():
            if name not in self._snapshots:
                self.take_snapshot(name)
                continue

            try:
                current = self._qmp.read_physical_memory(region.base_address, region.size)
            except QMPError:
                continue

            old = self._snapshots[name]
            if current == old:
                continue

            # Detect specific types of changes
            if region.pointer_offsets:
                changes.extend(self._check_pointer_changes(region, old, current))
            else:
                changes.extend(self._check_data_changes(region, old, current))

            if region.detect_code_injection:
                changes.extend(self._check_code_injection(region, old, current))

            self._snapshots[name] = current

        for change in changes:
            change.timestamp = time.time()
            self._change_log.append(change)
            for callback in self._callbacks:
                callback(change)

        return changes

    def get_bst_pointers(self) -> Dict[str, int]:
        """Read current BST function pointers."""
        if "BST" not in self._regions:
            return {}

        region = self._regions["BST"]
        try:
            data = self._qmp.read_physical_memory(region.base_address, region.size)
        except QMPError:
            return {}

        pointers = {}
        for offset, name in self.BST_OFFSETS.items():
            if offset + 8 <= len(data):
                ptr = struct.unpack_from('<Q', data, offset)[0]
                pointers[name] = ptr
        return pointers

    def get_change_log(self) -> List[MemoryChange]:
        """Return all detected changes."""
        return list(self._change_log)

    def clear_change_log(self) -> None:
        """Clear the change history."""
        self._change_log.clear()

    def _check_pointer_changes(
        self, region: MemoryRegion, old: bytes, new: bytes
    ) -> List[MemoryChange]:
        """Check for pointer value modifications."""
        changes = []
        for offset in region.pointer_offsets:
            if offset + 8 > min(len(old), len(new)):
                continue
            old_ptr = old[offset:offset + 8]
            new_ptr = new[offset:offset + 8]
            if old_ptr != new_ptr:
                changes.append(MemoryChange(
                    region_name=region.name,
                    address=region.base_address + offset,
                    offset=offset,
                    change_type=ChangeType.POINTER_MODIFIED,
                    old_value=old_ptr,
                    new_value=new_ptr,
                ))
        return changes

    def _check_data_changes(
        self, region: MemoryRegion, old: bytes, new: bytes
    ) -> List[MemoryChange]:
        """Check for general data modifications."""
        changes = []
        min_len = min(len(old), len(new))

        # Find changed ranges (group consecutive changed bytes)
        i = 0
        while i < min_len:
            if old[i] != new[i]:
                start = i
                while i < min_len and old[i] != new[i]:
                    i += 1
                end = i
                # Only report if change is significant (> 4 bytes)
                if end - start >= 4:
                    change_type = ChangeType.REGION_ZEROED if all(
                        b == 0 for b in new[start:end]
                    ) else ChangeType.DATA_WRITTEN
                    changes.append(MemoryChange(
                        region_name=region.name,
                        address=region.base_address + start,
                        offset=start,
                        change_type=change_type,
                        old_value=old[start:min(start + 64, end)],
                        new_value=new[start:min(start + 64, end)],
                    ))
            i += 1

        return changes

    def _check_code_injection(
        self, region: MemoryRegion, old: bytes, new: bytes
    ) -> List[MemoryChange]:
        """Check for code injection patterns in changed regions."""
        changes = []
        min_len = min(len(old), len(new))

        i = 0
        while i < min_len - 2:
            if old[i] != new[i]:
                # Check if new bytes match code injection patterns
                for pattern in self.CODE_PATTERNS:
                    if new[i:i + len(pattern)] == pattern:
                        # Found instruction pattern in newly written data
                        end = min(i + 16, min_len)
                        changes.append(MemoryChange(
                            region_name=region.name,
                            address=region.base_address + i,
                            offset=i,
                            change_type=ChangeType.CODE_INJECTED,
                            old_value=old[i:end],
                            new_value=new[i:end],
                        ))
                        i = end
                        break
                else:
                    i += 1
            else:
                i += 1

        return changes

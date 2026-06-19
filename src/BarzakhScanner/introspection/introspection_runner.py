"""
Introspection Runner - Orchestrator for live UEFI monitoring sessions.

Coordinates QMP client, memory watcher, breakpoint engine, and event
stream into a unified monitoring session.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .qemu_monitor import QMPClient, QMPError
from .memory_watch import MemoryWatcher, MemoryRegion, MemoryChange
from .breakpoint_engine import BreakpointEngine, BreakpointHit, BreakpointType, GDBProtocolError
from .event_stream import EventStream, EventType, IntrospectionEvent, Severity
from .live_detector import LiveDetector, LiveFinding


@dataclass
class IntrospectionConfig:
    """Configuration for an introspection session."""
    # QMP connection
    qmp_socket: Optional[str] = None
    qmp_host: str = "localhost"
    qmp_port: int = 4444

    # GDB stub connection
    gdb_host: str = "localhost"
    gdb_port: int = 1234
    use_gdb: bool = True

    # Monitoring targets
    bst_address: Optional[int] = None
    watch_regions: List[MemoryRegion] = field(default_factory=list)

    # Timing
    poll_interval: float = 0.5
    session_timeout: float = 300.0
    settle_time: float = 2.0

    # Output
    output_dir: Optional[str] = None
    verbose: bool = False


class IntrospectionRunner:
    """
    Orchestrates a live UEFI introspection session.

    Lifecycle:
    1. Connect to QEMU (QMP + optional GDB)
    2. Locate BST in memory
    3. Take baseline snapshot
    4. Start polling loop
    5. Detect and report changes
    6. Stop and produce summary
    """

    # EFI System Table signature: "IBI SYST" at offset 0
    EFI_SYSTEM_TABLE_SIG = b'IBI SYST'

    # Common BST search ranges for OVMF
    BST_SEARCH_RANGES = [
        (0x7000000, 0x7F00000),
        (0x6000000, 0x7000000),
        (0x3000000, 0x4000000),
    ]

    def __init__(self, config: Optional[IntrospectionConfig] = None):
        self.config = config or IntrospectionConfig()
        self._qmp: Optional[QMPClient] = None
        self._gdb: Optional[BreakpointEngine] = None
        self._watcher: Optional[MemoryWatcher] = None
        self._events: Optional[EventStream] = None
        self._detector: Optional[LiveDetector] = None
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._findings: List[LiveFinding] = []
        self._session_start: float = 0.0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def events(self) -> Optional[EventStream]:
        return self._events

    @property
    def detector(self) -> Optional[LiveDetector]:
        return self._detector

    def connect(self) -> bool:
        """Establish connections to QEMU."""
        try:
            # Connect QMP
            self._qmp = QMPClient(
                socket_path=self.config.qmp_socket,
                host=self.config.qmp_host,
                port=self.config.qmp_port,
            )
            self._qmp.connect()

            # Connect GDB stub if enabled
            if self.config.use_gdb:
                try:
                    self._gdb = BreakpointEngine(
                        host=self.config.gdb_host,
                        port=self.config.gdb_port,
                    )
                    self._gdb.connect()
                except GDBProtocolError:
                    self._gdb = None

            # Initialize components
            self._watcher = MemoryWatcher(self._qmp)
            self._events = EventStream()
            self._detector = LiveDetector(self._events)

            # Wire up callbacks
            self._watcher.add_callback(self._on_memory_change)
            if self._gdb:
                self._gdb.add_callback(self._on_breakpoint_hit)

            return True

        except QMPError as e:
            self._cleanup()
            return False

    def setup_monitoring(self, bst_address: Optional[int] = None) -> bool:
        """Configure monitoring targets."""
        if not self._qmp or not self._watcher:
            return False

        # Use provided BST address or search for it
        bst_addr = bst_address or self.config.bst_address
        if not bst_addr:
            bst_addr = self._find_bst_address()

        if bst_addr:
            self._watcher.add_bst_watch(bst_addr)
            # Take baseline
            self._watcher.take_snapshot("BST")
            pointers = self._watcher.get_bst_pointers()
            self._detector.set_baseline(pointers)

            if self.config.verbose:
                self._events.emit_custom(
                    EventType.VM_STATE_CHANGE,
                    Severity.INFO,
                    f"BST located at {bst_addr:#x}, baseline captured ({len(pointers)} functions)",
                )

        # Add custom watch regions
        for region in self.config.watch_regions:
            self._watcher.add_region(region)
            self._watcher.take_snapshot(region.name)

        # Set GDB watchpoints on critical BST entries
        if self._gdb and bst_addr:
            critical_offsets = [0xC0, 0xC8, 0xE0]  # LoadImage, StartImage, ExitBootServices
            for offset in critical_offsets:
                func_name = MemoryWatcher.BST_OFFSETS.get(offset, f"offset_{offset:#x}")
                try:
                    self._gdb.add_write_watchpoint(
                        bst_addr + offset, 8,
                        label=f"BST.{func_name}",
                    )
                except GDBProtocolError:
                    pass

        return True

    def start(self) -> None:
        """Start the monitoring loop."""
        if self._running:
            return

        self._running = True
        self._session_start = time.time()

        # Resume VM if halted
        if self._gdb and self._gdb.halted:
            try:
                self._gdb.continue_execution()
            except GDBProtocolError:
                pass

        # Start polling thread
        self._poll_thread = threading.Thread(
            target=self._poll_loop, daemon=True
        )
        self._poll_thread.start()

    def stop(self) -> Dict:
        """Stop monitoring and return summary."""
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=5.0)
            self._poll_thread = None

        summary = self._build_summary()
        self._cleanup()
        return summary

    def poll_once(self) -> List[LiveFinding]:
        """Perform a single poll cycle (for non-threaded use)."""
        if not self._watcher:
            return []

        changes = self._watcher.check_changes()
        findings = []
        for change in changes:
            finding = self._detector.analyze_memory_change(change)
            if finding:
                findings.append(finding)
                self._findings.append(finding)
        return findings

    def get_current_bst(self) -> Dict[str, int]:
        """Get current BST pointer values."""
        if self._watcher:
            return self._watcher.get_bst_pointers()
        return {}

    def _poll_loop(self) -> None:
        """Background polling loop."""
        while self._running:
            elapsed = time.time() - self._session_start
            if elapsed > self.config.session_timeout:
                self._running = False
                break

            try:
                self.poll_once()
            except (QMPError, Exception):
                pass

            time.sleep(self.config.poll_interval)

    def _find_bst_address(self) -> Optional[int]:
        """Search memory for EFI System Table and extract BST pointer."""
        if not self._qmp:
            return None

        for start, end in self.BST_SEARCH_RANGES:
            try:
                # Read in chunks looking for EFI_SYSTEM_TABLE_SIGNATURE
                chunk_size = 0x10000
                for addr in range(start, end, chunk_size):
                    data = self._qmp.read_physical_memory(addr, chunk_size)
                    idx = data.find(self.EFI_SYSTEM_TABLE_SIG)
                    if idx >= 0:
                        # Found System Table, BST pointer is at offset 0x60
                        st_addr = addr + idx
                        st_data = self._qmp.read_physical_memory(st_addr, 0x70)
                        if len(st_data) >= 0x68:
                            import struct
                            bst_ptr = struct.unpack_from('<Q', st_data, 0x60)[0]
                            if bst_ptr > 0x1000:
                                return bst_ptr
            except QMPError:
                continue

        return None

    def _on_memory_change(self, change: MemoryChange) -> None:
        """Handle memory change from watcher."""
        event = self._events.process_memory_change(change)
        if event:
            finding = self._detector.analyze_event(event)
            if finding:
                self._findings.append(finding)

    def _on_breakpoint_hit(self, hit: BreakpointHit) -> None:
        """Handle breakpoint hit from GDB."""
        self._events.process_breakpoint_hit(hit)

    def _build_summary(self) -> Dict:
        """Build session summary report."""
        duration = time.time() - self._session_start if self._session_start else 0

        return {
            "session": {
                "duration_seconds": round(duration, 1),
                "poll_interval": self.config.poll_interval,
                "total_polls": int(duration / self.config.poll_interval) if duration else 0,
            },
            "findings": [f.to_dict() for f in self._findings],
            "findings_count": len(self._findings),
            "events": self._events.get_stats() if self._events else {},
            "detector_summary": self._detector.get_summary() if self._detector else {},
        }

    def _cleanup(self) -> None:
        """Disconnect and clean up resources."""
        if self._qmp:
            self._qmp.disconnect()
            self._qmp = None
        if self._gdb:
            self._gdb.disconnect()
            self._gdb = None

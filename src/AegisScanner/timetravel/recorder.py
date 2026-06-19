"""
Trace Recorder - Records UEFI boot execution via QEMU record/replay.

Uses QEMU's built-in deterministic record/replay mechanism combined
with QMP memory polling to capture execution traces.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .trace_format import (
    Architecture,
    MemoryAccessType,
    TraceEvent,
    TraceEventType,
    TraceHeader,
    TraceWriter,
)


@dataclass
class RecordingConfig:
    """Configuration for a trace recording session."""
    # QEMU settings
    qemu_binary: str = "qemu-system-x86_64"
    firmware_path: Optional[str] = None
    memory_mb: int = 256
    extra_qemu_args: List[str] = field(default_factory=list)

    # Recording settings
    output_dir: str = "."
    trace_name: str = "boot_trace"
    record_replay: bool = True
    poll_interval: float = 0.1
    max_duration: float = 60.0

    # Monitoring targets
    bst_address: Optional[int] = None
    watch_addresses: List[int] = field(default_factory=list)
    watch_ranges: List[tuple] = field(default_factory=list)

    # QMP settings
    qmp_port: int = 4445

    @property
    def trace_path(self) -> Path:
        return Path(self.output_dir) / f"{self.trace_name}.agtt"

    @property
    def replay_log_path(self) -> Path:
        return Path(self.output_dir) / f"{self.trace_name}.rr"


class TraceRecorder:
    """
    Records UEFI boot execution traces.

    Uses QEMU's record/replay for deterministic capture, augmented with
    QMP-based memory polling to track BST pointer changes and memory
    writes during boot.
    """

    def __init__(self, config: Optional[RecordingConfig] = None):
        self.config = config or RecordingConfig()
        self._process: Optional[subprocess.Popen] = None
        self._writer: Optional[TraceWriter] = None
        self._recording = False
        self._start_time_ns: int = 0
        self._event_count: int = 0
        self._snapshots: List[Dict[str, int]] = []
        self._callbacks: List[Callable[[TraceEvent], None]] = []

    @property
    def is_recording(self) -> bool:
        return self._recording

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def elapsed_ns(self) -> int:
        if not self._start_time_ns:
            return 0
        return time.time_ns() - self._start_time_ns

    def add_callback(self, callback: Callable[[TraceEvent], None]) -> None:
        self._callbacks.append(callback)

    def build_qemu_command(self) -> List[str]:
        """Build the QEMU command line for recording."""
        cmd = [self.config.qemu_binary]

        # Memory
        cmd.extend(["-m", str(self.config.memory_mb)])

        # Firmware
        if self.config.firmware_path:
            cmd.extend(["-drive",
                        f"if=pflash,format=raw,file={self.config.firmware_path}"])

        # QMP for introspection
        cmd.extend(["-qmp",
                    f"tcp:localhost:{self.config.qmp_port},server,nowait"])

        # No display
        cmd.extend(["-nographic", "-serial", "null"])

        # Record/replay
        if self.config.record_replay:
            rr_path = str(self.config.replay_log_path)
            cmd.extend(["-icount", f"shift=auto,rr=record,rrfile={rr_path}"])
            cmd.extend(["-net", "none"])

        # Extra args
        cmd.extend(self.config.extra_qemu_args)

        return cmd

    def start_recording(self) -> bool:
        """Launch QEMU and begin recording."""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        header = TraceHeader(
            start_time_ns=time.time_ns(),
            arch=Architecture.X86_64,
            bst_address=self.config.bst_address or 0,
        )
        self._writer = TraceWriter(self.config.trace_path, header)
        self._writer.open()

        self._start_time_ns = time.time_ns()
        self._recording = True
        self._event_count = 0

        return True

    def record_event(self, event: TraceEvent) -> None:
        """Record a single trace event."""
        if not self._recording or not self._writer:
            return

        self._writer.write_event(event)
        self._event_count += 1

        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def record_memory_write(self, pc: int, address: int, value: int,
                            size: int = 8) -> None:
        """Record a memory write event."""
        access_type = MemoryAccessType(min(size, 8))
        event = TraceEvent(
            timestamp_ns=self.elapsed_ns,
            event_type=TraceEventType.MEMORY_WRITE,
            access_type=access_type,
            pc=pc,
            address=address,
            value=value,
        )
        self.record_event(event)

    def record_bst_modification(self, pc: int, offset: int,
                                old_value: int, new_value: int) -> None:
        """Record a BST pointer modification."""
        bst_addr = self.config.bst_address or 0
        event = TraceEvent(
            timestamp_ns=self.elapsed_ns,
            event_type=TraceEventType.BST_ACCESS,
            access_type=MemoryAccessType.QWORD,
            pc=pc,
            address=bst_addr + offset,
            value=new_value,
            aux_data=old_value,
        )
        self.record_event(event)

    def record_instruction(self, pc: int, opcode: int = 0) -> None:
        """Record an instruction execution event."""
        event = TraceEvent(
            timestamp_ns=self.elapsed_ns,
            event_type=TraceEventType.INSTRUCTION,
            pc=pc,
            value=opcode,
        )
        self.record_event(event)

    def record_marker(self, label_id: int, pc: int = 0) -> None:
        """Record a named marker event for timeline correlation."""
        event = TraceEvent(
            timestamp_ns=self.elapsed_ns,
            event_type=TraceEventType.MARKER,
            pc=pc,
            value=label_id,
        )
        self.record_event(event)

    def take_snapshot(self, bst_pointers: Dict[str, int]) -> None:
        """Take a snapshot of current BST state for diffing."""
        self._snapshots.append({
            "timestamp_ns": self.elapsed_ns,
            **{k: v for k, v in bst_pointers.items()},
        })

    def stop_recording(self) -> Dict:
        """Stop recording and finalize the trace file."""
        self._recording = False

        if self._writer:
            self._writer.close()

        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

        duration_ns = self.elapsed_ns
        return {
            "trace_path": str(self.config.trace_path),
            "replay_log": str(self.config.replay_log_path) if self.config.record_replay else None,
            "event_count": self._event_count,
            "duration_ns": duration_ns,
            "duration_seconds": duration_ns / 1_000_000_000,
            "snapshots": len(self._snapshots),
        }

    def get_snapshots(self) -> List[Dict]:
        """Return all BST snapshots taken during recording."""
        return list(self._snapshots)

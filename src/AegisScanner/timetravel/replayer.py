"""
Trace Replayer - Deterministic replay of recorded UEFI execution traces.

Supports state queries at arbitrary points in the trace, enabling
reverse debugging of bootkit installation sequences.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from .trace_format import (
    HEADER_SIZE,
    MemoryAccessType,
    TraceEvent,
    TraceEventType,
    TraceHeader,
    TraceReader,
)


@dataclass
class ReplayState:
    """Snapshot of emulated state at a point in the trace."""
    event_index: int = 0
    timestamp_ns: int = 0
    pc: int = 0
    memory: Dict[int, int] = field(default_factory=dict)
    bst_pointers: Dict[int, int] = field(default_factory=dict)
    registers: Dict[str, int] = field(default_factory=dict)
    events_processed: int = 0

    @property
    def bst_modified(self) -> bool:
        return len(self.bst_pointers) > 0

    def memory_at(self, address: int, size: int = 8) -> Optional[int]:
        """Read tracked memory at address (None if never written)."""
        return self.memory.get(address)

    def bst_pointer_at(self, offset: int) -> Optional[int]:
        """Read BST pointer at given offset."""
        return self.bst_pointers.get(offset)

    def clone(self) -> 'ReplayState':
        return ReplayState(
            event_index=self.event_index,
            timestamp_ns=self.timestamp_ns,
            pc=self.pc,
            memory=dict(self.memory),
            bst_pointers=dict(self.bst_pointers),
            registers=dict(self.registers),
            events_processed=self.events_processed,
        )


class TraceReplayer:
    """
    Deterministic trace replayer.

    Replays a recorded trace event by event, maintaining state that can
    be queried at any point. Supports forward and backward traversal
    via checkpoints.
    """

    def __init__(self, trace_path: Path, bst_base: int = 0):
        self._trace_path = Path(trace_path)
        self._bst_base = bst_base
        self._reader: Optional[TraceReader] = None
        self._header: Optional[TraceHeader] = None
        self._state = ReplayState()
        self._checkpoints: List[Tuple[int, ReplayState]] = []
        self._checkpoint_interval: int = 1000
        self._event_callbacks: Dict[TraceEventType, List[Callable]] = {}
        self._breakpoints: Set[int] = set()
        self._watch_addresses: Set[int] = set()
        self._current_index: int = 0

    @property
    def header(self) -> Optional[TraceHeader]:
        return self._header

    @property
    def state(self) -> ReplayState:
        return self._state

    @property
    def current_index(self) -> int:
        return self._current_index

    @property
    def total_events(self) -> int:
        return self._header.event_count if self._header else 0

    @property
    def is_at_end(self) -> bool:
        return self._current_index >= self.total_events

    def open(self) -> TraceHeader:
        """Open trace file for replay."""
        self._reader = TraceReader(self._trace_path)
        self._header = self._reader.open()
        if self._bst_base == 0 and self._header.bst_address:
            self._bst_base = self._header.bst_address
        self._state = ReplayState()
        self._current_index = 0
        return self._header

    def close(self) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None

    def set_checkpoint_interval(self, interval: int) -> None:
        self._checkpoint_interval = max(1, interval)

    def add_breakpoint(self, pc: int) -> None:
        self._breakpoints.add(pc)

    def remove_breakpoint(self, pc: int) -> None:
        self._breakpoints.discard(pc)

    def add_watch(self, address: int) -> None:
        self._watch_addresses.add(address)

    def on_event(self, event_type: TraceEventType,
                 callback: Callable[[TraceEvent, ReplayState], None]) -> None:
        self._event_callbacks.setdefault(event_type, []).append(callback)

    def step(self) -> Optional[TraceEvent]:
        """Advance one event, returning it (or None at end)."""
        if not self._reader:
            raise RuntimeError("Trace not opened")

        event = self._reader.read_event()
        if event is None:
            return None

        self._apply_event(event)
        self._current_index += 1

        if self._current_index % self._checkpoint_interval == 0:
            self._checkpoints.append((self._current_index, self._state.clone()))

        self._fire_callbacks(event)
        return event

    def step_n(self, n: int) -> List[TraceEvent]:
        """Advance n events, returning all of them."""
        events = []
        for _ in range(n):
            ev = self.step()
            if ev is None:
                break
            events.append(ev)
        return events

    def run_to_index(self, target_index: int) -> ReplayState:
        """Replay from current position to target event index."""
        while self._current_index < target_index:
            ev = self.step()
            if ev is None:
                break
        return self._state

    def run_to_breakpoint(self) -> Optional[TraceEvent]:
        """Run until a breakpoint PC is hit or end of trace."""
        while True:
            ev = self.step()
            if ev is None:
                return None
            if ev.pc in self._breakpoints:
                return ev

    def run_to_bst_write(self) -> Optional[TraceEvent]:
        """Run until the next BST modification."""
        while True:
            ev = self.step()
            if ev is None:
                return None
            if ev.event_type == TraceEventType.BST_ACCESS:
                return ev

    def run_to_memory_write(self, address: int) -> Optional[TraceEvent]:
        """Run until a write to the specified address."""
        while True:
            ev = self.step()
            if ev is None:
                return None
            if (ev.event_type == TraceEventType.MEMORY_WRITE and
                    ev.address == address):
                return ev

    def seek_to(self, target_index: int) -> ReplayState:
        """
        Seek to an arbitrary event index (forward or backward).

        Uses checkpoints for efficient backward seeking.
        """
        if target_index == self._current_index:
            return self._state

        if target_index < self._current_index:
            best_checkpoint = None
            for idx, state in self._checkpoints:
                if idx <= target_index:
                    best_checkpoint = (idx, state)
                else:
                    break

            if best_checkpoint:
                self._current_index = best_checkpoint[0]
                self._state = best_checkpoint[1].clone()
                self._reader.seek_event(self._current_index)
            else:
                self._current_index = 0
                self._state = ReplayState()
                self._reader.seek_event(0)

        return self.run_to_index(target_index)

    def find_first_write_to(self, address: int,
                            start_index: int = 0) -> Optional[Tuple[int, TraceEvent]]:
        """Find the first event that writes to a specific address."""
        self.seek_to(start_index)
        while True:
            ev = self.step()
            if ev is None:
                return None
            if (ev.event_type in (TraceEventType.MEMORY_WRITE,
                                  TraceEventType.BST_ACCESS) and
                    ev.address == address):
                return (self._current_index - 1, ev)

    def find_bst_modifications(self) -> List[Tuple[int, TraceEvent]]:
        """Scan entire trace for all BST modification events."""
        self.seek_to(0)
        results = []
        while True:
            ev = self.step()
            if ev is None:
                break
            if ev.event_type == TraceEventType.BST_ACCESS:
                results.append((self._current_index - 1, ev))
        return results

    def get_state_at(self, index: int) -> ReplayState:
        """Get full replay state at a specific event index."""
        return self.seek_to(index)

    def _apply_event(self, event: TraceEvent) -> None:
        """Update tracked state based on an event."""
        self._state.event_index = self._current_index
        self._state.timestamp_ns = event.timestamp_ns
        self._state.pc = event.pc
        self._state.events_processed += 1

        if event.event_type == TraceEventType.MEMORY_WRITE:
            self._state.memory[event.address] = event.value

        elif event.event_type == TraceEventType.BST_ACCESS:
            if self._bst_base:
                offset = event.address - self._bst_base
            else:
                offset = event.address
            self._state.bst_pointers[offset] = event.value

    def _fire_callbacks(self, event: TraceEvent) -> None:
        """Invoke registered callbacks for this event type."""
        callbacks = self._event_callbacks.get(event.event_type, [])
        for cb in callbacks:
            try:
                cb(event, self._state)
            except Exception:
                pass

    def __enter__(self) -> 'TraceReplayer':
        self.open()
        return self

    def __exit__(self, *args) -> None:
        self.close()

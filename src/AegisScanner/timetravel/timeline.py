"""
Timeline - Constructs a security-event timeline from execution traces.

Transforms raw trace events into a human-readable timeline of
security-relevant events during UEFI boot.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional

from .trace_format import (
    TraceEvent,
    TraceEventType,
    TraceHeader,
    TraceReader,
)
from .trace_analyzer import TraceAnalyzer


class TimelineEventKind(IntEnum):
    """High-level timeline event categories."""
    BOOT_START = 0
    DXE_DISPATCH = 1
    BST_HOOK_INSTALLED = 2
    BST_HOOK_CALLED = 3
    MEMORY_PAYLOAD_WRITTEN = 4
    BOOT_SERVICE_CALL = 5
    RUNTIME_SERVICE_CALL = 6
    SMI_TRIGGERED = 7
    EXIT_BOOT_SERVICES = 8
    SUSPICIOUS_WRITE = 9
    MARKER = 10


@dataclass
class TimelineEvent:
    """A single event in the security timeline."""
    kind: TimelineEventKind
    timestamp_ns: int
    event_index: int
    pc: int = 0
    description: str = ""
    details: Dict = field(default_factory=dict)
    severity: int = 0  # 0=info, 1=low, 2=medium, 3=high, 4=critical

    @property
    def timestamp_ms(self) -> float:
        return self.timestamp_ns / 1_000_000

    @property
    def timestamp_s(self) -> float:
        return self.timestamp_ns / 1_000_000_000

    def to_dict(self) -> Dict:
        return {
            "kind": self.kind.name,
            "timestamp_ns": self.timestamp_ns,
            "timestamp_ms": self.timestamp_ms,
            "event_index": self.event_index,
            "pc": f"0x{self.pc:x}",
            "description": self.description,
            "severity": self.severity,
            "details": self.details,
        }


class Timeline:
    """
    Constructs a timeline of security-relevant events from a trace.

    Filters raw events into meaningful security milestones: hook
    installations, payload writes, boot service calls, and markers.
    """

    def __init__(self, trace_path: Optional[Path] = None,
                 bst_base: int = 0):
        self._trace_path = Path(trace_path) if trace_path else None
        self._bst_base = bst_base
        self._events: List[TimelineEvent] = []
        self._header: Optional[TraceHeader] = None

    @property
    def events(self) -> List[TimelineEvent]:
        return list(self._events)

    @property
    def event_count(self) -> int:
        return len(self._events)

    def build_from_trace(self, trace_path: Optional[Path] = None) -> 'Timeline':
        """Build timeline by scanning the trace file."""
        path = Path(trace_path) if trace_path else self._trace_path
        if not path:
            raise ValueError("No trace path specified")

        reader = TraceReader(path)
        self._header = reader.open()
        if self._bst_base == 0 and self._header.bst_address:
            self._bst_base = self._header.bst_address

        self._events = []
        self._events.append(TimelineEvent(
            kind=TimelineEventKind.BOOT_START,
            timestamp_ns=0,
            event_index=0,
            description="Boot sequence started",
            severity=0,
        ))

        for idx, event in enumerate(reader.iter_events()):
            timeline_event = self._classify_event(idx, event)
            if timeline_event:
                self._events.append(timeline_event)

        reader.close()
        self._events.sort(key=lambda e: e.timestamp_ns)
        return self

    def build_from_events(self, events: List[TraceEvent]) -> 'Timeline':
        """Build timeline from an in-memory event list."""
        self._events = []
        self._events.append(TimelineEvent(
            kind=TimelineEventKind.BOOT_START,
            timestamp_ns=0,
            event_index=0,
            description="Boot sequence started",
            severity=0,
        ))

        for idx, event in enumerate(events):
            timeline_event = self._classify_event(idx, event)
            if timeline_event:
                self._events.append(timeline_event)

        self._events.sort(key=lambda e: e.timestamp_ns)
        return self

    def filter_by_kind(self, kind: TimelineEventKind) -> List[TimelineEvent]:
        """Return only events of a specific kind."""
        return [e for e in self._events if e.kind == kind]

    def filter_by_severity(self, min_severity: int) -> List[TimelineEvent]:
        """Return events at or above a severity threshold."""
        return [e for e in self._events if e.severity >= min_severity]

    def get_hooks_installed(self) -> List[TimelineEvent]:
        """Return all BST hook installation events."""
        return self.filter_by_kind(TimelineEventKind.BST_HOOK_INSTALLED)

    def get_suspicious_events(self) -> List[TimelineEvent]:
        """Return all events with severity >= high."""
        return self.filter_by_severity(3)

    def time_between(self, first_kind: TimelineEventKind,
                     second_kind: TimelineEventKind) -> Optional[int]:
        """Return nanoseconds between first occurrence of two event kinds."""
        first = next((e for e in self._events if e.kind == first_kind), None)
        second = next((e for e in self._events if e.kind == second_kind), None)
        if first and second:
            return second.timestamp_ns - first.timestamp_ns
        return None

    def to_report(self) -> List[Dict]:
        """Export timeline as a list of dictionaries."""
        return [e.to_dict() for e in self._events]

    def summary(self) -> Dict:
        """Produce a summary of the timeline."""
        kind_counts = {}
        max_severity = 0
        for e in self._events:
            kind_counts[e.kind.name] = kind_counts.get(e.kind.name, 0) + 1
            max_severity = max(max_severity, e.severity)

        hooks = self.get_hooks_installed()
        return {
            "total_events": len(self._events),
            "event_kind_counts": kind_counts,
            "max_severity": max_severity,
            "hooks_installed": len(hooks),
            "hook_targets": [h.details.get("service_name", "unknown")
                            for h in hooks],
            "duration_ns": (self._events[-1].timestamp_ns
                          if self._events else 0),
        }

    def _classify_event(self, idx: int, event: TraceEvent
                        ) -> Optional[TimelineEvent]:
        """Classify a raw trace event into a timeline event."""
        if event.event_type == TraceEventType.BST_ACCESS:
            return self._make_bst_hook_event(idx, event)

        elif event.event_type == TraceEventType.BOOT_SERVICE_CALL:
            if event.value == 0xE0:  # ExitBootServices offset
                return TimelineEvent(
                    kind=TimelineEventKind.EXIT_BOOT_SERVICES,
                    timestamp_ns=event.timestamp_ns,
                    event_index=idx,
                    pc=event.pc,
                    description="ExitBootServices called",
                    severity=0,
                )
            return TimelineEvent(
                kind=TimelineEventKind.BOOT_SERVICE_CALL,
                timestamp_ns=event.timestamp_ns,
                event_index=idx,
                pc=event.pc,
                description=f"Boot service call at 0x{event.pc:x}",
                severity=0,
            )

        elif event.event_type == TraceEventType.RUNTIME_SERVICE_CALL:
            return TimelineEvent(
                kind=TimelineEventKind.RUNTIME_SERVICE_CALL,
                timestamp_ns=event.timestamp_ns,
                event_index=idx,
                pc=event.pc,
                description=f"Runtime service call at 0x{event.pc:x}",
                severity=0,
            )

        elif event.event_type == TraceEventType.SMI_ENTRY:
            return TimelineEvent(
                kind=TimelineEventKind.SMI_TRIGGERED,
                timestamp_ns=event.timestamp_ns,
                event_index=idx,
                pc=event.pc,
                description=f"SMI triggered at 0x{event.pc:x}",
                severity=2,
            )

        elif event.event_type == TraceEventType.MARKER:
            return TimelineEvent(
                kind=TimelineEventKind.MARKER,
                timestamp_ns=event.timestamp_ns,
                event_index=idx,
                pc=event.pc,
                description=f"Marker {event.value}",
                details={"marker_id": event.value},
                severity=0,
            )

        return None

    def _make_bst_hook_event(self, idx: int, event: TraceEvent
                             ) -> TimelineEvent:
        """Create a timeline event for a BST modification."""
        bst_offset = (event.address - self._bst_base
                      if self._bst_base else event.address)
        service_name = TraceAnalyzer.BST_OFFSETS.get(
            bst_offset, f"offset_0x{bst_offset:x}")

        return TimelineEvent(
            kind=TimelineEventKind.BST_HOOK_INSTALLED,
            timestamp_ns=event.timestamp_ns,
            event_index=idx,
            pc=event.pc,
            description=f"BST hook installed: {service_name} -> 0x{event.value:x}",
            severity=4,
            details={
                "bst_offset": bst_offset,
                "service_name": service_name,
                "old_handler": event.aux_data,
                "new_handler": event.value,
                "installing_pc": event.pc,
            },
        )

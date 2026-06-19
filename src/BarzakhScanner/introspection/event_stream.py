"""
Event Stream - Real-time introspection event processing.

Collects events from memory watchers and breakpoint engines,
classifies them, and provides a unified event timeline.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Dict, List, Optional

from .memory_watch import ChangeType, MemoryChange, MemoryWatcher
from .breakpoint_engine import BreakpointHit


class EventType(Enum):
    BST_HOOK_INSTALLED = "bst_hook_installed"
    BST_HOOK_REMOVED = "bst_hook_removed"
    CODE_INJECTION = "code_injection"
    MEMORY_TAMPER = "memory_tamper"
    NEW_DRIVER_LOADED = "new_driver_loaded"
    PCR_EXTEND = "pcr_extend"
    SECURE_BOOT_BYPASS = "secure_boot_bypass"
    RUNTIME_SERVICE_HOOK = "runtime_service_hook"
    SMM_CALLOUT = "smm_callout"
    SUSPICIOUS_ALLOC = "suspicious_alloc"
    BREAKPOINT_HIT = "breakpoint_hit"
    VM_STATE_CHANGE = "vm_state_change"


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IntrospectionEvent:
    """A single introspection event."""
    event_type: EventType
    severity: Severity
    timestamp: float
    description: str
    address: Optional[int] = None
    details: Dict = field(default_factory=dict)
    source: str = ""

    def to_dict(self) -> Dict:
        return {
            "type": self.event_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "description": self.description,
            "address": f"{self.address:#x}" if self.address else None,
            "details": self.details,
            "source": self.source,
        }


class EventStream:
    """
    Unified event processing pipeline.

    Consumes raw events from MemoryWatcher and BreakpointEngine,
    classifies them by severity, and dispatches to subscribers.
    """

    MAX_EVENTS = 10000

    # BST function names that are high-value hook targets
    HIGH_VALUE_BST_HOOKS = {
        "LoadImage", "StartImage", "ExitBootServices",
        "SetVariable", "GetVariable",
    }

    def __init__(self):
        self._events: Deque[IntrospectionEvent] = deque(maxlen=self.MAX_EVENTS)
        self._subscribers: List[Callable[[IntrospectionEvent], None]] = []
        self._filters: List[Callable[[IntrospectionEvent], bool]] = []
        self._event_count: Dict[EventType, int] = {}
        self._start_time = time.time()

    def subscribe(self, callback: Callable[[IntrospectionEvent], None]) -> None:
        """Subscribe to receive events."""
        self._subscribers.append(callback)

    def add_filter(self, filter_fn: Callable[[IntrospectionEvent], bool]) -> None:
        """Add an event filter. Events passing the filter are emitted."""
        self._filters.append(filter_fn)

    def process_memory_change(self, change: MemoryChange) -> Optional[IntrospectionEvent]:
        """Process a memory change into an introspection event."""
        event = self._classify_memory_change(change)
        if event:
            self._emit(event)
        return event

    def process_breakpoint_hit(self, hit: BreakpointHit) -> Optional[IntrospectionEvent]:
        """Process a breakpoint hit into an introspection event."""
        event = IntrospectionEvent(
            event_type=EventType.BREAKPOINT_HIT,
            severity=Severity.MEDIUM,
            timestamp=hit.timestamp,
            description=f"Breakpoint hit at {hit.pc:#x}: {hit.breakpoint.label}",
            address=hit.pc,
            details={
                "bp_id": hit.breakpoint.bp_id,
                "label": hit.breakpoint.label,
                "hit_count": hit.breakpoint.hit_count,
                "registers": {k: f"{v:#x}" for k, v in hit.registers.items()},
            },
            source="breakpoint_engine",
        )
        self._emit(event)
        return event

    def emit_custom(
        self,
        event_type: EventType,
        severity: Severity,
        description: str,
        address: Optional[int] = None,
        details: Optional[Dict] = None,
    ) -> IntrospectionEvent:
        """Emit a custom event."""
        event = IntrospectionEvent(
            event_type=event_type,
            severity=severity,
            timestamp=time.time(),
            description=description,
            address=address,
            details=details or {},
            source="custom",
        )
        self._emit(event)
        return event

    def get_events(
        self,
        event_type: Optional[EventType] = None,
        min_severity: Optional[Severity] = None,
        since: Optional[float] = None,
    ) -> List[IntrospectionEvent]:
        """Query events with optional filters."""
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

        results = []
        for event in self._events:
            if event_type and event.event_type != event_type:
                continue
            if min_severity:
                if severity_order.index(event.severity) < severity_order.index(min_severity):
                    continue
            if since and event.timestamp < since:
                continue
            results.append(event)
        return results

    def get_timeline(self) -> List[Dict]:
        """Get full event timeline as serializable dicts."""
        return [e.to_dict() for e in self._events]

    def get_stats(self) -> Dict:
        """Get event statistics."""
        return {
            "total_events": len(self._events),
            "by_type": {k.value: v for k, v in self._event_count.items()},
            "uptime_seconds": time.time() - self._start_time,
        }

    def clear(self) -> None:
        """Clear all events."""
        self._events.clear()
        self._event_count.clear()

    def _emit(self, event: IntrospectionEvent) -> None:
        """Emit an event to all subscribers."""
        # Apply filters
        for f in self._filters:
            if not f(event):
                return

        self._events.append(event)
        self._event_count[event.event_type] = self._event_count.get(event.event_type, 0) + 1

        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception:
                pass

    def _classify_memory_change(self, change: MemoryChange) -> Optional[IntrospectionEvent]:
        """Classify a memory change into a typed introspection event."""
        if change.change_type == ChangeType.POINTER_MODIFIED:
            return self._classify_pointer_change(change)
        elif change.change_type == ChangeType.CODE_INJECTED:
            return IntrospectionEvent(
                event_type=EventType.CODE_INJECTION,
                severity=Severity.CRITICAL,
                timestamp=change.timestamp,
                description=(
                    f"Code injection detected at {change.address:#x} "
                    f"in region '{change.region_name}'"
                ),
                address=change.address,
                details={
                    "old_bytes": change.old_value.hex(),
                    "new_bytes": change.new_value.hex(),
                    "region": change.region_name,
                },
                source="memory_watcher",
            )
        elif change.change_type == ChangeType.DATA_WRITTEN:
            return IntrospectionEvent(
                event_type=EventType.MEMORY_TAMPER,
                severity=Severity.MEDIUM,
                timestamp=change.timestamp,
                description=(
                    f"Memory modification at {change.address:#x} "
                    f"in region '{change.region_name}' ({len(change.new_value)} bytes)"
                ),
                address=change.address,
                details={
                    "region": change.region_name,
                    "size": len(change.new_value),
                },
                source="memory_watcher",
            )
        return None

    def _classify_pointer_change(self, change: MemoryChange) -> IntrospectionEvent:
        """Classify a pointer modification event."""
        from .memory_watch import MemoryWatcher

        # Check if this is a BST pointer
        func_name = MemoryWatcher.BST_OFFSETS.get(change.offset, "")

        if func_name:
            severity = (
                Severity.CRITICAL if func_name in self.HIGH_VALUE_BST_HOOKS
                else Severity.HIGH
            )
            return IntrospectionEvent(
                event_type=EventType.BST_HOOK_INSTALLED,
                severity=severity,
                timestamp=change.timestamp,
                description=(
                    f"BST hook: {func_name} pointer changed "
                    f"{change.old_value_int:#x} → {change.new_value_int:#x}"
                ),
                address=change.address,
                details={
                    "function": func_name,
                    "old_pointer": f"{change.old_value_int:#x}",
                    "new_pointer": f"{change.new_value_int:#x}",
                    "offset": f"{change.offset:#x}",
                },
                source="memory_watcher",
            )
        else:
            return IntrospectionEvent(
                event_type=EventType.MEMORY_TAMPER,
                severity=Severity.HIGH,
                timestamp=change.timestamp,
                description=(
                    f"Pointer modified at offset {change.offset:#x} "
                    f"in region '{change.region_name}'"
                ),
                address=change.address,
                details={
                    "old_value": f"{change.old_value_int:#x}",
                    "new_value": f"{change.new_value_int:#x}",
                },
                source="memory_watcher",
            )

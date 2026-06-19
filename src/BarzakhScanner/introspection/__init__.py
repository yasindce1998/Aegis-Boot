"""
Live UEFI Introspection Engine.

Real-time hypervisor-level monitoring of UEFI execution via QEMU's QMP
protocol, detecting BST modifications and payload injection as they happen.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

try:
    from .qemu_monitor import QMPClient, QMPError
    from .memory_watch import MemoryWatcher, MemoryRegion, MemoryChange
    from .breakpoint_engine import BreakpointEngine, Breakpoint, BreakpointHit
    from .event_stream import EventStream, IntrospectionEvent, EventType
    from .introspection_runner import IntrospectionRunner, IntrospectionConfig
    from .live_detector import LiveDetector, LiveFinding
except ImportError:
    from BarzakhScanner.introspection.qemu_monitor import QMPClient, QMPError
    from BarzakhScanner.introspection.memory_watch import MemoryWatcher, MemoryRegion, MemoryChange
    from BarzakhScanner.introspection.breakpoint_engine import BreakpointEngine, Breakpoint, BreakpointHit
    from BarzakhScanner.introspection.event_stream import EventStream, IntrospectionEvent, EventType
    from BarzakhScanner.introspection.introspection_runner import IntrospectionRunner, IntrospectionConfig
    from BarzakhScanner.introspection.live_detector import LiveDetector, LiveFinding

__all__ = [
    'QMPClient', 'QMPError',
    'MemoryWatcher', 'MemoryRegion', 'MemoryChange',
    'BreakpointEngine', 'Breakpoint', 'BreakpointHit',
    'EventStream', 'IntrospectionEvent', 'EventType',
    'IntrospectionRunner', 'IntrospectionConfig',
    'LiveDetector', 'LiveFinding',
]

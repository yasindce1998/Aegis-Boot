"""
Live UEFI Introspection Engine.

Real-time hypervisor-level monitoring of UEFI execution via QEMU's QMP
protocol, detecting BST modifications and payload injection as they happen.

Copyright (c) 2026, Aegis-Boot Research Project
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
    from AegisScanner.introspection.qemu_monitor import QMPClient, QMPError
    from AegisScanner.introspection.memory_watch import MemoryWatcher, MemoryRegion, MemoryChange
    from AegisScanner.introspection.breakpoint_engine import BreakpointEngine, Breakpoint, BreakpointHit
    from AegisScanner.introspection.event_stream import EventStream, IntrospectionEvent, EventType
    from AegisScanner.introspection.introspection_runner import IntrospectionRunner, IntrospectionConfig
    from AegisScanner.introspection.live_detector import LiveDetector, LiveFinding

__all__ = [
    'QMPClient', 'QMPError',
    'MemoryWatcher', 'MemoryRegion', 'MemoryChange',
    'BreakpointEngine', 'Breakpoint', 'BreakpointHit',
    'EventStream', 'IntrospectionEvent', 'EventType',
    'IntrospectionRunner', 'IntrospectionConfig',
    'LiveDetector', 'LiveFinding',
]

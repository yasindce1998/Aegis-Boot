"""
Time-Travel Debugging - Record and replay UEFI boot execution traces.

Provides deterministic replay of UEFI boot sequences with the ability
to query state at any point in time, supporting post-hoc analysis of
bootkit installation, BST modifications, and firmware tampering.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

try:
    from .trace_format import (
        TraceEvent,
        TraceEventType,
        MemoryAccessType,
        TraceHeader,
        TraceWriter,
        TraceReader,
    )
    from .recorder import TraceRecorder, RecordingConfig
    from .replayer import TraceReplayer, ReplayState
    from .trace_analyzer import TraceAnalyzer, AnalysisResult
    from .timeline import Timeline, TimelineEvent, TimelineEventKind
except ImportError:
    pass

__all__ = [
    'TraceEvent',
    'TraceEventType',
    'MemoryAccessType',
    'TraceHeader',
    'TraceWriter',
    'TraceReader',
    'TraceRecorder',
    'RecordingConfig',
    'TraceReplayer',
    'ReplayState',
    'TraceAnalyzer',
    'AnalysisResult',
    'Timeline',
    'TimelineEvent',
    'TimelineEventKind',
]

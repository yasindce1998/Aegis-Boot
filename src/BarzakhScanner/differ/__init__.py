"""
Differential Firmware Diffing Engine

Semantic firmware diff that understands FV/FFS structure, classifies changes
by type and severity, and produces actionable diff reports.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

try:
    from .fv_differ import FirmwareDiffer, DiffResult, FileDiff, VolumeDiff
    from .semantic_diff import SemanticAnalyzer, ChangeClassification
    from .diff_report import DiffReportGenerator
    from .baseline_db import BaselineDB
except ImportError:
    from differ.fv_differ import FirmwareDiffer, DiffResult, FileDiff, VolumeDiff
    from differ.semantic_diff import SemanticAnalyzer, ChangeClassification
    from differ.diff_report import DiffReportGenerator
    from differ.baseline_db import BaselineDB

__all__ = [
    'FirmwareDiffer',
    'DiffResult',
    'FileDiff',
    'VolumeDiff',
    'SemanticAnalyzer',
    'ChangeClassification',
    'DiffReportGenerator',
    'BaselineDB',
]

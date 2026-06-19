"""
Diff Report Generator - Human-readable and machine-parseable diff reports.

Produces reports in JSON, Markdown, and summary formats from firmware diffs.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import json
from datetime import datetime
from typing import Dict, List, Optional

try:
    from .fv_differ import DiffResult, DiffType
    from .semantic_diff import ChangeClassification, Severity, ChangeCategory
except ImportError:
    from differ.fv_differ import DiffResult, DiffType
    from differ.semantic_diff import ChangeClassification, Severity, ChangeCategory


class DiffReportGenerator:
    """Generates diff reports in multiple formats."""

    def __init__(self, diff_result: DiffResult,
                 classifications: Optional[List[ChangeClassification]] = None):
        self.diff_result = diff_result
        self.classifications = classifications or []

    def generate_json(self, output_path: str):
        """Generate JSON diff report."""
        report = self._build_report_data()
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

    def generate_markdown(self, output_path: str):
        """Generate Markdown diff report."""
        md = self._build_markdown()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

    def to_dict(self) -> Dict:
        """Return report as dictionary."""
        return self._build_report_data()

    def _build_report_data(self) -> Dict:
        """Build structured report data."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'baseline': self.diff_result.baseline_path,
            'target': self.diff_result.target_path,
            'summary': {
                'total_files_compared': self.diff_result.total_files_compared,
                'added': self.diff_result.total_added,
                'removed': self.diff_result.total_removed,
                'modified': self.diff_result.total_modified,
                'unchanged': self.diff_result.total_unchanged,
                'has_changes': self.diff_result.has_changes,
            },
            'volumes': [],
            'classifications': [],
        }

        for vol_diff in self.diff_result.volume_diffs:
            vol_data = {
                'guid': vol_diff.guid,
                'baseline_offset': f'0x{vol_diff.baseline_offset:x}',
                'target_offset': f'0x{vol_diff.target_offset:x}',
                'changes': {
                    'added': vol_diff.added_count,
                    'removed': vol_diff.removed_count,
                    'modified': vol_diff.modified_count,
                },
                'files': [],
            }

            for fd in vol_diff.file_diffs:
                if fd.diff_type == DiffType.UNCHANGED:
                    continue
                vol_data['files'].append({
                    'guid': fd.guid,
                    'diff_type': fd.diff_type.name,
                    'file_type': fd.file_type_name,
                    'baseline_hash': fd.baseline_hash,
                    'target_hash': fd.target_hash,
                    'size_delta': fd.size_delta,
                    'sections_changed': fd.sections_changed,
                })

            if vol_data['files'] or vol_diff.has_changes:
                report['volumes'].append(vol_data)

        for cls in self.classifications:
            report['classifications'].append({
                'title': cls.title,
                'severity': cls.severity.name,
                'category': cls.category.name,
                'guid': cls.file_diff.guid,
                'confidence': cls.confidence,
                'description': cls.description,
                'indicators': cls.indicators,
            })

        return report

    def _build_markdown(self) -> str:
        """Build Markdown report."""
        lines = []
        lines.append('# Firmware Diff Report')
        lines.append('')
        lines.append(f'**Baseline:** `{self.diff_result.baseline_path}`')
        lines.append(f'**Target:** `{self.diff_result.target_path}`')
        lines.append(f'**Generated:** {datetime.now().isoformat()}')
        lines.append('')

        # Summary
        lines.append('## Summary')
        lines.append('')
        lines.append(f'| Metric | Count |')
        lines.append(f'|--------|-------|')
        lines.append(f'| Files compared | {self.diff_result.total_files_compared} |')
        lines.append(f'| Added | {self.diff_result.total_added} |')
        lines.append(f'| Removed | {self.diff_result.total_removed} |')
        lines.append(f'| Modified | {self.diff_result.total_modified} |')
        lines.append(f'| Unchanged | {self.diff_result.total_unchanged} |')
        lines.append('')

        # Threat classifications
        if self.classifications:
            critical = [c for c in self.classifications if c.severity >= Severity.HIGH]
            if critical:
                lines.append('## Threats Detected')
                lines.append('')
                for cls in critical:
                    icon = '🔴' if cls.severity == Severity.CRITICAL else '🟠'
                    lines.append(f'### {icon} {cls.title}')
                    lines.append('')
                    lines.append(f'- **Severity:** {cls.severity.name}')
                    lines.append(f'- **Category:** {cls.category.name}')
                    lines.append(f'- **GUID:** `{cls.file_diff.guid}`')
                    lines.append(f'- **Confidence:** {cls.confidence:.0%}')
                    lines.append(f'- **Description:** {cls.description}')
                    if cls.indicators:
                        lines.append(f'- **Indicators:** {", ".join(cls.indicators)}')
                    lines.append('')

        # Volume details
        lines.append('## Volume Details')
        lines.append('')

        for vol_diff in self.diff_result.volume_diffs:
            if not vol_diff.has_changes:
                continue
            lines.append(f'### FV `{vol_diff.guid}`')
            lines.append('')
            lines.append(f'Baseline offset: `0x{vol_diff.baseline_offset:x}` | '
                        f'Target offset: `0x{vol_diff.target_offset:x}`')
            lines.append('')

            changed_files = [f for f in vol_diff.file_diffs if f.diff_type != DiffType.UNCHANGED]
            if changed_files:
                lines.append('| GUID | Type | Change | Size Delta |')
                lines.append('|------|------|--------|------------|')
                for fd in changed_files:
                    lines.append(
                        f'| `{fd.guid}` | {fd.file_type_name} | '
                        f'{fd.diff_type.name} | {fd.size_delta:+d} |'
                    )
                lines.append('')

        return '\n'.join(lines)

    def get_scanner_findings(self) -> List[Dict]:
        """Convert classifications to scanner-compatible findings."""
        return [cls.to_finding() for cls in self.classifications
                if cls.severity >= Severity.MEDIUM]

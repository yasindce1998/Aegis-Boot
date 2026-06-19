"""
Behavior Report — Summarizes bootkit behavior from symbolic analysis.

Produces human-readable and structured reports describing what a binary
does: hooks installed, conditions, persistence, evasion techniques.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .hook_analyzer import HookAnalyzer, HookBehavior
from .path_explorer import PathExplorer, PathSummary
from .efi_environment import EfiEnvironment


@dataclass
class BehaviorFinding:
    """A single behavioral finding."""
    category: str  # hook, persistence, evasion, payload, privilege
    severity: int  # 0-4
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)


@dataclass
class BehaviorReport:
    """
    Complete behavioral analysis report for a binary.

    Aggregates findings from path exploration, hook analysis,
    and constraint solving into a coherent report.
    """
    binary_name: str = ""
    binary_size: int = 0
    entry_point: int = 0
    findings: List[BehaviorFinding] = field(default_factory=list)
    paths_explored: int = 0
    hooks_detected: int = 0
    is_bootkit: bool = False
    confidence: float = 0.0
    techniques: List[str] = field(default_factory=list)

    @property
    def critical_findings(self) -> List[BehaviorFinding]:
        return [f for f in self.findings if f.severity >= 4]

    @property
    def high_findings(self) -> List[BehaviorFinding]:
        return [f for f in self.findings if f.severity >= 3]

    def add_finding(self, category: str, severity: int,
                    title: str, description: str,
                    evidence: Optional[Dict] = None):
        """Add a finding to the report."""
        self.findings.append(BehaviorFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence or {},
        ))

    def to_dict(self) -> Dict:
        """Export report as dictionary."""
        return {
            'binary_name': self.binary_name,
            'binary_size': self.binary_size,
            'entry_point': f'0x{self.entry_point:x}',
            'is_bootkit': self.is_bootkit,
            'confidence': self.confidence,
            'techniques': self.techniques,
            'paths_explored': self.paths_explored,
            'hooks_detected': self.hooks_detected,
            'findings': [
                {
                    'category': f.category,
                    'severity': f.severity,
                    'title': f.title,
                    'description': f.description,
                    'evidence': f.evidence,
                }
                for f in self.findings
            ],
            'summary': self.text_summary(),
        }

    def text_summary(self) -> str:
        """Generate human-readable summary."""
        lines = []
        lines.append(f"Binary: {self.binary_name} ({self.binary_size} bytes)")
        lines.append(f"Entry: 0x{self.entry_point:x}")
        lines.append(f"Verdict: {'BOOTKIT DETECTED' if self.is_bootkit else 'Clean/Unknown'}")
        lines.append(f"Confidence: {self.confidence:.1%}")
        lines.append(f"Paths explored: {self.paths_explored}")
        lines.append(f"Hooks detected: {self.hooks_detected}")

        if self.techniques:
            lines.append(f"Techniques: {', '.join(self.techniques)}")

        if self.findings:
            lines.append(f"\nFindings ({len(self.findings)}):")
            for f in sorted(self.findings, key=lambda x: -x.severity):
                sev = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][f.severity]
                lines.append(f"  [{sev}] {f.title}")
                lines.append(f"    {f.description}")

        return '\n'.join(lines)


class BehaviorReportBuilder:
    """Builds a BehaviorReport from analysis results."""

    BOOTKIT_INDICATORS = {
        'bst_hook': 4,
        'rst_hook': 4,
        'spi_write': 4,
        'nvram_persistence': 3,
        'conditional_activation': 2,
        'input_filtering': 2,
        'timer_delay': 1,
        'memory_payload': 3,
    }

    def __init__(self):
        self._report = BehaviorReport()

    def set_binary_info(self, name: str, size: int, entry: int):
        """Set basic binary metadata."""
        self._report.binary_name = name
        self._report.binary_size = size
        self._report.entry_point = entry

    def add_path_results(self, explorer: PathExplorer):
        """Incorporate path exploration results."""
        self._report.paths_explored = explorer.path_count

        for path in explorer.explored_paths:
            if path.hooks_installed:
                self._report.hooks_detected += len(path.hooks_installed)
                for hook in path.hooks_installed:
                    self._report.add_finding(
                        category='hook',
                        severity=4,
                        title=f"BST hook: {hook.get('service', 'unknown')}",
                        description=(
                            f"Installs hook at BST offset 0x{hook.get('offset', 0):x} "
                            f"({hook.get('service', 'unknown')}), "
                            f"redirecting to 0x{hook.get('new_handler', 0):x}"
                        ),
                        evidence=hook,
                    )

            for write in path.memory_writes:
                if write.is_symbolic:
                    self._report.add_finding(
                        category='payload',
                        severity=2,
                        title=f"Symbolic memory write at 0x{write.address:x}",
                        description=(
                            f"Write of {write.size} bytes to 0x{write.address:x} "
                            f"from PC 0x{write.pc:x}"
                        ),
                    )

    def add_hook_analysis(self, analyzer: HookAnalyzer):
        """Incorporate hook analysis results."""
        for hook in analyzer.hooks:
            if hook.filter_conditions:
                self._report.techniques.append('conditional_hook')
                self._report.add_finding(
                    category='evasion',
                    severity=2,
                    title=f"Conditional hook on {hook.hooked_service}",
                    description=(
                        f"Hook activates conditionally: "
                        f"{'; '.join(hook.filter_conditions)}"
                    ),
                )

            if hook.persistence_mechanism:
                self._report.techniques.append(
                    f"persistence:{hook.persistence_mechanism}")
                self._report.add_finding(
                    category='persistence',
                    severity=3,
                    title=f"Persistence via {hook.persistence_mechanism}",
                    description=(
                        f"Hook on {hook.hooked_service} uses "
                        f"{hook.persistence_mechanism} for persistence"
                    ),
                )

            if hook.calls_original:
                self._report.techniques.append('transparent_hook')

    def add_environment_results(self, env: EfiEnvironment):
        """Incorporate EFI environment interaction results."""
        summary = env.summary()
        if summary['total_service_calls'] > 0:
            self._report.add_finding(
                category='behavior',
                severity=0,
                title=f"EFI services usage",
                description=(
                    f"Called {summary['unique_services_called']} unique "
                    f"services, {summary['total_service_calls']} total calls"
                ),
                evidence=summary['service_call_counts'],
            )

    def compute_verdict(self) -> BehaviorReport:
        """Compute final bootkit verdict and confidence."""
        score = 0
        max_score = 0

        for finding in self._report.findings:
            score += finding.severity
            max_score += 4

        if self._report.hooks_detected > 0:
            score += 10

        if max_score > 0:
            self._report.confidence = min(1.0, score / max(max_score, 20))
        else:
            self._report.confidence = 0.0

        self._report.is_bootkit = (
            self._report.hooks_detected > 0 or
            self._report.confidence > 0.5
        )

        self._report.techniques = list(set(self._report.techniques))
        return self._report

    def build(self) -> BehaviorReport:
        """Finalize and return the report."""
        return self.compute_verdict()

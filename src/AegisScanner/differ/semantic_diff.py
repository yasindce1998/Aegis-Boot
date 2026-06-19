"""
Semantic Diff Analyzer - Classifies firmware changes by threat level.

Applies domain knowledge about UEFI firmware to classify structural
differences into security-relevant categories with severity scoring.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional

try:
    from .fv_differ import DiffResult, FileDiff, VolumeDiff, DiffType
except ImportError:
    from differ.fv_differ import DiffResult, FileDiff, VolumeDiff, DiffType


class ChangeCategory(IntEnum):
    """Category of firmware change."""
    BENIGN = 0
    CONFIGURATION = 1
    UPDATE = 2
    SUSPICIOUS = 3
    MALICIOUS = 4


class Severity(IntEnum):
    """Severity level for a classified change."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ChangeClassification:
    """A classified firmware change with context."""
    file_diff: FileDiff
    volume_guid: str
    category: ChangeCategory
    severity: Severity
    title: str
    description: str
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.5

    def to_finding(self) -> Dict:
        """Convert to scanner-compatible finding dict."""
        severity_map = {
            Severity.INFO: 'info',
            Severity.LOW: 'low',
            Severity.MEDIUM: 'medium',
            Severity.HIGH: 'high',
            Severity.CRITICAL: 'critical',
        }
        return {
            'detector': 'firmware_differ',
            'severity': severity_map[self.severity],
            'title': self.title,
            'description': self.description,
            'details': {
                'guid': self.file_diff.guid,
                'file_type': self.file_diff.file_type_name,
                'diff_type': self.file_diff.diff_type.name,
                'category': self.category.name,
                'volume_guid': self.volume_guid,
                'baseline_hash': self.file_diff.baseline_hash,
                'target_hash': self.file_diff.target_hash,
                'size_delta': self.file_diff.size_delta,
                'sections_changed': self.file_diff.sections_changed,
                'indicators': self.indicators,
            },
            'confidence': self.confidence,
            'recommendation': self._get_recommendation(),
        }

    def _get_recommendation(self) -> str:
        if self.severity >= Severity.CRITICAL:
            return (
                'Immediately investigate this component. An added or modified '
                'DXE driver is the primary vector for UEFI bootkits. Compare '
                'against vendor firmware release notes.'
            )
        elif self.severity >= Severity.HIGH:
            return (
                'Investigate this modification. Compare against known firmware '
                'updates from the vendor. Check if the change correlates with '
                'a legitimate update.'
            )
        elif self.severity >= Severity.MEDIUM:
            return (
                'Review this change. May be a legitimate configuration update '
                'or NVRAM change, but should be verified.'
            )
        return 'Informational finding. No immediate action required.'


# Known GUIDs that are commonly targeted by bootkits
KNOWN_BOOTKIT_TARGET_GUIDS = {
    '7c04a583-9e3e-4f1c-ad65-e05268d0b4d1',  # DxeCore
    'fc510ee7-ffdc-11d4-bd41-0080c73c8881',  # BDS (Boot Device Selection)
    'b601f8c4-43b7-4784-95b1-f4226cb340be',  # RuntimeDxe
}

# GUIDs that are benign when modified (NVRAM, config)
KNOWN_BENIGN_GUIDS = {
    'fff12b8d-7696-4c8b-a985-2747075b4f50',  # NvStorage
    'cef5b9a3-476d-497f-9fdc-e98143e0422c',  # NvStorageFtwWorking
    '00504624-8a59-4eeb-bd0f-6b36e96128e0',  # NvStorageFtwSpare
}


class SemanticAnalyzer:
    """
    Classifies firmware differences by their security significance.

    Takes raw structural diffs and applies UEFI domain knowledge to
    determine whether changes are benign, suspicious, or malicious.
    """

    def __init__(self, known_update_hashes: Optional[Dict[str, str]] = None):
        """
        Args:
            known_update_hashes: Dict mapping GUID -> expected hash after legitimate update
        """
        self.known_update_hashes = known_update_hashes or {}

    def analyze(self, diff_result: DiffResult) -> List[ChangeClassification]:
        """
        Classify all changes in a diff result.

        Args:
            diff_result: Raw structural diff from FirmwareDiffer

        Returns:
            List of classified changes, sorted by severity (highest first)
        """
        classifications = []

        for vol_diff in diff_result.volume_diffs:
            for file_diff in vol_diff.file_diffs:
                if file_diff.diff_type == DiffType.UNCHANGED:
                    continue
                classification = self._classify_change(file_diff, vol_diff.guid)
                classifications.append(classification)

        # Handle entire volumes that only exist in target (suspicious)
        for fv in diff_result.unmatched_target_volumes:
            for ff in fv.files:
                fake_diff = FileDiff(
                    guid=ff.guid,
                    diff_type=DiffType.ADDED,
                    file_type=ff.type,
                    file_type_name='DRIVER' if ff.type == 0x07 else 'UNKNOWN',
                    target_hash=ff.hash,
                    target_size=ff.size,
                    target_offset=ff.offset,
                )
                classifications.append(self._classify_change(fake_diff, fv.guid))

        # Handle entire volumes removed from baseline
        for fv in diff_result.unmatched_baseline_volumes:
            for ff in fv.files:
                fake_diff = FileDiff(
                    guid=ff.guid,
                    diff_type=DiffType.REMOVED,
                    file_type=ff.type,
                    file_type_name='DRIVER' if ff.type == 0x07 else 'UNKNOWN',
                    baseline_hash=ff.hash,
                    baseline_size=ff.size,
                    baseline_offset=ff.offset,
                )
                classifications.append(self._classify_change(fake_diff, fv.guid))

        classifications.sort(key=lambda c: c.severity, reverse=True)
        return classifications

    def _classify_change(self, file_diff: FileDiff, volume_guid: str) -> ChangeClassification:
        """Classify a single file change."""
        if file_diff.diff_type == DiffType.ADDED:
            return self._classify_addition(file_diff, volume_guid)
        elif file_diff.diff_type == DiffType.REMOVED:
            return self._classify_removal(file_diff, volume_guid)
        elif file_diff.diff_type == DiffType.MODIFIED:
            return self._classify_modification(file_diff, volume_guid)
        elif file_diff.diff_type == DiffType.RELOCATED:
            return self._classify_relocation(file_diff, volume_guid)

        return ChangeClassification(
            file_diff=file_diff,
            volume_guid=volume_guid,
            category=ChangeCategory.BENIGN,
            severity=Severity.INFO,
            title=f'Unchanged file: {file_diff.guid}',
            description='No significant change detected.',
        )

    def _classify_addition(self, file_diff: FileDiff, volume_guid: str) -> ChangeClassification:
        """Classify an added firmware file."""
        indicators = []

        # Added DXE driver is the #1 bootkit injection vector
        if file_diff.is_driver:
            indicators.append('ADDED_DXE_DRIVER')

            if file_diff.guid.lower() in KNOWN_BOOTKIT_TARGET_GUIDS:
                indicators.append('KNOWN_BOOTKIT_GUID')

            # Check if this is a known legitimate update
            if file_diff.guid in self.known_update_hashes:
                if self.known_update_hashes[file_diff.guid] == file_diff.target_hash:
                    return ChangeClassification(
                        file_diff=file_diff,
                        volume_guid=volume_guid,
                        category=ChangeCategory.UPDATE,
                        severity=Severity.LOW,
                        title=f'Known update: added driver {file_diff.guid}',
                        description='This driver addition matches a known firmware update.',
                        indicators=indicators,
                        confidence=0.9,
                    )

            return ChangeClassification(
                file_diff=file_diff,
                volume_guid=volume_guid,
                category=ChangeCategory.MALICIOUS,
                severity=Severity.CRITICAL,
                title=f'Unknown DXE driver injected: {file_diff.guid}',
                description=(
                    f'A new DXE driver ({file_diff.target_size} bytes) was added to the firmware. '
                    f'DXE driver injection is the primary vector for UEFI bootkits.'
                ),
                indicators=indicators,
                confidence=0.85,
            )

        # Added application
        if file_diff.is_application:
            indicators.append('ADDED_APPLICATION')
            return ChangeClassification(
                file_diff=file_diff,
                volume_guid=volume_guid,
                category=ChangeCategory.SUSPICIOUS,
                severity=Severity.HIGH,
                title=f'Unknown EFI application added: {file_diff.guid}',
                description=(
                    f'A new EFI application ({file_diff.target_size} bytes) was added. '
                    f'May be a legitimate tool or a malicious boot application.'
                ),
                indicators=indicators,
                confidence=0.7,
            )

        # Added other file types
        if file_diff.guid.lower() in KNOWN_BENIGN_GUIDS:
            return ChangeClassification(
                file_diff=file_diff,
                volume_guid=volume_guid,
                category=ChangeCategory.CONFIGURATION,
                severity=Severity.INFO,
                title=f'Configuration data added: {file_diff.guid}',
                description='Added file matches a known configuration/NVRAM GUID.',
                indicators=['KNOWN_BENIGN_GUID'],
                confidence=0.9,
            )

        return ChangeClassification(
            file_diff=file_diff,
            volume_guid=volume_guid,
            category=ChangeCategory.SUSPICIOUS,
            severity=Severity.MEDIUM,
            title=f'Unknown firmware file added: {file_diff.guid}',
            description=f'A new {file_diff.file_type_name} file was added to the firmware.',
            indicators=indicators,
            confidence=0.6,
        )

    def _classify_removal(self, file_diff: FileDiff, volume_guid: str) -> ChangeClassification:
        """Classify a removed firmware file."""
        indicators = ['REMOVED_FILE']

        if file_diff.is_driver:
            indicators.append('REMOVED_DRIVER')
            return ChangeClassification(
                file_diff=file_diff,
                volume_guid=volume_guid,
                category=ChangeCategory.SUSPICIOUS,
                severity=Severity.HIGH,
                title=f'DXE driver removed: {file_diff.guid}',
                description=(
                    'A DXE driver was removed from the firmware. This could indicate '
                    'a security component was stripped (e.g., disabling Secure Boot enforcement).'
                ),
                indicators=indicators,
                confidence=0.7,
            )

        return ChangeClassification(
            file_diff=file_diff,
            volume_guid=volume_guid,
            category=ChangeCategory.SUSPICIOUS,
            severity=Severity.MEDIUM,
            title=f'Firmware file removed: {file_diff.guid}',
            description=f'A {file_diff.file_type_name} was removed from the firmware.',
            indicators=indicators,
            confidence=0.5,
        )

    def _classify_modification(self, file_diff: FileDiff, volume_guid: str) -> ChangeClassification:
        """Classify a modified firmware file."""
        indicators = ['MODIFIED_FILE']

        # Check known update
        if file_diff.guid in self.known_update_hashes:
            if self.known_update_hashes[file_diff.guid] == file_diff.target_hash:
                return ChangeClassification(
                    file_diff=file_diff,
                    volume_guid=volume_guid,
                    category=ChangeCategory.UPDATE,
                    severity=Severity.INFO,
                    title=f'Known update: modified {file_diff.guid}',
                    description='This modification matches a known firmware update.',
                    indicators=['KNOWN_UPDATE'],
                    confidence=0.95,
                )

        if file_diff.is_driver:
            indicators.append('MODIFIED_DRIVER')

            # Check if .text section was modified (code change)
            text_modified = any('section_modified(.text)' in s for s in file_diff.sections_changed)
            if text_modified:
                indicators.append('CODE_SECTION_MODIFIED')

                if file_diff.guid.lower() in KNOWN_BOOTKIT_TARGET_GUIDS:
                    indicators.append('KNOWN_BOOTKIT_TARGET')
                    return ChangeClassification(
                        file_diff=file_diff,
                        volume_guid=volume_guid,
                        category=ChangeCategory.MALICIOUS,
                        severity=Severity.CRITICAL,
                        title=f'Critical driver code patched: {file_diff.guid}',
                        description=(
                            'A driver commonly targeted by bootkits has its code section '
                            'modified. This is a strong indicator of firmware-level compromise.'
                        ),
                        indicators=indicators,
                        confidence=0.9,
                    )

                return ChangeClassification(
                    file_diff=file_diff,
                    volume_guid=volume_guid,
                    category=ChangeCategory.SUSPICIOUS,
                    severity=Severity.HIGH,
                    title=f'Driver code modified: {file_diff.guid}',
                    description=(
                        f'DXE driver code section was modified (size delta: {file_diff.size_delta} bytes). '
                        f'Verify against vendor firmware release.'
                    ),
                    indicators=indicators,
                    confidence=0.75,
                )

            # Non-code modification (data/reloc only)
            return ChangeClassification(
                file_diff=file_diff,
                volume_guid=volume_guid,
                category=ChangeCategory.SUSPICIOUS,
                severity=Severity.MEDIUM,
                title=f'Driver data modified: {file_diff.guid}',
                description=(
                    f'DXE driver was modified but code section unchanged. '
                    f'Sections: {", ".join(file_diff.sections_changed) or "unknown"}'
                ),
                indicators=indicators,
                confidence=0.6,
            )

        # Non-driver modification
        if file_diff.guid.lower() in KNOWN_BENIGN_GUIDS:
            return ChangeClassification(
                file_diff=file_diff,
                volume_guid=volume_guid,
                category=ChangeCategory.CONFIGURATION,
                severity=Severity.INFO,
                title=f'Configuration updated: {file_diff.guid}',
                description='Known configuration/NVRAM area was modified.',
                indicators=['KNOWN_BENIGN_GUID'],
                confidence=0.9,
            )

        return ChangeClassification(
            file_diff=file_diff,
            volume_guid=volume_guid,
            category=ChangeCategory.SUSPICIOUS,
            severity=Severity.MEDIUM,
            title=f'Firmware file modified: {file_diff.guid}',
            description=f'{file_diff.file_type_name} was modified (delta: {file_diff.size_delta} bytes).',
            indicators=indicators,
            confidence=0.5,
        )

    def _classify_relocation(self, file_diff: FileDiff, volume_guid: str) -> ChangeClassification:
        """Classify a relocated (same content, different offset) file."""
        return ChangeClassification(
            file_diff=file_diff,
            volume_guid=volume_guid,
            category=ChangeCategory.BENIGN,
            severity=Severity.INFO,
            title=f'File relocated: {file_diff.guid}',
            description=(
                f'File moved from offset 0x{file_diff.baseline_offset:x} to '
                f'0x{file_diff.target_offset:x} but content unchanged.'
            ),
            indicators=['RELOCATED'],
            confidence=0.95,
        )

    def get_threat_summary(self, classifications: List[ChangeClassification]) -> Dict:
        """Generate a threat summary from classifications."""
        summary = {
            'total_changes': len(classifications),
            'by_category': {},
            'by_severity': {},
            'threat_score': 0.0,
            'top_threats': [],
        }

        for cat in ChangeCategory:
            count = sum(1 for c in classifications if c.category == cat)
            if count > 0:
                summary['by_category'][cat.name] = count

        for sev in Severity:
            count = sum(1 for c in classifications if c.severity == sev)
            if count > 0:
                summary['by_severity'][sev.name] = count

        # Compute threat score (0-100)
        weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 5, Severity.LOW: 1}
        score = sum(weights.get(c.severity, 0) * c.confidence for c in classifications)
        summary['threat_score'] = min(100.0, score)

        # Top threats
        critical_and_high = [c for c in classifications if c.severity >= Severity.HIGH]
        summary['top_threats'] = [
            {'title': c.title, 'severity': c.severity.name, 'guid': c.file_diff.guid}
            for c in critical_and_high[:10]
        ]

        return summary

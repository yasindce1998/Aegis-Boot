"""
Firmware Volume Differ - Structural FV/FFS diff engine.

Compares two firmware images at the FV and FFS level, matching components
by GUID and detecting additions, removals, and modifications.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

try:
    from ..detectors.fv_parser import FirmwareVolumeParser, FirmwareVolume, FirmwareFile
except ImportError:
    from detectors.fv_parser import FirmwareVolumeParser, FirmwareVolume, FirmwareFile


class DiffType(IntEnum):
    """Type of difference detected between firmware images."""
    UNCHANGED = 0
    ADDED = 1
    REMOVED = 2
    MODIFIED = 3
    RELOCATED = 4


@dataclass
class FileDiff:
    """Represents a difference in a single firmware file."""
    guid: str
    diff_type: DiffType
    file_type: int
    file_type_name: str
    baseline_hash: Optional[str] = None
    target_hash: Optional[str] = None
    baseline_size: int = 0
    target_size: int = 0
    baseline_offset: int = 0
    target_offset: int = 0
    size_delta: int = 0
    sections_changed: List[str] = field(default_factory=list)

    @property
    def is_driver(self) -> bool:
        return self.file_type == 0x07

    @property
    def is_application(self) -> bool:
        return self.file_type == 0x09


@dataclass
class VolumeDiff:
    """Represents differences within a firmware volume."""
    guid: str
    baseline_offset: int
    target_offset: int
    baseline_size: int
    target_size: int
    file_diffs: List[FileDiff] = field(default_factory=list)
    added_count: int = 0
    removed_count: int = 0
    modified_count: int = 0

    @property
    def has_changes(self) -> bool:
        return self.added_count > 0 or self.removed_count > 0 or self.modified_count > 0


@dataclass
class DiffResult:
    """Complete diff result between two firmware images."""
    baseline_path: str
    target_path: str
    volume_diffs: List[VolumeDiff] = field(default_factory=list)
    unmatched_baseline_volumes: List[FirmwareVolume] = field(default_factory=list)
    unmatched_target_volumes: List[FirmwareVolume] = field(default_factory=list)
    total_added: int = 0
    total_removed: int = 0
    total_modified: int = 0
    total_unchanged: int = 0

    @property
    def has_changes(self) -> bool:
        return self.total_added > 0 or self.total_removed > 0 or self.total_modified > 0

    @property
    def total_files_compared(self) -> int:
        return self.total_added + self.total_removed + self.total_modified + self.total_unchanged


class FirmwareDiffer:
    """
    Structural firmware diff engine.

    Parses both images with FirmwareVolumeParser, matches FVs by GUID,
    then matches FFS files within each FV by GUID to produce a structural diff.
    """

    FILE_TYPES = FirmwareVolumeParser.FILE_TYPES

    def __init__(self):
        self.parser = FirmwareVolumeParser()

    def diff(self, baseline_path: str, target_path: str) -> DiffResult:
        """
        Compare two firmware images structurally.

        Args:
            baseline_path: Path to known-good firmware image
            target_path: Path to firmware image to check

        Returns:
            DiffResult with all structural differences
        """
        baseline_volumes = self.parser.parse(baseline_path)
        target_volumes = self.parser.parse(target_path)

        result = DiffResult(baseline_path=baseline_path, target_path=target_path)

        baseline_by_guid = {fv.guid: fv for fv in baseline_volumes}
        target_by_guid = {fv.guid: fv for fv in target_volumes}

        all_guids = set(baseline_by_guid.keys()) | set(target_by_guid.keys())

        for guid in sorted(all_guids):
            baseline_fv = baseline_by_guid.get(guid)
            target_fv = target_by_guid.get(guid)

            if baseline_fv and target_fv:
                vol_diff = self._diff_volumes(baseline_fv, target_fv)
                result.volume_diffs.append(vol_diff)
                result.total_added += vol_diff.added_count
                result.total_removed += vol_diff.removed_count
                result.total_modified += vol_diff.modified_count
                unchanged = len(vol_diff.file_diffs) - (
                    vol_diff.added_count + vol_diff.removed_count + vol_diff.modified_count)
                result.total_unchanged += max(0, unchanged)
            elif baseline_fv:
                result.unmatched_baseline_volumes.append(baseline_fv)
                result.total_removed += len(baseline_fv.files)
            else:
                result.unmatched_target_volumes.append(target_fv)
                result.total_added += len(target_fv.files)

        return result

    def _diff_volumes(self, baseline_fv: FirmwareVolume,
                      target_fv: FirmwareVolume) -> VolumeDiff:
        """Diff two matched firmware volumes."""
        vol_diff = VolumeDiff(
            guid=baseline_fv.guid,
            baseline_offset=baseline_fv.offset,
            target_offset=target_fv.offset,
            baseline_size=baseline_fv.size,
            target_size=target_fv.size,
        )

        baseline_files = {f.guid: f for f in baseline_fv.files}
        target_files = {f.guid: f for f in target_fv.files}

        all_file_guids = set(baseline_files.keys()) | set(target_files.keys())

        for guid in sorted(all_file_guids):
            bf = baseline_files.get(guid)
            tf = target_files.get(guid)

            if bf and tf:
                file_diff = self._diff_files(bf, tf)
                vol_diff.file_diffs.append(file_diff)
                if file_diff.diff_type == DiffType.MODIFIED:
                    vol_diff.modified_count += 1
                elif file_diff.diff_type == DiffType.RELOCATED:
                    vol_diff.modified_count += 1
            elif bf:
                vol_diff.file_diffs.append(FileDiff(
                    guid=guid,
                    diff_type=DiffType.REMOVED,
                    file_type=bf.type,
                    file_type_name=self.FILE_TYPES.get(bf.type, f'UNKNOWN(0x{bf.type:02x})'),
                    baseline_hash=bf.hash,
                    baseline_size=bf.size,
                    baseline_offset=bf.offset,
                ))
                vol_diff.removed_count += 1
            else:
                vol_diff.file_diffs.append(FileDiff(
                    guid=guid,
                    diff_type=DiffType.ADDED,
                    file_type=tf.type,
                    file_type_name=self.FILE_TYPES.get(tf.type, f'UNKNOWN(0x{tf.type:02x})'),
                    target_hash=tf.hash,
                    target_size=tf.size,
                    target_offset=tf.offset,
                ))
                vol_diff.added_count += 1

        return vol_diff

    def _diff_files(self, baseline: FirmwareFile, target: FirmwareFile) -> FileDiff:
        """Compare two matched firmware files."""
        file_type_name = self.FILE_TYPES.get(baseline.type, f'UNKNOWN(0x{baseline.type:02x})')

        if baseline.hash == target.hash:
            diff_type = DiffType.UNCHANGED
            if baseline.offset != target.offset:
                diff_type = DiffType.RELOCATED
        else:
            diff_type = DiffType.MODIFIED

        sections_changed = []
        if diff_type == DiffType.MODIFIED:
            sections_changed = self._identify_changed_sections(baseline, target)

        return FileDiff(
            guid=baseline.guid,
            diff_type=diff_type,
            file_type=baseline.type,
            file_type_name=file_type_name,
            baseline_hash=baseline.hash,
            target_hash=target.hash,
            baseline_size=baseline.size,
            target_size=target.size,
            baseline_offset=baseline.offset,
            target_offset=target.offset,
            size_delta=target.size - baseline.size,
            sections_changed=sections_changed,
        )

    def _identify_changed_sections(self, baseline: FirmwareFile,
                                    target: FirmwareFile) -> List[str]:
        """Identify which PE sections changed between two file versions."""
        changes = []

        if baseline.size != target.size:
            changes.append(f'size_changed({baseline.size}->{target.size})')

        if baseline.type != target.type:
            changes.append(f'type_changed({baseline.type}->{target.type})')

        if baseline.attributes != target.attributes:
            changes.append(f'attributes_changed(0x{baseline.attributes:02x}->0x{target.attributes:02x})')

        pe_sections_b = self._extract_pe_sections(baseline.data)
        pe_sections_t = self._extract_pe_sections(target.data)

        if pe_sections_b or pe_sections_t:
            all_sections = set(pe_sections_b.keys()) | set(pe_sections_t.keys())
            for section_name in sorted(all_sections):
                hash_b = pe_sections_b.get(section_name)
                hash_t = pe_sections_t.get(section_name)
                if hash_b != hash_t:
                    if hash_b is None:
                        changes.append(f'section_added({section_name})')
                    elif hash_t is None:
                        changes.append(f'section_removed({section_name})')
                    else:
                        changes.append(f'section_modified({section_name})')

        return changes

    def _extract_pe_sections(self, data: bytes) -> Dict[str, str]:
        """Extract PE/COFF section names and hashes from file data."""
        import hashlib
        sections = {}

        # Look for PE signature in file data (skip FFS header ~24 bytes)
        pe_offset = None
        for search_offset in range(0, min(len(data), 1024)):
            if data[search_offset:search_offset + 2] == b'MZ':
                if search_offset + 0x3C + 4 <= len(data):
                    import struct
                    pe_ptr = struct.unpack_from('<I', data, search_offset + 0x3C)[0]
                    actual_pe = search_offset + pe_ptr
                    if actual_pe + 4 <= len(data) and data[actual_pe:actual_pe + 4] == b'PE\x00\x00':
                        pe_offset = actual_pe
                        break

        if pe_offset is None:
            return sections

        import struct
        try:
            # COFF header starts at PE+4
            coff_offset = pe_offset + 4
            num_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
            optional_header_size = struct.unpack_from('<H', data, coff_offset + 16)[0]

            # Section headers start after optional header
            section_table_offset = coff_offset + 20 + optional_header_size

            for i in range(min(num_sections, 64)):
                sec_offset = section_table_offset + (i * 40)
                if sec_offset + 40 > len(data):
                    break

                name_raw = data[sec_offset:sec_offset + 8]
                name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')

                raw_size = struct.unpack_from('<I', data, sec_offset + 16)[0]
                raw_ptr = struct.unpack_from('<I', data, sec_offset + 20)[0]

                # Compute hash of section content
                sec_data_start = search_offset + raw_ptr if raw_ptr else 0
                sec_data_end = sec_data_start + raw_size
                if sec_data_start < len(data) and raw_size > 0:
                    sec_data = data[sec_data_start:min(sec_data_end, len(data))]
                    sections[name] = hashlib.sha256(sec_data).hexdigest()
        except (struct.error, IndexError):
            pass

        return sections

    def diff_from_volumes(self, baseline_volumes: List[FirmwareVolume],
                          target_volumes: List[FirmwareVolume],
                          baseline_path: str = '<memory>',
                          target_path: str = '<memory>') -> DiffResult:
        """
        Diff pre-parsed firmware volumes (useful when volumes are already loaded).

        Args:
            baseline_volumes: Pre-parsed baseline FVs
            target_volumes: Pre-parsed target FVs
            baseline_path: Label for baseline
            target_path: Label for target

        Returns:
            DiffResult
        """
        result = DiffResult(baseline_path=baseline_path, target_path=target_path)

        baseline_by_guid = {fv.guid: fv for fv in baseline_volumes}
        target_by_guid = {fv.guid: fv for fv in target_volumes}

        all_guids = set(baseline_by_guid.keys()) | set(target_by_guid.keys())

        for guid in sorted(all_guids):
            baseline_fv = baseline_by_guid.get(guid)
            target_fv = target_by_guid.get(guid)

            if baseline_fv and target_fv:
                vol_diff = self._diff_volumes(baseline_fv, target_fv)
                result.volume_diffs.append(vol_diff)
                result.total_added += vol_diff.added_count
                result.total_removed += vol_diff.removed_count
                result.total_modified += vol_diff.modified_count
            elif baseline_fv:
                result.unmatched_baseline_volumes.append(baseline_fv)
                result.total_removed += len(baseline_fv.files)
            else:
                result.unmatched_target_volumes.append(target_fv)
                result.total_added += len(target_fv.files)

        return result

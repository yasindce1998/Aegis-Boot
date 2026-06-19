"""
Unit tests for the Differential Firmware Diffing engine.

Tests FirmwareDiffer, SemanticAnalyzer, DiffReportGenerator, and BaselineDB.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from AegisScanner.differ.fv_differ import (
    FirmwareDiffer, DiffResult, DiffType, FileDiff, VolumeDiff
)
from AegisScanner.differ.semantic_diff import (
    SemanticAnalyzer, ChangeCategory, Severity, ChangeClassification,
    KNOWN_BOOTKIT_TARGET_GUIDS, KNOWN_BENIGN_GUIDS
)
from AegisScanner.differ.diff_report import DiffReportGenerator
from AegisScanner.differ.baseline_db import BaselineDB
from AegisScanner.detectors.fv_parser import FirmwareVolume, FirmwareFile


# ============================================================================
# Test Helpers
# ============================================================================

def _make_guid(n: int) -> str:
    """Generate a deterministic GUID from an integer."""
    return f'{n:08x}-0000-0000-0000-000000000000'


def _make_firmware_file(guid: str, file_type: int = 0x07,
                        data: bytes = b'\x00' * 64,
                        offset: int = 0) -> FirmwareFile:
    """Create a FirmwareFile with computed hash."""
    return FirmwareFile(
        guid=guid,
        type=file_type,
        attributes=0x00,
        size=len(data),
        offset=offset,
        hash=hashlib.sha256(data).hexdigest(),
        data=data,
    )


def _make_fv_header() -> bytes:
    """Create a minimal _FVH signature block."""
    # Simplified: just enough to be found by the parser
    header = bytearray(64)
    header[0:16] = b'\x00' * 16  # zero vector
    header[16:20] = b'_FVH'  # FV signature at offset 40... actually
    return bytes(header)


def _build_firmware_image(volumes: list) -> bytes:
    """
    Build a minimal firmware image with FV headers and FFS entries.

    Each volume is a dict: {'guid': str, 'files': [{'guid': str, 'type': int, 'data': bytes}]}
    """
    image = bytearray()

    for vol in volumes:
        vol_start = len(image)

        # FV header (simplified - 72 bytes minimum)
        fv_header = bytearray(72)
        # Zero vector (16 bytes)
        fv_header[0:16] = b'\x00' * 16
        # GUID (16 bytes at offset 16) - use vol guid
        parts = vol['guid'].split('-')
        guid_bytes = struct.pack('<IHH', int(parts[0], 16), int(parts[1], 16), int(parts[2], 16))
        guid_bytes += bytes.fromhex(parts[3]) + bytes.fromhex(parts[4])
        fv_header[16:32] = guid_bytes
        # FV length (8 bytes at offset 32) - placeholder, fill later
        # Signature '_FVH' at offset 40
        fv_header[40:44] = b'_FVH'
        # Attributes (4 bytes at offset 44)
        struct.pack_into('<I', fv_header, 44, 0x0004FEFF)
        # Header length (2 bytes at offset 48)
        struct.pack_into('<H', fv_header, 48, 72)
        # Revision (1 byte at offset 55)
        fv_header[55] = 0x02

        image.extend(fv_header)

        # FFS files
        for f in vol.get('files', []):
            file_data = f.get('data', b'\x90' * 32)
            # FFS file header (24 bytes)
            ffs_header = bytearray(24)
            # File GUID (16 bytes)
            fparts = f['guid'].split('-')
            fguid = struct.pack('<IHH', int(fparts[0], 16), int(fparts[1], 16), int(fparts[2], 16))
            fguid += bytes.fromhex(fparts[3]) + bytes.fromhex(fparts[4])
            ffs_header[0:16] = fguid
            # Integrity check (2 bytes at offset 16)
            ffs_header[16] = 0xAA
            ffs_header[17] = 0x55
            # File type (1 byte at offset 18)
            ffs_header[18] = f.get('type', 0x07)
            # Attributes (1 byte at offset 19)
            ffs_header[19] = 0x00
            # Size (3 bytes at offset 20, little-endian 24-bit)
            total_size = 24 + len(file_data)
            ffs_header[20] = total_size & 0xFF
            ffs_header[21] = (total_size >> 8) & 0xFF
            ffs_header[22] = (total_size >> 16) & 0xFF
            # State (1 byte at offset 23)
            ffs_header[23] = 0xF8

            image.extend(ffs_header)
            image.extend(file_data)

            # 8-byte align
            padding = (8 - (len(image) % 8)) % 8
            image.extend(b'\xFF' * padding)

        # Update FV length
        vol_size = len(image) - vol_start
        struct.pack_into('<Q', image, vol_start + 32, vol_size)

    return bytes(image)


# ============================================================================
# FirmwareDiffer Tests
# ============================================================================

class TestDiffType(unittest.TestCase):
    """Test DiffType enum values."""

    def test_enum_values(self):
        self.assertEqual(DiffType.UNCHANGED, 0)
        self.assertEqual(DiffType.ADDED, 1)
        self.assertEqual(DiffType.REMOVED, 2)
        self.assertEqual(DiffType.MODIFIED, 3)
        self.assertEqual(DiffType.RELOCATED, 4)


class TestFileDiff(unittest.TestCase):
    """Test FileDiff dataclass."""

    def test_is_driver(self):
        fd = FileDiff(guid='test', diff_type=DiffType.ADDED, file_type=0x07,
                      file_type_name='DRIVER')
        self.assertTrue(fd.is_driver)

    def test_is_not_driver(self):
        fd = FileDiff(guid='test', diff_type=DiffType.ADDED, file_type=0x09,
                      file_type_name='APPLICATION')
        self.assertFalse(fd.is_driver)

    def test_is_application(self):
        fd = FileDiff(guid='test', diff_type=DiffType.ADDED, file_type=0x09,
                      file_type_name='APPLICATION')
        self.assertTrue(fd.is_application)

    def test_size_delta(self):
        fd = FileDiff(guid='test', diff_type=DiffType.MODIFIED, file_type=0x07,
                      file_type_name='DRIVER', baseline_size=100, target_size=150,
                      size_delta=50)
        self.assertEqual(fd.size_delta, 50)


class TestVolumeDiff(unittest.TestCase):
    """Test VolumeDiff dataclass."""

    def test_has_changes_true(self):
        vd = VolumeDiff(guid='test', baseline_offset=0, target_offset=0,
                        baseline_size=1000, target_size=1000, added_count=1)
        self.assertTrue(vd.has_changes)

    def test_has_changes_false(self):
        vd = VolumeDiff(guid='test', baseline_offset=0, target_offset=0,
                        baseline_size=1000, target_size=1000)
        self.assertFalse(vd.has_changes)


class TestDiffResult(unittest.TestCase):
    """Test DiffResult dataclass."""

    def test_has_changes(self):
        r = DiffResult(baseline_path='a', target_path='b', total_added=1)
        self.assertTrue(r.has_changes)

    def test_no_changes(self):
        r = DiffResult(baseline_path='a', target_path='b')
        self.assertFalse(r.has_changes)

    def test_total_files_compared(self):
        r = DiffResult(baseline_path='a', target_path='b',
                       total_added=2, total_removed=1, total_modified=3,
                       total_unchanged=10)
        self.assertEqual(r.total_files_compared, 16)


class TestFirmwareDiffer(unittest.TestCase):
    """Test FirmwareDiffer structural diff engine."""

    def setUp(self):
        self.differ = FirmwareDiffer()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_image(self, name: str, volumes: list) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, 'wb') as f:
            f.write(_build_firmware_image(volumes))
        return path

    def test_identical_images(self):
        """Identical images should show no changes."""
        vol_guid = _make_guid(1)
        file_guid = _make_guid(10)
        volumes = [{'guid': vol_guid, 'files': [
            {'guid': file_guid, 'type': 0x07, 'data': b'\x90' * 32}
        ]}]
        baseline = self._write_image('baseline.rom', volumes)
        target = self._write_image('target.rom', volumes)

        result = self.differ.diff(baseline, target)
        self.assertFalse(result.has_changes)

    def test_added_file_detected(self):
        """File present only in target should be ADDED."""
        vol_guid = _make_guid(1)
        file_guid_a = _make_guid(10)
        file_guid_b = _make_guid(11)

        baseline_volumes = [{'guid': vol_guid, 'files': [
            {'guid': file_guid_a, 'type': 0x07, 'data': b'\x90' * 32}
        ]}]
        target_volumes = [{'guid': vol_guid, 'files': [
            {'guid': file_guid_a, 'type': 0x07, 'data': b'\x90' * 32},
            {'guid': file_guid_b, 'type': 0x07, 'data': b'\xCC' * 64}
        ]}]

        baseline = self._write_image('baseline.rom', baseline_volumes)
        target = self._write_image('target.rom', target_volumes)

        result = self.differ.diff(baseline, target)
        self.assertTrue(result.has_changes)
        self.assertEqual(result.total_added, 1)

    def test_removed_file_detected(self):
        """File present only in baseline should be REMOVED."""
        vol_guid = _make_guid(1)
        file_guid_a = _make_guid(10)
        file_guid_b = _make_guid(11)

        baseline_volumes = [{'guid': vol_guid, 'files': [
            {'guid': file_guid_a, 'type': 0x07, 'data': b'\x90' * 32},
            {'guid': file_guid_b, 'type': 0x07, 'data': b'\xCC' * 64}
        ]}]
        target_volumes = [{'guid': vol_guid, 'files': [
            {'guid': file_guid_a, 'type': 0x07, 'data': b'\x90' * 32}
        ]}]

        baseline = self._write_image('baseline.rom', baseline_volumes)
        target = self._write_image('target.rom', target_volumes)

        result = self.differ.diff(baseline, target)
        self.assertTrue(result.has_changes)
        self.assertEqual(result.total_removed, 1)

    def test_modified_file_detected(self):
        """File with different content should be MODIFIED."""
        vol_guid = _make_guid(1)
        file_guid = _make_guid(10)

        baseline_volumes = [{'guid': vol_guid, 'files': [
            {'guid': file_guid, 'type': 0x07, 'data': b'\x90' * 32}
        ]}]
        target_volumes = [{'guid': vol_guid, 'files': [
            {'guid': file_guid, 'type': 0x07, 'data': b'\xCC' * 32}
        ]}]

        baseline = self._write_image('baseline.rom', baseline_volumes)
        target = self._write_image('target.rom', target_volumes)

        result = self.differ.diff(baseline, target)
        self.assertTrue(result.has_changes)
        self.assertEqual(result.total_modified, 1)

    def test_diff_from_volumes(self):
        """Test diffing pre-parsed volume objects."""
        guid = _make_guid(1)
        file_a = _make_firmware_file(_make_guid(10), data=b'\x90' * 32)
        file_b = _make_firmware_file(_make_guid(11), data=b'\xCC' * 64)

        baseline_vols = [FirmwareVolume(guid=guid, size=1000, offset=0,
                                        attributes=0, files=[file_a])]
        target_vols = [FirmwareVolume(guid=guid, size=1000, offset=0,
                                      attributes=0, files=[file_a, file_b])]

        result = self.differ.diff_from_volumes(baseline_vols, target_vols)
        self.assertTrue(result.has_changes)
        self.assertEqual(result.total_added, 1)

    def test_unmatched_volume_in_target(self):
        """Entirely new volume in target."""
        vol_a = _make_guid(1)
        vol_b = _make_guid(2)
        file_a = _make_firmware_file(_make_guid(10))
        file_b = _make_firmware_file(_make_guid(11))

        baseline_vols = [FirmwareVolume(guid=vol_a, size=1000, offset=0,
                                        attributes=0, files=[file_a])]
        target_vols = [
            FirmwareVolume(guid=vol_a, size=1000, offset=0, attributes=0, files=[file_a]),
            FirmwareVolume(guid=vol_b, size=500, offset=1000, attributes=0, files=[file_b]),
        ]

        result = self.differ.diff_from_volumes(baseline_vols, target_vols)
        self.assertEqual(len(result.unmatched_target_volumes), 1)
        self.assertEqual(result.total_added, 1)


# ============================================================================
# SemanticAnalyzer Tests
# ============================================================================

class TestSemanticAnalyzer(unittest.TestCase):
    """Test semantic classification of firmware changes."""

    def setUp(self):
        self.analyzer = SemanticAnalyzer()

    def test_added_driver_is_critical(self):
        """An added DXE driver should be classified CRITICAL."""
        file_diff = FileDiff(
            guid=_make_guid(99),
            diff_type=DiffType.ADDED,
            file_type=0x07,
            file_type_name='DRIVER',
            target_hash='abc123',
            target_size=4096,
            target_offset=0x1000,
        )
        vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0,
            baseline_size=10000, target_size=14000,
            file_diffs=[file_diff], added_count=1,
        )
        diff_result = DiffResult(
            baseline_path='clean.rom', target_path='infected.rom',
            volume_diffs=[vol_diff], total_added=1,
        )

        classifications = self.analyzer.analyze(diff_result)
        self.assertEqual(len(classifications), 1)
        self.assertEqual(classifications[0].severity, Severity.CRITICAL)
        self.assertEqual(classifications[0].category, ChangeCategory.MALICIOUS)

    def test_added_application_is_high(self):
        """An added EFI application should be HIGH severity."""
        file_diff = FileDiff(
            guid=_make_guid(99),
            diff_type=DiffType.ADDED,
            file_type=0x09,
            file_type_name='APPLICATION',
            target_hash='xyz789',
            target_size=2048,
            target_offset=0x2000,
        )
        vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0,
            baseline_size=10000, target_size=12000,
            file_diffs=[file_diff], added_count=1,
        )
        diff_result = DiffResult(
            baseline_path='clean.rom', target_path='modified.rom',
            volume_diffs=[vol_diff], total_added=1,
        )

        classifications = self.analyzer.analyze(diff_result)
        self.assertEqual(classifications[0].severity, Severity.HIGH)
        self.assertEqual(classifications[0].category, ChangeCategory.SUSPICIOUS)

    def test_removed_driver_is_high(self):
        """A removed DXE driver should be HIGH severity."""
        file_diff = FileDiff(
            guid=_make_guid(50),
            diff_type=DiffType.REMOVED,
            file_type=0x07,
            file_type_name='DRIVER',
            baseline_hash='old123',
            baseline_size=4096,
            baseline_offset=0x1000,
        )
        vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0,
            baseline_size=14000, target_size=10000,
            file_diffs=[file_diff], removed_count=1,
        )
        diff_result = DiffResult(
            baseline_path='clean.rom', target_path='stripped.rom',
            volume_diffs=[vol_diff], total_removed=1,
        )

        classifications = self.analyzer.analyze(diff_result)
        self.assertEqual(classifications[0].severity, Severity.HIGH)

    def test_modified_bootkit_target_is_critical(self):
        """Modified driver with .text change targeting known bootkit GUID -> CRITICAL."""
        bootkit_guid = list(KNOWN_BOOTKIT_TARGET_GUIDS)[0]
        file_diff = FileDiff(
            guid=bootkit_guid,
            diff_type=DiffType.MODIFIED,
            file_type=0x07,
            file_type_name='DRIVER',
            baseline_hash='aaa',
            target_hash='bbb',
            baseline_size=8192,
            target_size=8200,
            size_delta=8,
            sections_changed=['section_modified(.text)'],
        )
        vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0,
            baseline_size=50000, target_size=50000,
            file_diffs=[file_diff], modified_count=1,
        )
        diff_result = DiffResult(
            baseline_path='clean.rom', target_path='patched.rom',
            volume_diffs=[vol_diff], total_modified=1,
        )

        classifications = self.analyzer.analyze(diff_result)
        self.assertEqual(classifications[0].severity, Severity.CRITICAL)
        self.assertEqual(classifications[0].category, ChangeCategory.MALICIOUS)
        self.assertIn('KNOWN_BOOTKIT_TARGET', classifications[0].indicators)

    def test_benign_guid_modification_is_info(self):
        """Known benign GUID modification should be INFO."""
        benign_guid = list(KNOWN_BENIGN_GUIDS)[0]
        file_diff = FileDiff(
            guid=benign_guid,
            diff_type=DiffType.MODIFIED,
            file_type=0x01,
            file_type_name='RAW',
            baseline_hash='old',
            target_hash='new',
            baseline_size=4096,
            target_size=4096,
            size_delta=0,
        )
        vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0,
            baseline_size=50000, target_size=50000,
            file_diffs=[file_diff], modified_count=1,
        )
        diff_result = DiffResult(
            baseline_path='a', target_path='b',
            volume_diffs=[vol_diff], total_modified=1,
        )

        classifications = self.analyzer.analyze(diff_result)
        self.assertEqual(classifications[0].severity, Severity.INFO)
        self.assertEqual(classifications[0].category, ChangeCategory.CONFIGURATION)

    def test_known_update_hash_reduces_severity(self):
        """Known update hash should classify as UPDATE with low severity."""
        guid = _make_guid(77)
        analyzer = SemanticAnalyzer(known_update_hashes={guid: 'expected_hash'})

        file_diff = FileDiff(
            guid=guid,
            diff_type=DiffType.ADDED,
            file_type=0x07,
            file_type_name='DRIVER',
            target_hash='expected_hash',
            target_size=4096,
            target_offset=0x1000,
        )
        vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0,
            baseline_size=10000, target_size=14000,
            file_diffs=[file_diff], added_count=1,
        )
        diff_result = DiffResult(
            baseline_path='a', target_path='b',
            volume_diffs=[vol_diff], total_added=1,
        )

        classifications = analyzer.analyze(diff_result)
        self.assertEqual(classifications[0].severity, Severity.LOW)
        self.assertEqual(classifications[0].category, ChangeCategory.UPDATE)

    def test_relocated_file_is_info(self):
        """Relocated file (same hash, different offset) should be INFO."""
        file_diff = FileDiff(
            guid=_make_guid(30),
            diff_type=DiffType.RELOCATED,
            file_type=0x07,
            file_type_name='DRIVER',
            baseline_hash='same_hash',
            target_hash='same_hash',
            baseline_size=4096,
            target_size=4096,
            baseline_offset=0x1000,
            target_offset=0x2000,
        )
        vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0,
            baseline_size=50000, target_size=50000,
            file_diffs=[file_diff], modified_count=1,
        )
        diff_result = DiffResult(
            baseline_path='a', target_path='b',
            volume_diffs=[vol_diff], total_modified=1,
        )

        classifications = self.analyzer.analyze(diff_result)
        self.assertEqual(classifications[0].severity, Severity.INFO)
        self.assertEqual(classifications[0].category, ChangeCategory.BENIGN)

    def test_threat_summary(self):
        """Threat summary should aggregate scores correctly."""
        classifications = [
            ChangeClassification(
                file_diff=FileDiff(guid='a', diff_type=DiffType.ADDED,
                                   file_type=0x07, file_type_name='DRIVER'),
                volume_guid='vol1',
                category=ChangeCategory.MALICIOUS,
                severity=Severity.CRITICAL,
                title='Injected driver',
                description='Bad',
                confidence=0.9,
            ),
            ChangeClassification(
                file_diff=FileDiff(guid='b', diff_type=DiffType.MODIFIED,
                                   file_type=0x07, file_type_name='DRIVER'),
                volume_guid='vol1',
                category=ChangeCategory.SUSPICIOUS,
                severity=Severity.MEDIUM,
                title='Modified driver',
                description='Maybe bad',
                confidence=0.6,
            ),
        ]

        summary = self.analyzer.get_threat_summary(classifications)
        self.assertEqual(summary['total_changes'], 2)
        self.assertGreater(summary['threat_score'], 0)
        self.assertEqual(len(summary['top_threats']), 1)  # Only CRITICAL/HIGH


# ============================================================================
# DiffReportGenerator Tests
# ============================================================================

class TestDiffReportGenerator(unittest.TestCase):
    """Test diff report generation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.file_diff = FileDiff(
            guid=_make_guid(99),
            diff_type=DiffType.ADDED,
            file_type=0x07,
            file_type_name='DRIVER',
            target_hash='abc',
            target_size=4096,
            target_offset=0x1000,
        )
        self.vol_diff = VolumeDiff(
            guid=_make_guid(1), baseline_offset=0, target_offset=0x100,
            baseline_size=10000, target_size=14000,
            file_diffs=[self.file_diff], added_count=1,
        )
        self.diff_result = DiffResult(
            baseline_path='clean.rom', target_path='infected.rom',
            volume_diffs=[self.vol_diff], total_added=1,
        )
        self.classification = ChangeClassification(
            file_diff=self.file_diff,
            volume_guid=_make_guid(1),
            category=ChangeCategory.MALICIOUS,
            severity=Severity.CRITICAL,
            title='Injected DXE driver',
            description='A malicious driver was injected.',
            indicators=['ADDED_DXE_DRIVER'],
            confidence=0.85,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generate_json(self):
        gen = DiffReportGenerator(self.diff_result, [self.classification])
        output = os.path.join(self.tmpdir, 'report.json')
        gen.generate_json(output)

        with open(output) as f:
            report = json.load(f)

        self.assertEqual(report['summary']['added'], 1)
        self.assertEqual(len(report['classifications']), 1)
        self.assertEqual(report['classifications'][0]['severity'], 'CRITICAL')

    def test_generate_markdown(self):
        gen = DiffReportGenerator(self.diff_result, [self.classification])
        output = os.path.join(self.tmpdir, 'report.md')
        gen.generate_markdown(output)

        with open(output, encoding='utf-8') as f:
            md = f.read()

        self.assertIn('# Firmware Diff Report', md)
        self.assertIn('Injected DXE driver', md)
        self.assertIn('CRITICAL', md)

    def test_to_dict(self):
        gen = DiffReportGenerator(self.diff_result, [self.classification])
        report = gen.to_dict()

        self.assertIn('summary', report)
        self.assertIn('volumes', report)
        self.assertIn('classifications', report)

    def test_get_scanner_findings(self):
        gen = DiffReportGenerator(self.diff_result, [self.classification])
        findings = gen.get_scanner_findings()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['detector'], 'firmware_differ')
        self.assertEqual(findings[0]['severity'], 'critical')

    def test_scanner_findings_filters_low_severity(self):
        """Only MEDIUM+ severity should be returned as scanner findings."""
        low_classification = ChangeClassification(
            file_diff=self.file_diff,
            volume_guid=_make_guid(1),
            category=ChangeCategory.BENIGN,
            severity=Severity.LOW,
            title='Minor change',
            description='Low severity.',
        )
        gen = DiffReportGenerator(self.diff_result, [low_classification])
        findings = gen.get_scanner_findings()
        self.assertEqual(len(findings), 0)


# ============================================================================
# BaselineDB Tests
# ============================================================================

class TestBaselineDB(unittest.TestCase):
    """Test SQLite baseline database."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test.db')
        self.db = BaselineDB(self.db_path)

        # Create a test firmware image
        self.fw_path = os.path.join(self.tmpdir, 'test_fw.rom')
        volumes = [{'guid': _make_guid(1), 'files': [
            {'guid': _make_guid(10), 'type': 0x07, 'data': b'\x90' * 32},
            {'guid': _make_guid(11), 'type': 0x09, 'data': b'\xCC' * 64},
        ]}]
        with open(self.fw_path, 'wb') as f:
            f.write(_build_firmware_image(volumes))

    def tearDown(self):
        self.db.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_register_baseline(self):
        baseline_id = self.db.register_baseline('test-v1', self.fw_path,
                                                 description='Test baseline',
                                                 vendor='TestVendor')
        self.assertIsNotNone(baseline_id)
        self.assertGreater(baseline_id, 0)

    def test_duplicate_name_raises(self):
        self.db.register_baseline('test-v1', self.fw_path)
        with self.assertRaises(ValueError):
            self.db.register_baseline('test-v1', self.fw_path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.db.register_baseline('bad', '/nonexistent/firmware.rom')

    def test_get_baseline(self):
        self.db.register_baseline('test-v1', self.fw_path, vendor='ACME')
        info = self.db.get_baseline('test-v1')
        self.assertIsNotNone(info)
        self.assertEqual(info['name'], 'test-v1')
        self.assertEqual(info['vendor'], 'ACME')

    def test_get_nonexistent_baseline(self):
        info = self.db.get_baseline('does-not-exist')
        self.assertIsNone(info)

    def test_list_baselines(self):
        self.db.register_baseline('v1', self.fw_path)
        self.db.register_baseline('v2', self.fw_path.replace('test_fw', 'test_fw'),
                                   description='Second version')
        # Workaround: use unique name but same file
        baselines = self.db.list_baselines()
        self.assertEqual(len(baselines), 2)

    def test_get_baseline_volumes(self):
        self.db.register_baseline('test-v1', self.fw_path)
        volumes = self.db.get_baseline_volumes('test-v1')
        self.assertIsInstance(volumes, list)

    def test_delete_baseline(self):
        self.db.register_baseline('test-v1', self.fw_path)
        self.assertTrue(self.db.delete_baseline('test-v1'))
        self.assertIsNone(self.db.get_baseline('test-v1'))

    def test_delete_nonexistent(self):
        self.assertFalse(self.db.delete_baseline('nope'))

    def test_context_manager(self):
        with BaselineDB(os.path.join(self.tmpdir, 'ctx.db')) as db:
            db.register_baseline('ctx-test', self.fw_path)
            info = db.get_baseline('ctx-test')
            self.assertIsNotNone(info)


# ============================================================================
# Integration: FirmwareDifferDetector wrapper
# ============================================================================

class TestFirmwareDifferDetector(unittest.TestCase):
    """Test the scanner-integrated FirmwareDifferDetector."""

    def test_no_baseline_returns_info(self):
        from AegisScanner.scanner import FirmwareDifferDetector
        detector = FirmwareDifferDetector(baseline_firmware=None)
        results = detector.detect('any_path.rom')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['severity'], 'info')

    def test_with_baseline_detects_changes(self):
        from AegisScanner.scanner import FirmwareDifferDetector
        tmpdir = tempfile.mkdtemp()
        try:
            vol_guid = _make_guid(1)
            file_guid = _make_guid(10)
            injected_guid = _make_guid(99)

            baseline_volumes = [{'guid': vol_guid, 'files': [
                {'guid': file_guid, 'type': 0x07, 'data': b'\x90' * 32}
            ]}]
            target_volumes = [{'guid': vol_guid, 'files': [
                {'guid': file_guid, 'type': 0x07, 'data': b'\x90' * 32},
                {'guid': injected_guid, 'type': 0x07, 'data': b'\xCC' * 128}
            ]}]

            baseline_path = os.path.join(tmpdir, 'baseline.rom')
            target_path = os.path.join(tmpdir, 'target.rom')
            with open(baseline_path, 'wb') as f:
                f.write(_build_firmware_image(baseline_volumes))
            with open(target_path, 'wb') as f:
                f.write(_build_firmware_image(target_volumes))

            detector = FirmwareDifferDetector(baseline_firmware=baseline_path)
            results = detector.detect(target_path)
            self.assertGreater(len(results), 0)
            self.assertEqual(results[0]['severity'], 'critical')
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()

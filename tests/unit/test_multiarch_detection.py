"""
Unit Tests for Multi-Architecture Bootkit Detection

Tests ARM64/RISC-V trampoline detection in hook_detector_v2.py
and MBR/VBR detection in mbr_detector.py.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import unittest
import struct
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from BarzakhScanner.detectors.hook_detector_v2 import HookDetectorV2
from BarzakhScanner.detectors.mbr_detector import MBRDetector


class TestARM64TrampolineDetection(unittest.TestCase):
    """Test ARM64 trampoline pattern detection via internal method."""

    def setUp(self):
        self.detector = HookDetectorV2()

    def test_ldr_x16_br_x16_detection(self):
        """Detect LDR X16, [PC+8]; BR X16; <addr> trampoline."""
        trampoline = (
            b'\x50\x00\x00\x58'  # LDR X16, [PC+8]
            b'\x00\x02\x1F\xD6'  # BR X16
            b'\xBE\xBA\xFE\xCA\xEF\xBE\xAD\xDE'  # 64-bit target
        )
        data = b'\x00' * 0x100 + trampoline + b'\x00' * 0x100

        results = self.detector._detect_trampoline_patterns(data, 0x100)
        self.assertTrue(len(results) > 0, "Expected ARM64 LDR X16+BR X16 trampoline")
        self.assertEqual(results[0].pattern_type, 'aarch64_ldr_x16_br')
        self.assertAlmostEqual(results[0].confidence, 0.95)
        self.assertEqual(results[0].target, 0xDEADBEEFCAFEBABE)

    def test_ldr_x17_br_x17_detection(self):
        """Detect LDR X17, [PC+8]; BR X17; <addr> trampoline."""
        trampoline = (
            b'\x51\x00\x00\x58'  # LDR X17, [PC+8]
            b'\x20\x02\x1F\xD6'  # BR X17
            b'\x41\x41\x41\x41\x42\x42\x42\x42'  # target addr
        )
        data = b'\x00' * 0x100 + trampoline + b'\x00' * 0x100

        results = self.detector._detect_trampoline_patterns(data, 0x100)
        self.assertTrue(len(results) > 0, "Expected ARM64 LDR X17+BR X17 trampoline")
        self.assertEqual(results[0].pattern_type, 'aarch64_ldr_x17_br')
        self.assertAlmostEqual(results[0].confidence, 0.90)

    def test_no_false_positive_on_random_arm64(self):
        """No detection on random non-trampoline ARM64 instructions."""
        data = b'\x00\x04\x00\x91' * 100  # ADD X0, X0, #1 repeated
        results = self.detector._detect_trampoline_patterns(data, 0)
        arm64_results = [r for r in results if 'aarch64' in r.pattern_type]
        self.assertEqual(len(arm64_results), 0)


class TestRISCVTrampolineDetection(unittest.TestCase):
    """Test RISC-V trampoline pattern detection via internal method."""

    def setUp(self):
        self.detector = HookDetectorV2()

    def test_auipc_ld_jalr_detection(self):
        """Detect AUIPC t1,0; LD t1,8(t1); JALR x0,t1,0 trampoline."""
        trampoline = (
            b'\x17\x03\x00\x00'  # AUIPC t1, 0
            b'\x03\x33\x83\x00'  # LD t1, 8(t1)
            b'\x67\x00\x03\x00'  # JALR x0, t1, 0
            b'\xBE\xBA\xFE\xCA\xEF\xBE\xAD\xDE'  # 64-bit target
        )
        data = b'\x00' * 0x100 + trampoline + b'\x00' * 0x100

        results = self.detector._detect_trampoline_patterns(data, 0x100)
        self.assertTrue(len(results) > 0, "Expected RISC-V AUIPC+LD+JALR trampoline")
        self.assertEqual(results[0].pattern_type, 'riscv_auipc_ld_jalr')
        self.assertAlmostEqual(results[0].confidence, 0.95)
        self.assertEqual(results[0].target, 0xDEADBEEFCAFEBABE)

    def test_no_false_positive_on_random_riscv(self):
        """No detection on random non-trampoline RISC-V instructions."""
        data = b'\x13\x00\x00\x00' * 100  # NOP (addi x0,x0,0) repeated
        results = self.detector._detect_trampoline_patterns(data, 0)
        riscv_results = [r for r in results if 'riscv' in r.pattern_type]
        self.assertEqual(len(riscv_results), 0)


class TestMBRDetector(unittest.TestCase):
    """Test MBR/VBR bootkit detection."""

    def setUp(self):
        self.detector = MBRDetector()
        self.temp_dir = tempfile.mkdtemp()

    def _make_target(self, data: bytes) -> str:
        path = Path(self.temp_dir) / 'target.bin'
        with open(path, 'wb') as f:
            f.write(data)
        return str(path)

    def _build_mbr(self, code: bytes = b'', partition_table: bytes = None,
                   boot_sig: bool = True) -> bytes:
        """Build a 512-byte MBR with given code, partition table, and signature."""
        if partition_table is None:
            partition_table = b'\x00' * 64
        # Code section: pad to 446 bytes
        code_section = code.ljust(446, b'\x00')[:446]
        sig = b'\x55\xAA' if boot_sig else b'\x00\x00'
        return code_section + partition_table + sig

    def test_valid_boot_signature(self):
        """No finding for valid 0xAA55 signature."""
        mbr = self._build_mbr(boot_sig=True)
        target = self._make_target(mbr)
        results = self.detector.detect(target)
        sig_findings = [f for f in results if 'boot signature' in f.get('title', '').lower()
                        and 'Invalid' in f.get('title', '')]
        self.assertEqual(len(sig_findings), 0)

    def test_invalid_boot_signature(self):
        """Detect invalid boot signature."""
        mbr = self._build_mbr(boot_sig=False)
        target = self._make_target(mbr)
        results = self.detector.detect(target)
        sig_findings = [f for f in results if 'boot signature' in f.get('title', '').lower()]
        self.assertTrue(len(sig_findings) > 0)

    def test_int13h_hook_detection(self):
        """Detect INT 13h IVT write pattern."""
        # Build code that writes to IVT offset 0x4C (INT 13h)
        # MOV WORD [004Ch], 1234h -> C7 06 4C 00 34 12
        code = b'\xC7\x06\x4C\x00\x34\x12'
        mbr = self._build_mbr(code=code)
        target = self._make_target(mbr)
        results = self.detector.detect(target)

        int13_findings = [f for f in results if 'INT 13h' in f.get('title', '')]
        self.assertTrue(
            len(int13_findings) > 0,
            f"Expected INT 13h hook detection, got: {[f['title'] for f in results]}"
        )

    def test_int15h_hook_detection(self):
        """Detect INT 15h IVT write pattern."""
        # MOV WORD [0054h], 5678h -> C7 06 54 00 78 56
        code = b'\xC7\x06\x54\x00\x78\x56'
        mbr = self._build_mbr(code=code)
        target = self._make_target(mbr)
        results = self.detector.detect(target)

        int15_findings = [f for f in results if 'INT 15h' in f.get('title', '')]
        self.assertTrue(
            len(int15_findings) > 0,
            f"Expected INT 15h hook detection, got: {[f['title'] for f in results]}"
        )

    def test_relocation_detection(self):
        """Detect MBR self-relocation pattern."""
        # MOV DI, 0600h; ... REP MOVSW
        # BF 00 06 = MOV DI, 0x0600
        # F3 A5    = REP MOVSW
        code = b'\xBF\x00\x06' + b'\x90' * 5 + b'\xF3\xA5'
        mbr = self._build_mbr(code=code)
        target = self._make_target(mbr)
        results = self.detector.detect(target)

        reloc_findings = [f for f in results if 'relocation' in f.get('title', '').lower()]
        self.assertTrue(
            len(reloc_findings) > 0,
            f"Expected relocation detection, got: {[f['title'] for f in results]}"
        )

    def test_barzakh_signature_detection(self):
        """Detect AEGS signature in MBR."""
        code = b'\x90' * 100 + b'AEGS' + b'\x90' * 50
        mbr = self._build_mbr(code=code)
        target = self._make_target(mbr)
        results = self.detector.detect(target)

        sig_findings = [f for f in results if 'Barzakh research MBR' in f.get('title', '')]
        self.assertTrue(
            len(sig_findings) > 0,
            f"Expected AEGS signature finding, got: {[f['title'] for f in results]}"
        )

    def test_aegv_signature_detection(self):
        """Detect AEGV signature in MBR."""
        code = b'\x90' * 100 + b'AEGV' + b'\x90' * 50
        mbr = self._build_mbr(code=code)
        target = self._make_target(mbr)
        results = self.detector.detect(target)

        sig_findings = [f for f in results if 'Barzakh research VBR' in f.get('title', '')]
        self.assertTrue(
            len(sig_findings) > 0,
            f"Expected AEGV signature finding, got: {[f['title'] for f in results]}"
        )

    def test_empty_partition_table_with_code(self):
        """Detect empty partition table with executable code."""
        code = b'\xFA\x33\xC0\x8E\xD0' + b'\x90' * 100  # CLI + segment init
        mbr = self._build_mbr(code=code, partition_table=b'\x00' * 64)
        target = self._make_target(mbr)
        results = self.detector.detect(target)

        pt_findings = [f for f in results if 'partition' in f.get('title', '').lower()]
        self.assertTrue(len(pt_findings) > 0)

    def test_hidden_sector_boot_signature(self):
        """Detect boot signature in hidden sectors."""
        mbr = self._build_mbr(code=b'\x90' * 10)
        # Sector 2 also has boot signature
        sector2 = b'\x00' * 510 + b'\x55\xAA'
        data = mbr + sector2
        target = self._make_target(data)
        results = self.detector.detect(target)

        hidden_findings = [f for f in results if 'sector' in f.get('title', '').lower()
                           and 'signature' in f.get('title', '').lower()]
        self.assertTrue(len(hidden_findings) > 0)

    def test_clean_mbr_minimal_findings(self):
        """Clean MBR with valid signature and no hooks produces minimal findings."""
        # Standard Windows-like MBR: just NOP sled + partition table + sig
        code = b'\x00' * 446
        partition_table = b'\x80' + b'\x00' * 15  # One active partition entry (minimal)
        partition_table += b'\x00' * 48  # 3 empty entries
        mbr = code + partition_table + b'\x55\xAA'
        target = self._make_target(mbr)
        results = self.detector.detect(target)

        critical_findings = [f for f in results if f.get('severity') == 'critical']
        self.assertEqual(len(critical_findings), 0)

    def test_nonexistent_target(self):
        """Handle nonexistent file gracefully."""
        results = self.detector.detect('/nonexistent/path/mbr.bin')
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0]['severity'], 'medium')

    def test_too_small_file(self):
        """Handle file smaller than 512 bytes."""
        target = self._make_target(b'\x00' * 100)
        results = self.detector.detect(target)
        self.assertEqual(len(results), 0)


if __name__ == '__main__':
    unittest.main()

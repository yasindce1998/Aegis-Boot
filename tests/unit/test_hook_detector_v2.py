"""
Unit Tests for Enhanced Hook Detector V2

Tests FV-based pointer validation and trampoline pattern detection.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import unittest
import struct
import tempfile
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from BarzakhScanner.detectors.hook_detector_v2 import HookDetectorV2, FirmwareVolume, TrampolinePattern


class TestFirmwareVolume(unittest.TestCase):
    """Test FirmwareVolume dataclass."""
    
    def test_contains_address_inside(self):
        """Test address containment check - inside FV."""
        fv = FirmwareVolume(base_address=0x1000, size=0x1000, guid=b'\x00' * 16)
        self.assertTrue(fv.contains(0x1000))
        self.assertTrue(fv.contains(0x1500))
        self.assertTrue(fv.contains(0x1FFF))
    
    def test_contains_address_outside(self):
        """Test address containment check - outside FV."""
        fv = FirmwareVolume(base_address=0x1000, size=0x1000, guid=b'\x00' * 16)
        self.assertFalse(fv.contains(0x0FFF))
        self.assertFalse(fv.contains(0x2000))
        self.assertFalse(fv.contains(0x3000))
    
    def test_contains_boundary(self):
        """Test address containment at boundaries."""
        fv = FirmwareVolume(base_address=0x1000, size=0x1000, guid=b'\x00' * 16)
        self.assertTrue(fv.contains(0x1000))  # Start inclusive
        self.assertFalse(fv.contains(0x2000))  # End exclusive


class TestHookDetectorV2Initialization(unittest.TestCase):
    """Test HookDetectorV2 initialization."""
    
    def test_init_default(self):
        """Test default initialization."""
        detector = HookDetectorV2()
        self.assertIsNone(detector.baseline)
        self.assertFalse(detector.strict_mode)
        self.assertEqual(len(detector.findings), 0)
        self.assertEqual(len(detector.firmware_volumes), 0)
    
    def test_init_with_baseline(self):
        """Test initialization with baseline."""
        baseline = {'boot_services_table': {'AllocatePool': 0x12345678}}
        detector = HookDetectorV2(baseline=baseline)
        self.assertEqual(detector.baseline, baseline)
    
    def test_init_strict_mode(self):
        """Test initialization with strict mode."""
        detector = HookDetectorV2(strict_mode=True)
        self.assertTrue(detector.strict_mode)


class TestBootServicesTableParsing(unittest.TestCase):
    """Test Boot Services Table parsing."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = HookDetectorV2()
    
    def test_locate_bst_signature(self):
        """Test BST location by signature."""
        # Create test data with BST signature
        bst_sig = struct.pack('<Q', HookDetectorV2.BST_SIGNATURE)
        data = b'\x00' * 0x1000 + bst_sig + b'\x00' * 0x1000
        
        offset = self.detector._locate_boot_services_table(data)
        self.assertEqual(offset, 0x1000)
    
    def test_locate_bst_not_found(self):
        """Test BST location when not present."""
        data = b'\x00' * 0x1000
        offset = self.detector._locate_boot_services_table(data)
        self.assertIsNone(offset)
    
    def test_parse_bst_header(self):
        """Test BST header parsing."""
        # Create minimal BST structure
        bst_data = bytearray(0x1000)
        
        # Set signature
        struct.pack_into('<Q', bst_data, 0, HookDetectorV2.BST_SIGNATURE)
        # Set revision
        struct.pack_into('<I', bst_data, 8, 0x00020000)
        # Set header size
        struct.pack_into('<I', bst_data, 12, 0x100)
        # Set CRC32
        struct.pack_into('<I', bst_data, 16, 0x12345678)
        
        bst = self.detector._parse_boot_services_table(bytes(bst_data), 0)
        
        self.assertEqual(bst['Signature'], HookDetectorV2.BST_SIGNATURE)
        self.assertEqual(bst['Revision'], 0x00020000)
        self.assertEqual(bst['HeaderSize'], 0x100)
        self.assertEqual(bst['CRC32'], 0x12345678)
    
    def test_parse_bst_function_pointers(self):
        """Test BST function pointer parsing."""
        bst_data = bytearray(0x1000)
        
        # Set signature
        struct.pack_into('<Q', bst_data, 0, HookDetectorV2.BST_SIGNATURE)
        # Set header size
        struct.pack_into('<I', bst_data, 12, 0x100)
        
        # Set AllocatePool pointer (offset 64)
        struct.pack_into('<Q', bst_data, 64, 0xDEADBEEF12345678)
        # Set ExitBootServices pointer (offset 224)
        struct.pack_into('<Q', bst_data, 224, 0xCAFEBABE87654321)
        
        bst = self.detector._parse_boot_services_table(bytes(bst_data), 0)
        
        self.assertEqual(bst['AllocatePool'], 0xDEADBEEF12345678)
        self.assertEqual(bst['ExitBootServices'], 0xCAFEBABE87654321)


class TestCRC32Verification(unittest.TestCase):
    """Test CRC32 verification."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = HookDetectorV2()
    
    def test_crc32_mismatch_detection(self):
        """Test detection of CRC32 mismatch."""
        # Create BST with incorrect CRC32
        bst_data = bytearray(0x100)
        struct.pack_into('<Q', bst_data, 0, HookDetectorV2.BST_SIGNATURE)
        struct.pack_into('<I', bst_data, 12, 0x100)  # Header size
        struct.pack_into('<I', bst_data, 16, 0xDEADBEEF)  # Wrong CRC32
        
        bst = {
            'Signature': HookDetectorV2.BST_SIGNATURE,
            'HeaderSize': 0x100,
            'CRC32': 0xDEADBEEF
        }
        
        self.detector._verify_crc32(bst, 0, bytes(bst_data))
        
        # Should have one finding about CRC32 mismatch
        self.assertEqual(len(self.detector.findings), 1)
        self.assertEqual(self.detector.findings[0]['severity'], 'critical')
        self.assertIn('CRC32 mismatch', self.detector.findings[0]['title'])


class TestFirmwareVolumeValidation(unittest.TestCase):
    """Test FV-based pointer validation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = HookDetectorV2()
        
        # Add test FV ranges
        self.detector.firmware_volumes = [
            FirmwareVolume(0x10000, 0x10000, b'\x00' * 16),  # 0x10000-0x20000
            FirmwareVolume(0x30000, 0x10000, b'\x00' * 16),  # 0x30000-0x40000
        ]
    
    def test_pointer_in_fv(self):
        """Test pointer inside FV."""
        self.assertTrue(self.detector._is_pointer_in_fv(0x15000))
        self.assertTrue(self.detector._is_pointer_in_fv(0x35000))
    
    def test_pointer_outside_fv(self):
        """Test pointer outside FV."""
        self.assertFalse(self.detector._is_pointer_in_fv(0x5000))
        self.assertFalse(self.detector._is_pointer_in_fv(0x25000))
        self.assertFalse(self.detector._is_pointer_in_fv(0x50000))
    
    def test_pointer_at_fv_boundary(self):
        """Test pointer at FV boundaries."""
        self.assertTrue(self.detector._is_pointer_in_fv(0x10000))  # Start
        self.assertFalse(self.detector._is_pointer_in_fv(0x20000))  # End (exclusive)
    
    def test_hook_detection_outside_fv(self):
        """Test hook detection for pointers outside FV."""
        bst_data = bytearray(0x1000)
        struct.pack_into('<Q', bst_data, 0, HookDetectorV2.BST_SIGNATURE)
        struct.pack_into('<I', bst_data, 12, 0x100)
        
        # Set AllocatePool to address outside FV
        struct.pack_into('<Q', bst_data, 64, 0x50000)
        
        bst = {
            'AllocatePool': 0x50000,
            'HeaderSize': 0x100
        }
        
        self.detector._check_hooked_functions_fv(bst, 0, bytes(bst_data))
        
        # Should detect hook outside FV
        self.assertGreater(len(self.detector.findings), 0)
        finding = self.detector.findings[0]
        self.assertIn('outside Firmware Volume', finding['title'])
        self.assertEqual(finding['severity'], 'high')


class TestTrampolineDetection(unittest.TestCase):
    """Test trampoline pattern detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = HookDetectorV2()
    
    def test_detect_mov_rax_jmp_trampoline(self):
        """Test detection of MOV RAX, imm64; JMP RAX pattern."""
        # Create trampoline: MOV RAX, 0xDEADBEEF12345678; JMP RAX
        trampoline = bytearray()
        trampoline.extend([0x48, 0xB8])  # MOV RAX, imm64
        trampoline.extend(struct.pack('<Q', 0xDEADBEEF12345678))  # Target address
        trampoline.extend([0xFF, 0xE0])  # JMP RAX
        
        data = bytes(trampoline)
        trampolines = self.detector._detect_trampoline_patterns(data, 0)
        
        self.assertEqual(len(trampolines), 1)
        self.assertEqual(trampolines[0].pattern_type, 'mov_rax_jmp')
        self.assertEqual(trampolines[0].target, 0xDEADBEEF12345678)
        self.assertGreaterEqual(trampolines[0].confidence, 0.9)
    
    def test_detect_jmp_rip_indirect(self):
        """Test detection of JMP [RIP+offset] pattern."""
        # Create trampoline: JMP [RIP+offset]
        trampoline = bytearray()
        trampoline.extend([0xFF, 0x25])  # JMP [RIP+offset]
        trampoline.extend(struct.pack('<i', 0x10))  # RIP offset
        
        # Add padding and target address
        trampoline.extend(b'\x00' * 0x10)
        trampoline.extend(struct.pack('<Q', 0xCAFEBABE87654321))
        
        data = bytes(trampoline)
        trampolines = self.detector._detect_trampoline_patterns(data, 0)
        
        self.assertEqual(len(trampolines), 1)
        self.assertEqual(trampolines[0].pattern_type, 'jmp_rip_indirect')
        self.assertEqual(trampolines[0].target, 0xCAFEBABE87654321)
    
    def test_no_trampoline_in_normal_code(self):
        """Test that normal code doesn't trigger false positives."""
        # Normal function prologue
        normal_code = bytes([
            0x55,              # PUSH RBP
            0x48, 0x89, 0xE5,  # MOV RBP, RSP
            0x48, 0x83, 0xEC, 0x20,  # SUB RSP, 0x20
        ])
        
        trampolines = self.detector._detect_trampoline_patterns(normal_code, 0)
        self.assertEqual(len(trampolines), 0)


class TestBaselineComparison(unittest.TestCase):
    """Test baseline comparison functionality."""
    
    def test_detect_pointer_modification(self):
        """Test detection of modified pointers vs baseline."""
        baseline = {
            'boot_services_table': {
                'AllocatePool': 0x12345678,
                'ExitBootServices': 0x87654321
            }
        }
        
        detector = HookDetectorV2(baseline=baseline)
        
        current_bst = {
            'AllocatePool': 0x99999999,  # Modified
            'ExitBootServices': 0x87654321  # Unchanged
        }
        
        detector._compare_with_baseline(current_bst)
        
        # Should detect one modification
        self.assertEqual(len(detector.findings), 1)
        finding = detector.findings[0]
        self.assertIn('AllocatePool', finding['title'])
        self.assertEqual(finding['severity'], 'critical')
        self.assertIn('baseline', finding['details'])


class TestIntegration(unittest.TestCase):
    """Integration tests for full detection workflow."""
    
    def test_full_detection_with_hooks(self):
        """Test full detection workflow with hooked BST."""
        # Create test file with BST and hooks
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            # Create BST
            bst_data = bytearray(0x2000)
            
            # BST header
            struct.pack_into('<Q', bst_data, 0x1000, HookDetectorV2.BST_SIGNATURE)
            struct.pack_into('<I', bst_data, 0x1008, 0x00020000)  # Revision
            struct.pack_into('<I', bst_data, 0x100C, 0x100)  # Header size
            struct.pack_into('<I', bst_data, 0x1010, 0xDEADBEEF)  # Wrong CRC
            
            # Hooked function pointer (outside typical FV range)
            struct.pack_into('<Q', bst_data, 0x1040, 0x50000)  # AllocatePool
            
            # Add trampoline at hook target
            trampoline_offset = 0x50000 % len(bst_data)
            bst_data[trampoline_offset:trampoline_offset+2] = bytes([0x48, 0xB8])
            struct.pack_into('<Q', bst_data, trampoline_offset+2, 0xDEADBEEF12345678)
            bst_data[trampoline_offset+10:trampoline_offset+12] = bytes([0xFF, 0xE0])
            
            f.write(bytes(bst_data))
            temp_path = f.name
        
        try:
            detector = HookDetectorV2()
            findings = detector.detect(temp_path)
            
            # Should detect multiple issues
            self.assertGreater(len(findings), 0)
            
            # Check for CRC32 mismatch
            crc_findings = [f for f in findings if 'CRC32' in f['title']]
            self.assertGreater(len(crc_findings), 0)
            
        finally:
            Path(temp_path).unlink()
    
    def test_detection_with_clean_bst(self):
        """Test detection with clean (unhook) BST."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            # Create clean BST
            bst_data = bytearray(0x2000)
            
            # Add FV signature
            bst_data[0:4] = b'_FVH'
            struct.pack_into('<Q', bst_data, 32, 0x1000)  # FV length
            
            # BST header at offset 0x1000
            struct.pack_into('<Q', bst_data, 0x1000, HookDetectorV2.BST_SIGNATURE)
            struct.pack_into('<I', bst_data, 0x1008, 0x00020000)
            struct.pack_into('<I', bst_data, 0x100C, 0x100)
            
            # Function pointers within FV range
            struct.pack_into('<Q', bst_data, 0x1040, 0x500)  # AllocatePool
            struct.pack_into('<Q', bst_data, 0x10E0, 0x600)  # ExitBootServices
            
            f.write(bytes(bst_data))
            temp_path = f.name
        
        try:
            detector = HookDetectorV2()
            findings = detector.detect(temp_path)
            
            # Should have minimal findings (maybe CRC32 if not calculated correctly)
            # But no hook detections
            hook_findings = [f for f in findings if 'outside Firmware Volume' in f.get('title', '')]
            self.assertEqual(len(hook_findings), 0)
            
        finally:
            Path(temp_path).unlink()


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestFirmwareVolume))
    suite.addTests(loader.loadTestsFromTestCase(TestHookDetectorV2Initialization))
    suite.addTests(loader.loadTestsFromTestCase(TestBootServicesTableParsing))
    suite.addTests(loader.loadTestsFromTestCase(TestCRC32Verification))
    suite.addTests(loader.loadTestsFromTestCase(TestFirmwareVolumeValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestTrampolineDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestBaselineComparison))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)



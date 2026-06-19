"""
Unit Tests for PCR Replay Engine

Tests the core PCR extension algorithm and event log replay functionality.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import unittest
import hashlib
from src.BarzakhScanner.detectors.pcr_replay import PCRReplayEngine, HashAlgorithm


class TestPCRReplayEngine(unittest.TestCase):
    """Test suite for PCR Replay Engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = PCRReplayEngine()
    
    def test_initialization(self):
        """Test engine initializes with zeros."""
        for i in range(24):
            pcr_value = self.engine.get_pcr_value(i)
            self.assertEqual(pcr_value, b'\x00' * 32)
            self.assertEqual(len(pcr_value), 32)  # SHA256
    
    def test_single_pcr_extension(self):
        """Test single PCR extension matches expected value."""
        # PCR0 starts at 0x00...00
        # Extend with known digest
        test_digest = b'\x01' * 32
        
        result = self.engine.extend_pcr(0, test_digest)
        
        # Calculate expected: Hash(0x00...00 || 0x01...01)
        expected = hashlib.sha256(b'\x00' * 32 + test_digest).digest()
        
        self.assertEqual(result, expected)
        self.assertEqual(self.engine.get_pcr_value(0), expected)
    
    def test_multiple_extensions_same_pcr(self):
        """Test multiple extensions to same PCR."""
        digest1 = b'\x01' * 32
        digest2 = b'\x02' * 32
        
        # First extension
        result1 = self.engine.extend_pcr(0, digest1)
        expected1 = hashlib.sha256(b'\x00' * 32 + digest1).digest()
        self.assertEqual(result1, expected1)
        
        # Second extension
        result2 = self.engine.extend_pcr(0, digest2)
        expected2 = hashlib.sha256(result1 + digest2).digest()
        self.assertEqual(result2, expected2)
    
    def test_different_pcrs_independent(self):
        """Test that different PCRs are independent."""
        digest = b'\xAA' * 32
        
        self.engine.extend_pcr(0, digest)
        self.engine.extend_pcr(1, digest)
        
        # Both should have same value (extended from zero)
        pcr0 = self.engine.get_pcr_value(0)
        pcr1 = self.engine.get_pcr_value(1)
        
        self.assertEqual(pcr0, pcr1)
        
        # Extend PCR0 again
        self.engine.extend_pcr(0, digest)
        
        # Now they should be different
        pcr0_new = self.engine.get_pcr_value(0)
        self.assertNotEqual(pcr0_new, pcr1)
    
    def test_invalid_pcr_index(self):
        """Test that invalid PCR indices raise ValueError."""
        digest = b'\x00' * 32
        
        with self.assertRaises(ValueError):
            self.engine.extend_pcr(-1, digest)
        
        with self.assertRaises(ValueError):
            self.engine.extend_pcr(24, digest)
        
        with self.assertRaises(ValueError):
            self.engine.extend_pcr(100, digest)
    
    def test_invalid_digest_size(self):
        """Test that invalid digest sizes raise ValueError."""
        with self.assertRaises(ValueError):
            self.engine.extend_pcr(0, b'\x00' * 16)  # Too short
        
        with self.assertRaises(ValueError):
            self.engine.extend_pcr(0, b'\x00' * 64)  # Too long
        
        with self.assertRaises(ValueError):
            self.engine.extend_pcr(0, b'')  # Empty
    
    def test_event_log_replay(self):
        """Test replaying a simple event log."""
        events = [
            {
                'pcr_index': 0,
                'digests': [
                    {
                        'algorithm': HashAlgorithm.SHA256,
                        'digest': ('01' * 32)
                    }
                ]
            },
            {
                'pcr_index': 0,
                'digests': [
                    {
                        'algorithm': HashAlgorithm.SHA256,
                        'digest': ('02' * 32)
                    }
                ]
            },
            {
                'pcr_index': 1,
                'digests': [
                    {
                        'algorithm': HashAlgorithm.SHA256,
                        'digest': ('03' * 32)
                    }
                ]
            }
        ]
        
        result = self.engine.replay_event_log(events)
        
        # Verify PCR0 was extended twice
        self.assertEqual(self.engine.get_extension_count(0), 2)
        
        # Verify PCR1 was extended once
        self.assertEqual(self.engine.get_extension_count(1), 1)
        
        # Verify PCR2 was not extended
        self.assertEqual(self.engine.get_extension_count(2), 0)
        self.assertEqual(result[2], b'\x00' * 32)
    
    def test_validate_against_tpm_match(self):
        """Test validation when PCRs match."""
        # Extend PCR0
        digest = b'\xAB' * 32
        self.engine.extend_pcr(0, digest)
        
        # Create matching TPM state
        tpm_pcrs = {
            0: self.engine.get_pcr_value(0),
            1: b'\x00' * 32,
            2: b'\x00' * 32,
            3: b'\x00' * 32,
            4: b'\x00' * 32,
            5: b'\x00' * 32,
            6: b'\x00' * 32,
            7: b'\x00' * 32
        }
        
        findings = self.engine.validate_against_tpm(tpm_pcrs)
        
        # Should have no findings (all match)
        self.assertEqual(len(findings), 0)
    
    def test_validate_against_tpm_mismatch(self):
        """Test validation detects PCR mismatch."""
        # Extend PCR0
        digest = b'\xCD' * 32
        self.engine.extend_pcr(0, digest)
        
        # Create mismatched TPM state (PCR0 different)
        tpm_pcrs = {
            0: b'\xFF' * 32,  # Wrong value
            1: b'\x00' * 32,
            2: b'\x00' * 32,
            3: b'\x00' * 32,
            4: b'\x00' * 32,
            5: b'\x00' * 32,
            6: b'\x00' * 32,
            7: b'\x00' * 32
        }
        
        findings = self.engine.validate_against_tpm(tpm_pcrs)
        
        # Should detect mismatch in PCR0
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['details']['pcr_index'], 0)
        self.assertEqual(findings[0]['severity'], 'critical')
        self.assertIn('tampering', findings[0]['description'].lower())
    
    def test_reset(self):
        """Test reset clears all PCRs."""
        # Extend some PCRs
        digest = b'\xEF' * 32
        self.engine.extend_pcr(0, digest)
        self.engine.extend_pcr(1, digest)
        self.engine.extend_pcr(2, digest)
        
        # Verify they're not zero
        self.assertNotEqual(self.engine.get_pcr_value(0), b'\x00' * 32)
        
        # Reset
        self.engine.reset()
        
        # Verify all back to zero
        for i in range(24):
            self.assertEqual(self.engine.get_pcr_value(i), b'\x00' * 32)
        
        # Verify history cleared
        self.assertEqual(len(self.engine.extension_history), 0)
    
    def test_extension_history_tracking(self):
        """Test that extension history is tracked correctly."""
        digest1 = b'\x11' * 32
        digest2 = b'\x22' * 32
        
        self.engine.extend_pcr(0, digest1)
        self.engine.extend_pcr(0, digest2)
        self.engine.extend_pcr(1, digest1)
        
        # Check history length
        self.assertEqual(len(self.engine.extension_history), 3)
        
        # Check first entry
        self.assertEqual(self.engine.extension_history[0]['pcr_index'], 0)
        self.assertEqual(self.engine.extension_history[0]['digest'], digest1.hex())
        
        # Check extension counts
        self.assertEqual(self.engine.get_extension_count(0), 2)
        self.assertEqual(self.engine.get_extension_count(1), 1)
        self.assertEqual(self.engine.get_extension_count(2), 0)
    
    def test_export_state(self):
        """Test state export functionality."""
        digest = b'\x33' * 32
        self.engine.extend_pcr(0, digest)
        self.engine.extend_pcr(1, digest)
        
        state = self.engine.export_state()
        
        # Verify structure
        self.assertIn('algorithm', state)
        self.assertIn('pcr_values', state)
        self.assertIn('extension_count', state)
        self.assertIn('history', state)
        
        # Verify content
        self.assertEqual(state['algorithm'], 'SHA256')
        self.assertEqual(state['extension_count'][0], 1)
        self.assertEqual(state['extension_count'][1], 1)
        self.assertEqual(len(state['history']), 2)
    
    def test_sha1_algorithm(self):
        """Test PCR replay with SHA1 algorithm."""
        engine_sha1 = PCRReplayEngine(HashAlgorithm.SHA1)
        
        # SHA1 produces 20-byte digests
        digest = b'\x44' * 20
        result = engine_sha1.extend_pcr(0, digest)
        
        self.assertEqual(len(result), 20)
        
        # Verify calculation
        expected = hashlib.sha1(b'\x00' * 20 + digest).digest()
        self.assertEqual(result, expected)
    
    def test_known_tpm_sequence(self):
        """Test against known TPM measurement sequence."""
        # Simulate a known boot sequence
        # PCR0: BIOS measurement
        bios_digest = hashlib.sha256(b'BIOS_CODE').digest()
        
        # PCR1: BIOS config
        config_digest = hashlib.sha256(b'BIOS_CONFIG').digest()
        
        # PCR4: Bootloader
        bootloader_digest = hashlib.sha256(b'BOOTLOADER').digest()
        
        # Extend PCRs
        self.engine.extend_pcr(0, bios_digest)
        self.engine.extend_pcr(1, config_digest)
        self.engine.extend_pcr(4, bootloader_digest)
        
        # Calculate expected final values
        expected_pcr0 = hashlib.sha256(b'\x00' * 32 + bios_digest).digest()
        expected_pcr1 = hashlib.sha256(b'\x00' * 32 + config_digest).digest()
        expected_pcr4 = hashlib.sha256(b'\x00' * 32 + bootloader_digest).digest()
        
        # Verify
        self.assertEqual(self.engine.get_pcr_value(0), expected_pcr0)
        self.assertEqual(self.engine.get_pcr_value(1), expected_pcr1)
        self.assertEqual(self.engine.get_pcr_value(4), expected_pcr4)
    
    def test_event_log_with_multiple_algorithms(self):
        """Test event log with multiple hash algorithms."""
        events = [
            {
                'pcr_index': 0,
                'digests': [
                    {
                        'algorithm': HashAlgorithm.SHA1,  # Should be ignored
                        'digest': ('AA' * 20)
                    },
                    {
                        'algorithm': HashAlgorithm.SHA256,  # Should be used
                        'digest': ('BB' * 32)
                    }
                ]
            }
        ]
        
        self.engine.replay_event_log(events)
        
        # Should only process SHA256 digest
        self.assertEqual(self.engine.get_extension_count(0), 1)
        
        # Verify it used the SHA256 digest
        expected = hashlib.sha256(
            b'\x00' * 32 + bytes.fromhex('BB' * 32)
        ).digest()
        self.assertEqual(self.engine.get_pcr_value(0), expected)


if __name__ == '__main__':
    unittest.main()



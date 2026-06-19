"""
Integration Tests for PCR Replay with Scanner

Tests the complete PCR replay workflow integrated with the scanner.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import unittest
import tempfile
import struct
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.BarzakhScanner.detectors.pcr_detector import PCRDetector
from src.BarzakhScanner.detectors.pcr_replay import HashAlgorithm


class TestPCRReplayIntegration(unittest.TestCase):
    """Integration tests for PCR replay with scanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_mock_pcr_dump(self, pcr_values: dict) -> Path:
        """Create a mock PCR dump file."""
        pcr_file = self.temp_path / 'pcr_dump.bin'
        
        with open(pcr_file, 'wb') as f:
            # Write 8 PCRs (0-7) as 32-byte SHA256 values
            for i in range(8):
                pcr_value = pcr_values.get(i, b'\x00' * 32)
                f.write(pcr_value)
        
        return pcr_file
    
    def _create_mock_event_log(self, events: list) -> Path:
        """Create a mock TCG event log file."""
        event_log_file = self.temp_path / 'eventlog.bin'
        
        with open(event_log_file, 'wb') as f:
            for event in events:
                # Write TCG_PCR_EVENT2 structure
                # PCRIndex (4 bytes)
                f.write(struct.pack('<I', event['pcr_index']))
                
                # EventType (4 bytes)
                f.write(struct.pack('<I', event.get('event_type', 0x80000007)))
                
                # DigestCount (4 bytes)
                digests = event.get('digests', [])
                f.write(struct.pack('<I', len(digests)))
                
                # Digests
                for digest_info in digests:
                    # AlgorithmId (2 bytes)
                    f.write(struct.pack('<H', digest_info['algorithm']))
                    
                    # Digest (32 bytes for SHA256)
                    digest_bytes = bytes.fromhex(digest_info['digest'])
                    f.write(digest_bytes)
                
                # EventSize (4 bytes)
                event_data = event.get('event_data', b'')
                f.write(struct.pack('<I', len(event_data)))
                
                # Event data
                f.write(event_data)
        
        return event_log_file
    
    def test_pcr_replay_detects_valid_measurements(self):
        """Test that PCR replay validates correct measurements."""
        import hashlib
        
        # Create event log with known measurements
        digest1 = hashlib.sha256(b'BIOS_CODE').digest()
        digest2 = hashlib.sha256(b'BIOS_CONFIG').digest()
        
        events = [
            {
                'pcr_index': 0,
                'digests': [
                    {
                        'algorithm': HashAlgorithm.SHA256,
                        'digest': digest1.hex()
                    }
                ]
            },
            {
                'pcr_index': 1,
                'digests': [
                    {
                        'algorithm': HashAlgorithm.SHA256,
                        'digest': digest2.hex()
                    }
                ]
            }
        ]
        
        # Calculate expected PCR values
        expected_pcr0 = hashlib.sha256(b'\x00' * 32 + digest1).digest()
        expected_pcr1 = hashlib.sha256(b'\x00' * 32 + digest2).digest()
        
        # Create mock files
        pcr_values = {
            0: expected_pcr0,
            1: expected_pcr1,
            2: b'\x00' * 32,
            3: b'\x00' * 32,
            4: b'\x00' * 32,
            5: b'\x00' * 32,
            6: b'\x00' * 32,
            7: b'\x00' * 32
        }
        
        pcr_file = self._create_mock_pcr_dump(pcr_values)
        event_log_file = self._create_mock_event_log(events)
        
        # Run detector
        detector = PCRDetector(enable_replay=True)
        findings = detector.detect(str(pcr_file))
        
        # Should have info finding about successful validation
        info_findings = [f for f in findings if f.get('severity') == 'info']
        self.assertTrue(len(info_findings) > 0, "Should have info finding for successful validation")
        
        # Should not have critical findings
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        self.assertEqual(len(critical_findings), 0, "Should not have critical findings for valid PCRs")
    
    def test_pcr_replay_detects_tampering(self):
        """Test that PCR replay detects event log tampering."""
        import hashlib
        
        # Create event log with one measurement
        digest1 = hashlib.sha256(b'BIOS_CODE').digest()
        
        events = [
            {
                'pcr_index': 0,
                'digests': [
                    {
                        'algorithm': HashAlgorithm.SHA256,
                        'digest': digest1.hex()
                    }
                ]
            }
        ]
        
        # Calculate what PCR0 SHOULD be
        expected_pcr0 = hashlib.sha256(b'\x00' * 32 + digest1).digest()
        
        # But provide WRONG PCR value (simulating tampering)
        tampered_pcr0 = hashlib.sha256(b'TAMPERED').digest()
        
        pcr_values = {
            0: tampered_pcr0,  # Wrong value!
            1: b'\x00' * 32,
            2: b'\x00' * 32,
            3: b'\x00' * 32,
            4: b'\x00' * 32,
            5: b'\x00' * 32,
            6: b'\x00' * 32,
            7: b'\x00' * 32
        }
        
        # Create mock files
        pcr_file = self._create_mock_pcr_dump(pcr_values)
        event_log_file = self._create_mock_event_log(events)
        
        # Run detector
        detector = PCRDetector(enable_replay=True)
        findings = detector.detect(str(pcr_file))
        
        # Should detect tampering
        critical_findings = [f for f in findings 
                           if f.get('severity') == 'critical' 
                           and 'replay mismatch' in f.get('title', '').lower()]
        
        self.assertTrue(len(critical_findings) > 0, "Should detect PCR replay mismatch")
        
        # Verify finding details
        finding = critical_findings[0]
        self.assertEqual(finding['details']['pcr_index'], 0)
        self.assertIn('tampering', finding['description'].lower())
    
    def test_pcr_replay_handles_missing_event_log(self):
        """Test graceful handling when event log is missing."""
        # Create PCR dump but no event log
        pcr_values = {i: b'\x00' * 32 for i in range(8)}
        pcr_file = self._create_mock_pcr_dump(pcr_values)
        
        # Run detector
        detector = PCRDetector(enable_replay=True)
        findings = detector.detect(str(pcr_file))
        
        # Should have medium severity finding about missing event log
        missing_log_findings = [f for f in findings 
                               if 'event log not found' in f.get('title', '').lower()]
        
        self.assertTrue(len(missing_log_findings) > 0, 
                       "Should report missing event log")
        self.assertEqual(missing_log_findings[0]['severity'], 'medium')
    
    def test_pcr_replay_can_be_disabled(self):
        """Test that PCR replay can be disabled."""
        # Create PCR dump
        pcr_values = {i: b'\x00' * 32 for i in range(8)}
        pcr_file = self._create_mock_pcr_dump(pcr_values)
        
        # Run detector with replay disabled
        detector = PCRDetector(enable_replay=False)
        findings = detector.detect(str(pcr_file))
        
        # Should not have any replay-related findings
        replay_findings = [f for f in findings 
                          if 'replay' in f.get('title', '').lower()]
        
        self.assertEqual(len(replay_findings), 0, 
                        "Should not have replay findings when disabled")
    
    def test_pcr_replay_with_multiple_extensions(self):
        """Test PCR replay with multiple extensions to same PCR."""
        import hashlib
        
        # Create event log with multiple measurements to PCR0
        digest1 = hashlib.sha256(b'MEASUREMENT_1').digest()
        digest2 = hashlib.sha256(b'MEASUREMENT_2').digest()
        digest3 = hashlib.sha256(b'MEASUREMENT_3').digest()
        
        events = [
            {
                'pcr_index': 0,
                'digests': [{'algorithm': HashAlgorithm.SHA256, 'digest': digest1.hex()}]
            },
            {
                'pcr_index': 0,
                'digests': [{'algorithm': HashAlgorithm.SHA256, 'digest': digest2.hex()}]
            },
            {
                'pcr_index': 0,
                'digests': [{'algorithm': HashAlgorithm.SHA256, 'digest': digest3.hex()}]
            }
        ]
        
        # Calculate expected final PCR0 value
        pcr0_step1 = hashlib.sha256(b'\x00' * 32 + digest1).digest()
        pcr0_step2 = hashlib.sha256(pcr0_step1 + digest2).digest()
        pcr0_final = hashlib.sha256(pcr0_step2 + digest3).digest()
        
        pcr_values = {
            0: pcr0_final,
            1: b'\x00' * 32,
            2: b'\x00' * 32,
            3: b'\x00' * 32,
            4: b'\x00' * 32,
            5: b'\x00' * 32,
            6: b'\x00' * 32,
            7: b'\x00' * 32
        }
        
        # Create mock files
        pcr_file = self._create_mock_pcr_dump(pcr_values)
        event_log_file = self._create_mock_event_log(events)
        
        # Run detector
        detector = PCRDetector(enable_replay=True)
        findings = detector.detect(str(pcr_file))
        
        # Should validate successfully
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        self.assertEqual(len(critical_findings), 0, 
                        "Should validate multiple extensions correctly")


if __name__ == '__main__':
    unittest.main()



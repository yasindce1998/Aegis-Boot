"""
Unit tests for PCR Detector

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import pytest
import tempfile
import struct
from pathlib import Path
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.AegisScanner.detectors.pcr_detector import PCRDetector


class TestPCRDetector:
    """Test suite for PCR Detector."""

    def setup_method(self):
        """Setup test fixtures."""
        self.detector = PCRDetector()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Cleanup test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        assert self.detector is not None
        assert self.detector.baseline is None
        assert self.detector.findings == []

    def test_detector_with_baseline(self):
        """Test detector with baseline."""
        baseline = {
            'pcr_values': {
                '0': 'a' * 64,
                '1': 'b' * 64
            }
        }
        detector = PCRDetector(baseline=baseline)
        assert detector.baseline == baseline

    def test_detect_with_valid_pcr_dump(self):
        """Test detection with valid PCR dump."""
        # Create test PCR dump (8 PCRs × 32 bytes)
        pcr_data = b''
        for i in range(8):
            pcr_data += bytes([i] * 32)
        
        test_file = Path(self.temp_dir) / 'pcr_dump.bin'
        with open(test_file, 'wb') as f:
            f.write(pcr_data)
        
        findings = self.detector.detect(str(test_file))
        assert isinstance(findings, list)

    def test_detect_with_missing_file(self):
        """Test detection with missing file."""
        findings = self.detector.detect('/nonexistent/file.bin')
        assert len(findings) > 0
        assert findings[0]['severity'] == 'medium'
        assert 'Unable to extract PCR values' in findings[0]['title']

    def test_detect_all_zero_pcr(self):
        """Test detection of all-zero PCR."""
        # Create PCR dump with all zeros
        pcr_data = b'\x00' * 256
        
        test_file = Path(self.temp_dir) / 'zero_pcr.bin'
        with open(test_file, 'wb') as f:
            f.write(pcr_data)
        
        findings = self.detector.detect(str(test_file))
        
        # Should detect all-zero PCRs
        zero_findings = [f for f in findings if 'all zeros' in f['title']]
        assert len(zero_findings) > 0

    def test_detect_all_ones_pcr(self):
        """Test detection of all-ones PCR."""
        # Create PCR dump with all ones
        pcr_data = b'\xff' * 256
        
        test_file = Path(self.temp_dir) / 'ones_pcr.bin'
        with open(test_file, 'wb') as f:
            f.write(pcr_data)
        
        findings = self.detector.detect(str(test_file))
        
        # Should detect all-ones PCRs
        ones_findings = [f for f in findings if 'all ones' in f['title']]
        assert len(ones_findings) > 0

    def test_detect_with_baseline_mismatch(self):
        """Test detection with baseline mismatch."""
        baseline = {
            'pcr_values': {
                '0': 'a' * 64,
                '1': 'b' * 64
            }
        }
        detector = PCRDetector(baseline=baseline)
        
        # Create different PCR values
        pcr_data = b''
        for i in range(8):
            pcr_data += bytes([i] * 32)
        
        test_file = Path(self.temp_dir) / 'mismatch_pcr.bin'
        with open(test_file, 'wb') as f:
            f.write(pcr_data)
        
        findings = detector.detect(str(test_file))
        
        # Should detect mismatches
        mismatch_findings = [f for f in findings if 'mismatch' in f['title']]
        assert len(mismatch_findings) > 0

    def test_detect_identical_pcrs(self):
        """Test detection of identical PCR values."""
        # Create PCR dump with identical values for PCR 0-3
        pcr_data = b''
        identical_value = b'\xaa' * 32
        for i in range(4):
            pcr_data += identical_value
        for i in range(4, 8):
            pcr_data += bytes([i] * 32)
        
        test_file = Path(self.temp_dir) / 'identical_pcr.bin'
        with open(test_file, 'wb') as f:
            f.write(pcr_data)
        
        findings = self.detector.detect(str(test_file))
        
        # Should detect identical PCRs
        identical_findings = [f for f in findings if 'Identical' in f['title']]
        assert len(identical_findings) > 0

    def test_pcr_descriptions(self):
        """Test PCR descriptions are defined."""
        assert len(PCRDetector.PCR_DESCRIPTIONS) == 8
        assert 0 in PCRDetector.PCR_DESCRIPTIONS
        assert 7 in PCRDetector.PCR_DESCRIPTIONS

    def test_finding_structure(self):
        """Test finding structure is correct."""
        pcr_data = b'\x00' * 256
        
        test_file = Path(self.temp_dir) / 'test_pcr.bin'
        with open(test_file, 'wb') as f:
            f.write(pcr_data)
        
        findings = self.detector.detect(str(test_file))
        
        if findings:
            finding = findings[0]
            assert 'detector' in finding
            assert 'severity' in finding
            assert 'title' in finding
            assert 'description' in finding
            assert finding['detector'] == 'pcr'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

# Made with Bob

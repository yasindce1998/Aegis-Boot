"""
Unit Tests for Entropy Analyzer

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from AegisScanner.detectors.entropy_analyzer import EntropyAnalyzer, EntropyRegion


class TestEntropyAnalyzer:
    """Test suite for EntropyAnalyzer."""
    
    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = EntropyAnalyzer()
        assert analyzer.window_size == EntropyAnalyzer.DEFAULT_WINDOW_SIZE
        assert analyzer.findings == []
        
        # Custom window size
        analyzer = EntropyAnalyzer(window_size=512)
        assert analyzer.window_size == 512
    
    def test_calculate_entropy_zeros(self):
        """Test entropy calculation on all zeros (should be 0.0)."""
        analyzer = EntropyAnalyzer(window_size=256)
        data = b'\x00' * 1024
        
        entropies = analyzer.calculate_entropy(data)
        
        assert len(entropies) > 0
        assert all(e == 0.0 for e in entropies)
    
    def test_calculate_entropy_random(self):
        """Test entropy calculation on random data (should be ~8.0)."""
        analyzer = EntropyAnalyzer(window_size=256)
        
        # Pseudo-random data
        data = bytes([(i * 37 + 17) % 256 for i in range(1024)])
        
        entropies = analyzer.calculate_entropy(data)
        
        assert len(entropies) > 0
        # Random data should have high entropy
        assert max(entropies) > 7.0
    
    def test_calculate_entropy_mixed(self):
        """Test entropy on mixed data."""
        analyzer = EntropyAnalyzer(window_size=256)
        
        # Mix of zeros and random
        data = b'\x00' * 512 + bytes([(i * 37) % 256 for i in range(512)])
        
        entropies = analyzer.calculate_entropy(data)
        
        assert len(entropies) > 0
        # Should have both low and high entropy regions
        assert min(entropies) < 2.0
        assert max(entropies) > 6.0
    
    def test_analyze_regions_high_entropy(self):
        """Test detection of high entropy regions."""
        analyzer = EntropyAnalyzer(window_size=256)
        
        # High entropy data (encrypted/packed)
        data = bytes([(i * 37 + 17) % 256 for i in range(2048)])
        
        regions = analyzer.analyze_regions(data)
        
        # Should detect high entropy
        high_entropy = [r for r in regions if r.suspicious]
        assert len(high_entropy) > 0
        assert all(r.entropy > EntropyAnalyzer.HIGH_ENTROPY_THRESHOLD for r in high_entropy)
    
    def test_analyze_regions_low_entropy(self):
        """Test detection of low entropy regions."""
        analyzer = EntropyAnalyzer(window_size=256)
        
        # Low entropy data (padding)
        data = b'\x00' * 2048
        
        regions = analyzer.analyze_regions(data)
        
        # Should detect low entropy
        assert len(regions) > 0
        assert all(r.entropy < EntropyAnalyzer.LOW_ENTROPY_THRESHOLD for r in regions)
    
    def test_detect_with_findings(self):
        """Test detect method generates findings."""
        analyzer = EntropyAnalyzer(window_size=256)
        
        # Create temp file with high entropy
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(bytes([(i * 37) % 256 for i in range(4096)]))
            temp_path = f.name
        
        try:
            findings = analyzer.detect(temp_path)
            
            # Should have findings for high entropy
            assert len(findings) > 0
            assert any('high entropy' in f.get('description', '').lower() for f in findings)
        finally:
            Path(temp_path).unlink()
    
    def test_detect_nonexistent_file(self):
        """Test detect with nonexistent file."""
        analyzer = EntropyAnalyzer()
        
        findings = analyzer.detect("/nonexistent/file.bin")
        
        # Should return empty list or error finding
        assert isinstance(findings, list)
    
    def test_entropy_range(self):
        """Test that entropy is always in valid range [0, 8]."""
        analyzer = EntropyAnalyzer(window_size=128)
        
        # Test various data patterns
        test_data = [
            b'\x00' * 1024,  # All zeros
            b'\xFF' * 1024,  # All ones
            bytes(range(256)) * 4,  # Sequential
            bytes([(i * 37) % 256 for i in range(1024)]),  # Pseudo-random
        ]
        
        for data in test_data:
            entropies = analyzer.calculate_entropy(data)
            assert all(0.0 <= e <= 8.0 for e in entropies), \
                f"Entropy out of range: {entropies}"
    
    def test_window_size_edge_cases(self):
        """Test edge cases for window size."""
        # Very small window
        analyzer = EntropyAnalyzer(window_size=16)
        data = b'\x00' * 256
        entropies = analyzer.calculate_entropy(data)
        assert len(entropies) > 0
        
        # Large window
        analyzer = EntropyAnalyzer(window_size=1024)
        data = b'\x00' * 2048
        entropies = analyzer.calculate_entropy(data)
        assert len(entropies) > 0
    
    def test_empty_data(self):
        """Test handling of empty data."""
        analyzer = EntropyAnalyzer()
        
        entropies = analyzer.calculate_entropy(b'')
        assert entropies == []
        
        regions = analyzer.analyze_regions(b'')
        assert regions == []
    
    def test_data_smaller_than_window(self):
        """Test data smaller than window size."""
        analyzer = EntropyAnalyzer(window_size=256)
        data = b'\x00' * 128  # Smaller than window
        
        entropies = analyzer.calculate_entropy(data)
        # Should handle gracefully
        assert isinstance(entropies, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])



"""
Performance Benchmarks for Barzakh Scanner

Uses pytest-benchmark to measure and track performance of detection operations.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import sys
from pathlib import Path
import tempfile

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from BarzakhScanner.detectors.entropy_analyzer import EntropyAnalyzer
from BarzakhScanner.detectors.memory_detector import MemoryDetector
from BarzakhScanner.detectors.hook_detector_v2 import HookDetectorV2


class TestEntropyPerformance:
    """Performance benchmarks for entropy analysis."""
    
    def test_entropy_calculation_1kb(self, benchmark):
        """Benchmark entropy calculation on 1KB data."""
        analyzer = EntropyAnalyzer(window_size=256)
        data = bytes([(i * 37) % 256 for i in range(1024)])
        
        result = benchmark(analyzer.calculate_entropy, data)
        assert len(result) > 0
    
    def test_entropy_calculation_64kb(self, benchmark):
        """Benchmark entropy calculation on 64KB data."""
        analyzer = EntropyAnalyzer(window_size=256)
        data = bytes([(i * 37) % 256 for i in range(65536)])
        
        result = benchmark(analyzer.calculate_entropy, data)
        assert len(result) > 0
    
    def test_entropy_calculation_1mb(self, benchmark):
        """Benchmark entropy calculation on 1MB data."""
        analyzer = EntropyAnalyzer(window_size=256)
        data = bytes([(i * 37) % 256 for i in range(1024 * 1024)])
        
        result = benchmark(analyzer.calculate_entropy, data)
        assert len(result) > 0


class TestHookDetectionPerformance:
    """Performance benchmarks for hook detection."""
    
    def test_hook_scanning_small_dump(self, benchmark):
        """Benchmark hook scanning on small memory dump (64KB)."""
        detector = HookDetectorV2()
        data = bytes([(i * 37) % 256 for i in range(65536)])
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            temp_path = f.name
        
        try:
            result = benchmark(detector.detect, temp_path)
            assert isinstance(result, list)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_hook_scanning_medium_dump(self, benchmark):
        """Benchmark hook scanning on medium memory dump (1MB)."""
        detector = HookDetectorV2()
        data = bytes([(i * 37) % 256 for i in range(1024 * 1024)])
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            temp_path = f.name
        
        try:
            result = benchmark(detector.detect, temp_path)
            assert isinstance(result, list)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestMemoryDetectionPerformance:
    """Performance benchmarks for memory detection."""
    
    def test_memory_analysis_64kb(self, benchmark):
        """Benchmark memory analysis on 64KB dump."""
        detector = MemoryDetector()
        data = bytes([(i * 37) % 256 for i in range(65536)])
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            temp_path = f.name
        
        try:
            result = benchmark(detector.detect, temp_path)
            assert isinstance(result, list)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestPCRReplayPerformance:
    """Performance benchmarks for PCR replay."""
    
    def test_pcr_extend_single(self, benchmark):
        """Benchmark single PCR extend operation."""
        from BarzakhScanner.detectors.pcr_replay import PCRReplay
        
        pcr_replay = PCRReplay()
        pcr_value = b'\x00' * 32
        event_data = b'\x01' * 32
        
        result = benchmark(pcr_replay._extend_pcr, pcr_value, event_data)
        assert len(result) == 32
    
    def test_pcr_replay_100_events(self, benchmark):
        """Benchmark PCR replay with 100 events."""
        from BarzakhScanner.detectors.pcr_replay import PCRReplay
        
        pcr_replay = PCRReplay()
        
        def replay_events():
            pcr = b'\x00' * 32
            for i in range(100):
                event_data = bytes([i % 256] * 32)
                pcr = pcr_replay._extend_pcr(pcr, event_data)
            return pcr
        
        result = benchmark(replay_events)
        assert len(result) == 32


class TestFullScanPerformance:
    """Performance benchmarks for full scan operations."""
    
    def test_full_scan_small_firmware(self, benchmark):
        """Benchmark full scan on small firmware (256KB)."""
        from BarzakhScanner.scanner import BarzakhScanner
        
        # Create synthetic firmware
        data = bytes([(i * 37) % 256 for i in range(256 * 1024)])
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            temp_path = f.name
        
        try:
            scanner = BarzakhScanner()
            result = benchmark(scanner.scan, temp_path)
            assert 'findings' in result
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--benchmark-only", "--benchmark-autosave"])



"""
Entropy Analyzer

Detects packed or encrypted malware in firmware using Shannon entropy analysis.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import math
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class EntropyRegion:
    """Represents a region with calculated entropy."""
    offset: int
    size: int
    entropy: float
    suspicious: bool


class EntropyAnalyzer:
    """Analyzer for detecting packed/encrypted code via entropy."""
    
    # Entropy thresholds
    HIGH_ENTROPY_THRESHOLD = 7.5  # Likely encrypted/packed
    LOW_ENTROPY_THRESHOLD = 1.0   # Likely padding/zeros
    
    # Window size for sliding entropy calculation
    DEFAULT_WINDOW_SIZE = 256

    def __init__(self, window_size: int = DEFAULT_WINDOW_SIZE):
        """
        Initialize entropy analyzer.
        
        Args:
            window_size: Size of sliding window for entropy calculation
        """
        self.window_size = window_size
        self.findings = []

    def calculate_entropy(self, data: bytes) -> List[float]:
        """
        Calculate Shannon entropy across data using sliding window.
        
        Args:
            data: Binary data to analyze
            
        Returns:
            List of entropy values for each window
        """
        entropy_values = []
        
        for i in range(0, len(data) - self.window_size, self.window_size):
            window = data[i:i+self.window_size]
            entropy = self._shannon_entropy(window)
            entropy_values.append(entropy)
        
        return entropy_values

    def _shannon_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy for a data block.
        
        Formula: H = -Σ(p_i * log2(p_i))
        where p_i is the probability of byte i
        
        Args:
            data: Data block
            
        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        # Calculate probabilities and entropy
        entropy = 0.0
        data_len = len(data)
        
        for freq in frequencies:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy

    def analyze_regions(self, data: bytes) -> List[EntropyRegion]:
        """
        Analyze binary data and return all entropy regions.

        Args:
            data: Binary data to analyze

        Returns:
            List of EntropyRegion objects (both high and low entropy)
        """
        if not data:
            return []

        entropy_values = self.calculate_entropy(data)
        if not entropy_values:
            return []

        high = self._detect_high_entropy_regions(data, entropy_values)
        low = self._detect_low_entropy_regions(data, entropy_values)
        return high + low

    def detect(self, firmware_path: str) -> List[Dict]:
        """
        Detect packed or encrypted sections in firmware.
        
        Args:
            firmware_path: Path to firmware image
            
        Returns:
            List of findings
        """
        self.findings = []
        
        # Load firmware
        try:
            with open(firmware_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            self.findings.append({
                'detector': 'entropy',
                'severity': 'medium',
                'title': 'Failed to load firmware',
                'description': f'Error: {e}'
            })
            return self.findings
        
        # Calculate entropy
        entropy_values = self.calculate_entropy(data)
        
        # Analyze entropy distribution
        self._analyze_entropy_distribution(entropy_values, len(data))
        
        # Detect high-entropy regions
        high_entropy_regions = self._detect_high_entropy_regions(
            data, entropy_values
        )
        
        # Detect low-entropy regions (potential padding)
        low_entropy_regions = self._detect_low_entropy_regions(
            data, entropy_values
        )
        
        # Report findings
        self._report_high_entropy_findings(high_entropy_regions)
        self._report_low_entropy_findings(low_entropy_regions)
        
        return self.findings

    def _analyze_entropy_distribution(self, entropy_values: List[float], data_size: int):
        """Analyze overall entropy distribution."""
        if not entropy_values:
            return
        
        avg_entropy = sum(entropy_values) / len(entropy_values)
        max_entropy = max(entropy_values)
        min_entropy = min(entropy_values)
        
        # Count high-entropy windows
        high_entropy_count = sum(1 for e in entropy_values if e > self.HIGH_ENTROPY_THRESHOLD)
        high_entropy_percentage = (high_entropy_count / len(entropy_values)) * 100
        
        # Report if significant portion is high-entropy
        if high_entropy_percentage > 10:  # >10% high entropy
            self.findings.append({
                'detector': 'entropy',
                'severity': 'high',
                'title': 'High entropy content detected',
                'description': f'{high_entropy_percentage:.1f}% of firmware has high entropy',
                'details': {
                    'average_entropy': f'{avg_entropy:.2f}',
                    'max_entropy': f'{max_entropy:.2f}',
                    'min_entropy': f'{min_entropy:.2f}',
                    'high_entropy_percentage': f'{high_entropy_percentage:.1f}%',
                    'total_windows': len(entropy_values)
                },
                'recommendation': 'High entropy may indicate encrypted or packed malware'
            })

    def _detect_high_entropy_regions(
        self, 
        data: bytes, 
        entropy_values: List[float]
    ) -> List[EntropyRegion]:
        """Detect regions with suspiciously high entropy."""
        regions = []
        in_high_region = False
        region_start = 0
        
        for i, entropy in enumerate(entropy_values):
            offset = i * self.window_size
            
            if entropy > self.HIGH_ENTROPY_THRESHOLD:
                if not in_high_region:
                    # Start of new high-entropy region
                    in_high_region = True
                    region_start = offset
            else:
                if in_high_region:
                    # End of high-entropy region
                    region_size = offset - region_start
                    avg_entropy = sum(entropy_values[region_start//self.window_size:i]) / (i - region_start//self.window_size)
                    
                    regions.append(EntropyRegion(
                        offset=region_start,
                        size=region_size,
                        entropy=avg_entropy,
                        suspicious=True
                    ))
                    
                    in_high_region = False
        
        # Handle region extending to end
        if in_high_region:
            region_size = len(data) - region_start
            avg_entropy = sum(entropy_values[region_start//self.window_size:]) / len(entropy_values[region_start//self.window_size:])
            
            regions.append(EntropyRegion(
                offset=region_start,
                size=region_size,
                entropy=avg_entropy,
                suspicious=True
            ))
        
        return regions

    def _detect_low_entropy_regions(
        self,
        data: bytes,
        entropy_values: List[float]
    ) -> List[EntropyRegion]:
        """Detect regions with suspiciously low entropy (padding)."""
        regions = []
        
        for i, entropy in enumerate(entropy_values):
            if entropy < self.LOW_ENTROPY_THRESHOLD:
                offset = i * self.window_size
                
                regions.append(EntropyRegion(
                    offset=offset,
                    size=self.window_size,
                    entropy=entropy,
                    suspicious=False
                ))
        
        return regions

    def _report_high_entropy_findings(self, regions: List[EntropyRegion]):
        """Report high-entropy regions as findings."""
        # Merge adjacent regions
        merged_regions = self._merge_adjacent_regions(regions)
        
        for region in merged_regions:
            if region.size > 4096:  # Only report significant regions
                self.findings.append({
                    'detector': 'entropy',
                    'severity': 'high',
                    'title': 'Packed or encrypted code detected',
                    'description': f'High-entropy region at offset 0x{region.offset:x}',
                    'details': {
                        'offset': f'0x{region.offset:x}',
                        'size': f'{region.size} bytes',
                        'entropy': f'{region.entropy:.2f}',
                        'threshold': f'{self.HIGH_ENTROPY_THRESHOLD}'
                    },
                    'recommendation': 'Investigate for packed malware or encryption'
                })

    def _report_low_entropy_findings(self, regions: List[EntropyRegion]):
        """Report low-entropy regions (informational)."""
        total_windows = len(regions)
        low_entropy_count = sum(1 for r in regions if r.entropy < self.LOW_ENTROPY_THRESHOLD)
        
        if low_entropy_count > total_windows * 0.5:  # >50% low entropy
            total_low_entropy = low_entropy_count * self.window_size
            
            self.findings.append({
                'detector': 'entropy',
                'severity': 'low',
                'title': 'Significant padding detected',
                'description': f'{total_low_entropy} bytes of low-entropy data',
                'details': {
                    'regions': len(regions),
                    'total_size': f'{total_low_entropy} bytes'
                },
                'recommendation': 'Low entropy may indicate padding or unused space'
            })

    def _merge_adjacent_regions(self, regions: List[EntropyRegion]) -> List[EntropyRegion]:
        """Merge adjacent high-entropy regions."""
        if not regions:
            return []
        
        merged = []
        current = regions[0]
        
        for next_region in regions[1:]:
            # Check if adjacent (within 2 windows)
            if next_region.offset - (current.offset + current.size) < self.window_size * 2:
                # Merge regions
                new_size = (next_region.offset + next_region.size) - current.offset
                avg_entropy = (current.entropy + next_region.entropy) / 2
                
                current = EntropyRegion(
                    offset=current.offset,
                    size=new_size,
                    entropy=avg_entropy,
                    suspicious=True
                )
            else:
                # Not adjacent, save current and start new
                merged.append(current)
                current = next_region
        
        # Add final region
        merged.append(current)
        
        return merged

    def visualize_entropy(self, entropy_values: List[float], output_path: str):
        """
        Generate entropy visualization (ASCII art).
        
        Args:
            entropy_values: List of entropy values
            output_path: Path to save visualization
        """
        with open(output_path, 'w') as f:
            f.write("Entropy Visualization\n")
            f.write("=" * 80 + "\n\n")
            
            for i, entropy in enumerate(entropy_values):
                offset = i * self.window_size
                bar_length = int(entropy * 8)  # Scale to 0-64 chars
                bar = '#' * bar_length
                
                # Color code based on threshold
                if entropy > self.HIGH_ENTROPY_THRESHOLD:
                    marker = '!'
                elif entropy < self.LOW_ENTROPY_THRESHOLD:
                    marker = '.'
                else:
                    marker = ' '
                
                f.write(f"0x{offset:08x} [{entropy:4.2f}] {marker} {bar}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Legend: ! = High entropy, . = Low entropy\n")



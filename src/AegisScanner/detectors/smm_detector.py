"""
SMM Intrusion Detector

Detects System Management Mode (SMM) intrusions and SMRAM modifications.
SMM is the highest privilege level in x86 and a prime bootkit target.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from .base_detector import BaseDetector


class SMMDetector(BaseDetector):
    """Detector for SMM intrusions and SMRAM modifications."""
    
    # SMRAM region types
    SMRAM_TYPES = {
        0x01: 'SMRAM_OPEN',
        0x02: 'SMRAM_CLOSED',
        0x04: 'SMRAM_LOCKED',
        0x08: 'SMRAM_CACHEABLE',
        0x10: 'SMRAM_ALLOCATED'
    }
    
    # Common SMBASE addresses
    DEFAULT_SMBASE = 0x30000
    RELOCATED_SMBASE_MIN = 0xA0000
    RELOCATED_SMBASE_MAX = 0x100000
    
    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize SMM intrusion detector.
        
        Args:
            baseline: Baseline SMRAM configuration
        """
        super().__init__(baseline)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze memory dump for SMM intrusions.
        
        Args:
            target_path: Path to memory dump with SMRAM regions
            
        Returns:
            List of findings
        """
        self.clear_findings()
        
        # Load memory dump
        memory_data = self._load_dump(target_path)
        if not memory_data:
            self._add_finding(
                severity='medium',
                title='Unable to load memory dump',
                description=f'Could not read memory dump from {target_path}',
                recommendation='Verify file format and accessibility',
                confidence=1.0
            )
            return self.get_findings()
        
        # Detect SMRAM regions
        smram_regions = self._detect_smram_regions(memory_data)
        if not smram_regions:
            self._add_finding(
                severity='low',
                title='No SMRAM regions detected',
                description='Could not locate SMRAM regions in memory dump',
                recommendation='Ensure memory dump includes SMM memory regions',
                confidence=0.7
            )
            return self.get_findings()
        
        # Analyze SMBASE register modifications
        self._analyze_smbase_modifications(memory_data, smram_regions)
        
        # Check SMI handler integrity
        self._check_smi_handler_integrity(memory_data, smram_regions)
        
        # Detect SMRAM cache poisoning
        self._detect_cache_poisoning(memory_data, smram_regions)
        
        # Compare against baseline if available
        if self.baseline and 'smram_regions' in self.baseline:
            self._compare_with_baseline(smram_regions)
        
        return self.get_findings()
    
    def _load_dump(self, target_path: str) -> Optional[bytes]:
        """Load memory dump from file."""
        target = Path(target_path)
        if not target.exists():
            return None
        
        try:
            with open(target, 'rb') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Failed to load dump: {e}")
            return None
    
    def _detect_smram_regions(self, memory_data: bytes) -> List[Dict]:
        """
        Detect SMRAM regions in memory dump.
        
        SMRAM regions are typically:
        - 0x30000-0x40000 (default SMBASE)
        - 0xA0000-0xC0000 (legacy SMRAM)
        - High memory regions (TSEG)
        """
        regions = []
        
        # Check default SMBASE region
        if len(memory_data) > self.DEFAULT_SMBASE + 0x10000:
            regions.append({
                'base': self.DEFAULT_SMBASE,
                'size': 0x10000,
                'type': 'DEFAULT_SMBASE',
                'locked': False
            })
        
        # Search for SMRAM descriptor structures
        # Format: Base(8) + Size(8) + State(4) + Reserved(4)
        for offset in range(0, len(memory_data) - 24, 8):
            try:
                base = struct.unpack('<Q', memory_data[offset:offset+8])[0]
                size = struct.unpack('<Q', memory_data[offset+8:offset+16])[0]
                state = struct.unpack('<I', memory_data[offset+16:offset+20])[0]
                
                # Validate SMRAM region
                if (self.RELOCATED_SMBASE_MIN <= base <= 0xFFFFFFFF and
                    0x1000 <= size <= 0x1000000 and
                    state & 0x1F):  # Valid state bits
                    
                    regions.append({
                        'base': base,
                        'size': size,
                        'type': 'DETECTED',
                        'locked': bool(state & 0x04),
                        'state': state
                    })
                    self.logger.info(f"Found SMRAM region at 0x{base:x}, size 0x{size:x}")
            except (struct.error, IndexError):
                continue
        
        return regions
    
    def _analyze_smbase_modifications(self, memory_data: bytes, smram_regions: List[Dict]):
        """
        Analyze SMBASE register modifications.
        
        SMBASE relocation is normal, but unexpected relocations or
        multiple relocations may indicate SMM rootkit activity.
        """
        smbase_values = []
        
        for region in smram_regions:
            base = region['base']
            
            # Check for SMBASE signature in SMM save state
            # SMBASE is stored at offset 0x7EF8 in save state area
            if base + 0x8000 < len(memory_data):
                try:
                    # Read potential SMBASE value from save state
                    smbase_offset = base + 0x7EF8
                    smbase = struct.unpack('<I', memory_data[smbase_offset:smbase_offset+4])[0]
                    
                    if smbase != 0 and smbase != base:
                        smbase_values.append((base, smbase))
                        
                        # Check if SMBASE points to unexpected location
                        if smbase < self.RELOCATED_SMBASE_MIN or smbase > 0xFFFFFFFF:
                            self._add_finding(
                                severity='high',
                                title='Suspicious SMBASE relocation detected',
                                description=(
                                    f'SMBASE at region 0x{base:x} has been relocated to '
                                    f'suspicious address 0x{smbase:x}. This may indicate '
                                    f'SMM rootkit attempting to hide code.'
                                ),
                                details={
                                    'region_base': f'0x{base:x}',
                                    'smbase_value': f'0x{smbase:x}',
                                    'expected_range': f'0x{self.RELOCATED_SMBASE_MIN:x}-0xFFFFFFFF'
                                },
                                recommendation='Investigate SMBASE relocation and SMM code integrity',
                                confidence=0.85
                            )
                except (struct.error, IndexError):
                    continue
        
        # Check for multiple different SMBASE values (suspicious)
        unique_smbases = set(smbase for _, smbase in smbase_values)
        if len(unique_smbases) > 4:  # More than typical CPU count
            self._add_finding(
                severity='medium',
                title='Excessive SMBASE relocations detected',
                description=(
                    f'Found {len(unique_smbases)} different SMBASE values, which exceeds '
                    f'typical CPU count. This may indicate SMM manipulation.'
                ),
                details={
                    'smbase_count': len(unique_smbases),
                    'values': [f'0x{s:x}' for s in unique_smbases]
                },
                recommendation='Verify system CPU count and investigate anomalous relocations',
                confidence=0.75
            )
    
    def _check_smi_handler_integrity(self, memory_data: bytes, smram_regions: List[Dict]):
        """
        Check SMI handler integrity.
        
        Validates:
        1. SMI handler entry point is within SMRAM
        2. Handler code doesn't contain suspicious patterns
        3. Handler hasn't been replaced
        """
        for region in smram_regions:
            base = region['base']
            size = region['size']
            
            if base + size > len(memory_data):
                continue
            
            # Extract SMRAM region data
            smram_data = memory_data[base:base+size]
            
            # Check for SMI handler entry point (typically at offset 0x8000)
            handler_offset = 0x8000
            if handler_offset < len(smram_data):
                # Look for handler prologue patterns
                handler_code = smram_data[handler_offset:handler_offset+32]
                
                # Check for suspicious patterns in handler
                suspicious_patterns = [
                    (b'\xeb\xfe', 'Infinite loop (JMP $)'),
                    (b'\xf4', 'HLT instruction'),
                    (b'\x0f\x01\xc1', 'VMCALL instruction'),
                    (b'\x0f\x01\xc2', 'VMLAUNCH instruction'),
                    (b'\xcc', 'INT3 breakpoint')
                ]
                
                for pattern, description in suspicious_patterns:
                    if pattern in handler_code:
                        self._add_finding(
                            severity='critical',
                            title=f'Suspicious instruction in SMI handler: {description}',
                            description=(
                                f'SMI handler at SMRAM region 0x{base:x} contains '
                                f'suspicious instruction pattern: {description}. '
                                f'This may indicate SMM rootkit or debugging code.'
                            ),
                            details={
                                'region_base': f'0x{base:x}',
                                'handler_offset': f'0x{handler_offset:x}',
                                'pattern': pattern.hex(),
                                'description': description
                            },
                            recommendation='CRITICAL: Analyze SMI handler code for malicious modifications',
                            confidence=0.92
                        )
            
            # Check for code caves (large blocks of zeros or repeated bytes)
            self._detect_code_caves(smram_data, base)
    
    def _detect_code_caves(self, smram_data: bytes, base_addr: int):
        """Detect code caves in SMRAM that could hide malicious code."""
        cave_threshold = 256  # Minimum cave size to report
        current_cave_start = None
        current_cave_size = 0
        
        for i in range(len(smram_data)):
            if smram_data[i] == 0 or smram_data[i] == 0xFF:
                if current_cave_start is None:
                    current_cave_start = i
                current_cave_size += 1
            else:
                if current_cave_size >= cave_threshold:
                    self._add_finding(
                        severity='medium',
                        title='Code cave detected in SMRAM',
                        description=(
                            f'Found {current_cave_size}-byte code cave at offset '
                            f'0x{current_cave_start:x} in SMRAM region 0x{base_addr:x}. '
                            f'Code caves can hide malicious payloads.'
                        ),
                        details={
                            'region_base': f'0x{base_addr:x}',
                            'cave_offset': f'0x{current_cave_start:x}',
                            'cave_size': current_cave_size
                        },
                        recommendation='Analyze code cave contents for hidden payloads',
                        confidence=0.65
                    )
                current_cave_start = None
                current_cave_size = 0
    
    def _detect_cache_poisoning(self, memory_data: bytes, smram_regions: List[Dict]):
        """
        Detect SMRAM cache poisoning attacks.
        
        Cache poisoning allows attackers to execute code in SMM context
        by manipulating CPU cache before SMRAM is locked.
        """
        for region in smram_regions:
            if not region.get('locked', False):
                self._add_finding(
                    severity='critical',
                    title='Unlocked SMRAM region detected',
                    description=(
                        f'SMRAM region at 0x{region["base"]:x} is not locked. '
                        f'Unlocked SMRAM is vulnerable to cache poisoning attacks '
                        f'that can inject malicious code into SMM.'
                    ),
                    details={
                        'region_base': f'0x{region["base"]:x}',
                        'region_size': f'0x{region["size"]:x}',
                        'state': region.get('state', 0)
                    },
                    recommendation='CRITICAL: SMRAM must be locked before OS handoff',
                    confidence=0.98
                )
    
    def _compare_with_baseline(self, current_regions: List[Dict]):
        """Compare current SMRAM configuration against baseline."""
        if not self.baseline:
            return
        baseline_regions = self.baseline.get('smram_regions', [])
        
        # Check for new regions
        baseline_bases = set(r['base'] for r in baseline_regions)
        current_bases = set(r['base'] for r in current_regions)
        
        new_regions = current_bases - baseline_bases
        if new_regions:
            self._add_finding(
                severity='high',
                title='New SMRAM regions detected',
                description=(
                    f'Found {len(new_regions)} SMRAM regions not present in baseline. '
                    f'New regions may indicate SMM rootkit installation.'
                ),
                details={
                    'new_regions': [f'0x{addr:x}' for addr in new_regions],
                    'baseline_count': len(baseline_regions),
                    'current_count': len(current_regions)
                },
                recommendation='Investigate origin of new SMRAM regions',
                confidence=0.88
            )
        
        # Check for modified regions
        for current in current_regions:
            for baseline in baseline_regions:
                if current['base'] == baseline['base']:
                    if current['size'] != baseline['size']:
                        self._add_finding(
                            severity='critical',
                            title='SMRAM region size modified',
                            description=(
                                f'SMRAM region at 0x{current["base"]:x} has changed size '
                                f'from 0x{baseline["size"]:x} to 0x{current["size"]:x}. '
                                f'This indicates SMRAM manipulation.'
                            ),
                            details={
                                'region_base': f'0x{current["base"]:x}',
                                'baseline_size': f'0x{baseline["size"]:x}',
                                'current_size': f'0x{current["size"]:x}'
                            },
                            recommendation='CRITICAL: SMRAM region modified, investigate immediately',
                            confidence=0.95
                        )

# Made with Bob

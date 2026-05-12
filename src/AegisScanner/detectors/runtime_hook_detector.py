"""
Runtime Services Hook Detector

Detects modifications to UEFI Runtime Services table pointers.
Runtime Services survive OS transition and are prime bootkit targets.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import logging
from typing import Dict, List, Optional
from pathlib import Path
from .base_detector import BaseDetector


class RuntimeHookDetector(BaseDetector):
    """Detector for Runtime Services table hook modifications."""
    
    # Runtime Services function offsets (from EFI_RUNTIME_SERVICES structure)
    RT_SERVICES = {
        'GetTime': 0x18,
        'SetTime': 0x20,
        'GetWakeupTime': 0x28,
        'SetWakeupTime': 0x30,
        'SetVirtualAddressMap': 0x38,
        'ConvertPointer': 0x40,
        'GetVariable': 0x48,
        'GetNextVariableName': 0x50,
        'SetVariable': 0x58,
        'GetNextHighMonotonicCount': 0x60,
        'ResetSystem': 0x68,
        'UpdateCapsule': 0x70,
        'QueryCapsuleCapabilities': 0x78,
        'QueryVariableInfo': 0x80
    }
    
    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize Runtime Services hook detector.
        
        Args:
            baseline: Baseline RT table configuration
        """
        super().__init__(baseline)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze memory dump for Runtime Services table hooks.
        
        Args:
            target_path: Path to memory dump or RT table dump
            
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
        
        # Find Runtime Services table
        rt_table_addr = self._find_rt_table(memory_data)
        if not rt_table_addr:
            self._add_finding(
                severity='low',
                title='Runtime Services table not found',
                description='Could not locate RT table in memory dump',
                recommendation='Ensure memory dump includes UEFI runtime regions',
                confidence=0.8
            )
            return self.get_findings()
        
        # Validate RT table CRC32
        self._validate_rt_crc32(memory_data, rt_table_addr)
        
        # Check for pointer modifications
        self._check_pointer_modifications(memory_data, rt_table_addr)
        
        # Compare against baseline if available
        if self.baseline and 'rt_table' in self.baseline:
            self._compare_with_baseline(memory_data, rt_table_addr)
        
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
    
    def _find_rt_table(self, memory_data: bytes) -> Optional[int]:
        """
        Find Runtime Services table in memory.
        
        Searches for EFI_RUNTIME_SERVICES signature:
        - Signature: 0x56524553 ('RUNTSERV' in little-endian)
        - Followed by revision and header size
        """
        # EFI_RUNTIME_SERVICES signature
        signature = struct.pack('<Q', 0x56524553544E5552)  # 'RUNTSERV'
        
        offset = memory_data.find(signature)
        if offset != -1:
            self.logger.info(f"Found RT table at offset 0x{offset:x}")
            return offset
        
        # Try alternative search by structure pattern
        # Look for valid header size (0x58 or 0x88 depending on version)
        for offset in range(0, len(memory_data) - 0x100, 8):
            try:
                # Check if this looks like RT table header
                hdr_size = struct.unpack('<I', memory_data[offset+8:offset+12])[0]
                if hdr_size in [0x58, 0x88]:
                    # Validate CRC32 field exists
                    crc32 = struct.unpack('<I', memory_data[offset+12:offset+16])[0]
                    if crc32 != 0:  # CRC32 should be non-zero
                        self.logger.info(f"Found potential RT table at 0x{offset:x}")
                        return offset
            except (struct.error, IndexError):
                continue
        
        return None
    
    def _validate_rt_crc32(self, memory_data: bytes, rt_addr: int):
        """
        Validate Runtime Services table CRC32.
        
        The CRC32 field should match calculated CRC over the table.
        Mismatches indicate tampering.
        """
        try:
            # Read header size
            hdr_size = struct.unpack('<I', memory_data[rt_addr+8:rt_addr+12])[0]
            
            # Read stored CRC32
            stored_crc = struct.unpack('<I', memory_data[rt_addr+12:rt_addr+16])[0]
            
            # Calculate CRC32 (simplified - real implementation would use zlib.crc32)
            # For now, just check if CRC field is zero (indicates tampering)
            if stored_crc == 0:
                self._add_finding(
                    severity='high',
                    title='Runtime Services table CRC32 is zero',
                    description=(
                        f'RT table at 0x{rt_addr:x} has CRC32 = 0, indicating '
                        f'the table has been modified without updating the checksum.'
                    ),
                    details={
                        'address': f'0x{rt_addr:x}',
                        'stored_crc': f'0x{stored_crc:08x}',
                        'header_size': hdr_size
                    },
                    recommendation='Investigate RT table modifications',
                    confidence=0.90
                )
        except (struct.error, IndexError) as e:
            self.logger.warning(f"Failed to validate CRC32: {e}")
    
    def _check_pointer_modifications(self, memory_data: bytes, rt_addr: int):
        """
        Check for suspicious pointer modifications in RT table.
        
        Detects:
        1. Pointers outside expected memory ranges
        2. Pointers to unusual memory regions
        3. Multiple pointers to same address (hook consolidation)
        """
        pointers = {}
        
        for service_name, offset in self.RT_SERVICES.items():
            try:
                ptr_addr = rt_addr + offset
                if ptr_addr + 8 > len(memory_data):
                    continue
                
                ptr_value = struct.unpack('<Q', memory_data[ptr_addr:ptr_addr+8])[0]
                pointers[service_name] = ptr_value
                
                # Check for suspicious pointer values
                if ptr_value == 0:
                    self._add_finding(
                        severity='medium',
                        title=f'{service_name} pointer is NULL',
                        description=(
                            f'Runtime Service {service_name} has NULL pointer at '
                            f'offset 0x{offset:x}. This may indicate hook removal or corruption.'
                        ),
                        details={
                            'service': service_name,
                            'offset': f'0x{offset:x}',
                            'pointer': f'0x{ptr_value:016x}'
                        },
                        recommendation='Verify RT table integrity',
                        confidence=0.75
                    )
                elif ptr_value < 0x1000:
                    # Pointer in low memory (suspicious)
                    self._add_finding(
                        severity='high',
                        title=f'{service_name} pointer in low memory',
                        description=(
                            f'Runtime Service {service_name} points to low memory '
                            f'address 0x{ptr_value:x}, which is highly suspicious.'
                        ),
                        details={
                            'service': service_name,
                            'offset': f'0x{offset:x}',
                            'pointer': f'0x{ptr_value:016x}'
                        },
                        recommendation='Investigate potential hook or corruption',
                        confidence=0.95
                    )
                elif ptr_value > 0xFFFFFFFF00000000:
                    # Pointer in kernel space (expected for some services)
                    pass
                
            except (struct.error, IndexError) as e:
                self.logger.warning(f"Failed to read {service_name} pointer: {e}")
        
        # Check for pointer consolidation (multiple services pointing to same address)
        pointer_counts = {}
        for service, ptr in pointers.items():
            if ptr != 0:
                if ptr not in pointer_counts:
                    pointer_counts[ptr] = []
                pointer_counts[ptr].append(service)
        
        for ptr, services in pointer_counts.items():
            if len(services) > 1:
                self._add_finding(
                    severity='high',
                    title='Multiple RT services point to same address',
                    description=(
                        f'Services {", ".join(services)} all point to address '
                        f'0x{ptr:016x}. This may indicate hook consolidation.'
                    ),
                    details={
                        'address': f'0x{ptr:016x}',
                        'services': services,
                        'count': len(services)
                    },
                    recommendation='Analyze code at target address for hook dispatcher',
                    confidence=0.88
                )
    
    def _compare_with_baseline(self, memory_data: bytes, rt_addr: int):
        """Compare RT table against baseline configuration."""
        if not self.baseline:
            return
        baseline_rt = self.baseline.get('rt_table', {})
        
        for service_name, offset in self.RT_SERVICES.items():
            try:
                ptr_addr = rt_addr + offset
                if ptr_addr + 8 > len(memory_data):
                    continue
                
                current_ptr = struct.unpack('<Q', memory_data[ptr_addr:ptr_addr+8])[0]
                baseline_ptr = baseline_rt.get(service_name, 0)
                
                if baseline_ptr != 0 and current_ptr != baseline_ptr:
                    self._add_finding(
                        severity='critical',
                        title=f'{service_name} pointer modified from baseline',
                        description=(
                            f'Runtime Service {service_name} pointer has changed from '
                            f'baseline value 0x{baseline_ptr:016x} to 0x{current_ptr:016x}. '
                            f'This indicates a hook installation.'
                        ),
                        details={
                            'service': service_name,
                            'baseline_pointer': f'0x{baseline_ptr:016x}',
                            'current_pointer': f'0x{current_ptr:016x}',
                            'offset': f'0x{offset:x}'
                        },
                        recommendation='CRITICAL: Runtime Services hook detected. Investigate immediately.',
                        confidence=0.98
                    )
            except (struct.error, IndexError) as e:
                self.logger.warning(f"Failed to compare {service_name}: {e}")



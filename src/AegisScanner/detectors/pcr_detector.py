"""
PCR Detector - TPM Platform Configuration Register Analysis

Detects bootkit artifacts by analyzing PCR values and comparing against
known-good baselines. Focuses on PCR 0-7 which measure firmware components.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import struct
from typing import Dict, List, Optional
from pathlib import Path


class PCRDetector:
    """Detector for TPM PCR anomalies indicating bootkit presence."""

    # PCR indices and their meanings
    PCR_DESCRIPTIONS = {
        0: "BIOS/UEFI firmware code",
        1: "BIOS/UEFI firmware configuration",
        2: "Option ROM code",
        3: "Option ROM configuration",
        4: "MBR/GPT code",
        5: "MBR/GPT configuration",
        6: "State transitions and wake events",
        7: "Secure Boot policy"
    }

    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize PCR detector.

        Args:
            baseline: Baseline PCR values for comparison
        """
        self.baseline = baseline
        self.findings = []

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze PCR values for anomalies.

        Args:
            target_path: Path to PCR dump or firmware image

        Returns:
            List of findings
        """
        self.findings = []

        # Load PCR values from target
        pcr_values = self._load_pcr_values(target_path)
        
        if not pcr_values:
            self.findings.append({
                'detector': 'pcr',
                'severity': 'medium',
                'title': 'Unable to extract PCR values',
                'description': f'Could not read PCR values from {target_path}',
                'recommendation': 'Verify target file format and TPM availability'
            })
            return self.findings

        # Check each PCR
        for pcr_index in range(8):
            if pcr_index in pcr_values:
                self._analyze_pcr(pcr_index, pcr_values[pcr_index])

        # Check for PCR extension anomalies
        self._check_extension_patterns(pcr_values)

        # Check for known bootkit signatures
        self._check_known_signatures(pcr_values)

        return self.findings

    def _load_pcr_values(self, target_path: str) -> Dict[int, bytes]:
        """
        Load PCR values from target file.

        Args:
            target_path: Path to PCR dump

        Returns:
            Dictionary mapping PCR index to value
        """
        pcr_values = {}
        target = Path(target_path)

        if not target.exists():
            return pcr_values

        try:
            # Try to parse as binary PCR dump
            with open(target, 'rb') as f:
                data = f.read()
                
                # Expected format: 8 PCRs × 32 bytes (SHA256)
                if len(data) >= 256:
                    for i in range(8):
                        offset = i * 32
                        pcr_values[i] = data[offset:offset + 32]
                else:
                    # Try to extract from firmware image
                    pcr_values = self._extract_from_firmware(data)

        except Exception as e:
            print(f"[WARNING] Failed to load PCR values: {e}")

        return pcr_values

    def _extract_from_firmware(self, firmware_data: bytes) -> Dict[int, bytes]:
        """
        Extract PCR values from firmware image.

        Args:
            firmware_data: Raw firmware data

        Returns:
            Dictionary of PCR values
        """
        # Simulate PCR calculation from firmware components
        pcr_values = {}
        
        # PCR 0: Hash of firmware code sections
        pcr_values[0] = hashlib.sha256(firmware_data[:0x10000]).digest()
        
        # PCR 1: Hash of firmware configuration
        pcr_values[1] = hashlib.sha256(firmware_data[0x10000:0x20000]).digest()
        
        # Initialize remaining PCRs with zeros (would be measured during boot)
        for i in range(2, 8):
            pcr_values[i] = b'\x00' * 32

        return pcr_values

    def _analyze_pcr(self, pcr_index: int, pcr_value: bytes):
        """
        Analyze individual PCR for anomalies.

        Args:
            pcr_index: PCR index (0-7)
            pcr_value: PCR value (32 bytes)
        """
        # Check against baseline
        if self.baseline and 'pcr_values' in self.baseline:
            baseline_value = self.baseline['pcr_values'].get(str(pcr_index))
            
            if baseline_value:
                baseline_bytes = bytes.fromhex(baseline_value)
                
                if pcr_value != baseline_bytes:
                    self.findings.append({
                        'detector': 'pcr',
                        'severity': 'high',
                        'title': f'PCR {pcr_index} mismatch detected',
                        'description': f'PCR {pcr_index} ({self.PCR_DESCRIPTIONS[pcr_index]}) '
                                     f'does not match baseline. This may indicate firmware tampering.',
                        'details': {
                            'pcr_index': pcr_index,
                            'expected': baseline_value,
                            'actual': pcr_value.hex(),
                            'component': self.PCR_DESCRIPTIONS[pcr_index]
                        },
                        'recommendation': 'Investigate firmware modifications and verify boot chain integrity'
                    })

        # Check for suspicious patterns
        if pcr_value == b'\x00' * 32:
            self.findings.append({
                'detector': 'pcr',
                'severity': 'medium',
                'title': f'PCR {pcr_index} is all zeros',
                'description': f'PCR {pcr_index} contains all zeros, which may indicate '
                             'TPM not properly initialized or measurements not performed.',
                'details': {
                    'pcr_index': pcr_index,
                    'value': pcr_value.hex()
                },
                'recommendation': 'Verify TPM initialization and Measured Boot configuration'
            })

        if pcr_value == b'\xff' * 32:
            self.findings.append({
                'detector': 'pcr',
                'severity': 'high',
                'title': f'PCR {pcr_index} is all ones',
                'description': f'PCR {pcr_index} contains all ones, which is highly suspicious '
                             'and may indicate TPM manipulation.',
                'details': {
                    'pcr_index': pcr_index,
                    'value': pcr_value.hex()
                },
                'recommendation': 'Investigate potential TPM tampering or emulation'
            })

    def _check_extension_patterns(self, pcr_values: Dict[int, bytes]):
        """
        Check for suspicious PCR extension patterns.

        Args:
            pcr_values: Dictionary of PCR values
        """
        # Check if PCR 0-3 are identical (suspicious)
        if len(pcr_values) >= 4:
            if (pcr_values[0] == pcr_values[1] == pcr_values[2] == pcr_values[3]):
                self.findings.append({
                    'detector': 'pcr',
                    'severity': 'high',
                    'title': 'Identical PCR values detected',
                    'description': 'PCR 0-3 have identical values, which is highly unusual '
                                 'and may indicate PCR replay attack or bootkit manipulation.',
                    'recommendation': 'Investigate boot measurement process and verify TPM authenticity'
                })

        # Check for sequential patterns (indicates possible forgery)
        for i in range(len(pcr_values) - 1):
            if i in pcr_values and (i + 1) in pcr_values:
                val1 = int.from_bytes(pcr_values[i][:4], 'big')
                val2 = int.from_bytes(pcr_values[i + 1][:4], 'big')
                
                if abs(val2 - val1) == 1:
                    self.findings.append({
                        'detector': 'pcr',
                        'severity': 'medium',
                        'title': f'Sequential pattern in PCR {i}-{i+1}',
                        'description': f'PCR {i} and {i+1} show sequential pattern, '
                                     'which may indicate synthetic values.',
                        'recommendation': 'Verify measurement authenticity'
                    })

    def _check_known_signatures(self, pcr_values: Dict[int, bytes]):
        """
        Check for known bootkit PCR signatures.

        Args:
            pcr_values: Dictionary of PCR values
        """
        # Known bootkit signatures (examples)
        known_signatures = {
            'aegis_test': {
                'pcr': 0,
                'pattern': b'\xae\x61\x59',  # "aegis" in hex
                'description': 'Aegis-Boot test bootkit signature'
            }
        }

        for sig_name, sig_info in known_signatures.items():
            pcr_idx = sig_info['pcr']
            if pcr_idx in pcr_values:
                if sig_info['pattern'] in pcr_values[pcr_idx]:
                    self.findings.append({
                        'detector': 'pcr',
                        'severity': 'critical',
                        'title': f'Known bootkit signature detected: {sig_name}',
                        'description': f'PCR {pcr_idx} contains signature matching {sig_info["description"]}',
                        'details': {
                            'signature': sig_name,
                            'pcr_index': pcr_idx,
                            'pattern': sig_info['pattern'].hex()
                        },
                        'recommendation': 'System is infected with known bootkit. Immediate remediation required.'
                    })

# Made with Bob

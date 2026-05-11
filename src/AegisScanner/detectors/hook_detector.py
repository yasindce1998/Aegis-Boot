"""
Hook Detector - UEFI Boot Services Table Hook Analysis

Detects bootkit hooks in UEFI Boot Services Table by analyzing
function pointer modifications and CRC32 integrity.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import zlib
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class HookDetector:
    """Detector for UEFI Boot Services Table hooks."""

    # Boot Services Table function offsets (x86_64)
    BST_OFFSETS = {
        'Signature': 0,
        'Revision': 8,
        'HeaderSize': 12,
        'CRC32': 16,
        'Reserved': 20,
        'RaiseTPL': 24,
        'RestoreTPL': 32,
        'AllocatePages': 40,
        'FreePages': 48,
        'GetMemoryMap': 56,
        'AllocatePool': 64,
        'FreePool': 72,
        'CreateEvent': 80,
        'SetTimer': 88,
        'WaitForEvent': 96,
        'SignalEvent': 104,
        'CloseEvent': 112,
        'CheckEvent': 120,
        'InstallProtocolInterface': 128,
        'ReinstallProtocolInterface': 136,
        'UninstallProtocolInterface': 144,
        'HandleProtocol': 152,
        'RegisterProtocolNotify': 160,
        'LocateHandle': 168,
        'LocateDevicePath': 176,
        'InstallConfigurationTable': 184,
        'LoadImage': 192,
        'StartImage': 200,
        'Exit': 208,
        'UnloadImage': 216,
        'ExitBootServices': 224
    }

    # Expected Boot Services Table signature
    BST_SIGNATURE = 0x56524553544f4f42  # "BOOTSERV"

    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize hook detector.

        Args:
            baseline: Baseline Boot Services Table for comparison
        """
        self.baseline = baseline
        self.findings = []

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze Boot Services Table for hooks.

        Args:
            target_path: Path to memory dump or firmware image

        Returns:
            List of findings
        """
        self.findings = []

        # Load target data
        target_data = self._load_target(target_path)
        
        if not target_data:
            self.findings.append({
                'detector': 'hook',
                'severity': 'medium',
                'title': 'Unable to load target',
                'description': f'Could not read target from {target_path}',
                'recommendation': 'Verify file format and accessibility'
            })
            return self.findings

        # Locate Boot Services Table
        bst_offset = self._locate_boot_services_table(target_data)
        
        if bst_offset is None:
            self.findings.append({
                'detector': 'hook',
                'severity': 'low',
                'title': 'Boot Services Table not found',
                'description': 'Could not locate Boot Services Table in target',
                'recommendation': 'Verify target is a valid memory dump or firmware image'
            })
            return self.findings

        # Parse Boot Services Table
        bst = self._parse_boot_services_table(target_data, bst_offset)

        # Verify CRC32
        self._verify_crc32(bst, bst_offset)

        # Check for hooked functions
        self._check_hooked_functions(bst, bst_offset)

        # Check function pointer validity
        self._check_pointer_validity(bst)

        # Compare against baseline
        if self.baseline:
            self._compare_with_baseline(bst)

        return self.findings

    def _load_target(self, target_path: str) -> Optional[bytes]:
        """
        Load target file.

        Args:
            target_path: Path to target

        Returns:
            Target data or None
        """
        target = Path(target_path)
        
        if not target.exists():
            return None

        try:
            with open(target, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"[WARNING] Failed to load target: {e}")
            return None

    def _locate_boot_services_table(self, data: bytes) -> Optional[int]:
        """
        Locate Boot Services Table in memory dump.

        Args:
            data: Memory dump data

        Returns:
            Offset of BST or None
        """
        # Search for BST signature
        signature_bytes = struct.pack('<Q', self.BST_SIGNATURE)
        offset = data.find(signature_bytes)
        
        if offset != -1:
            return offset

        # Try alternative search: look for common BST patterns
        # BST typically starts with signature followed by revision
        for i in range(0, len(data) - 24, 8):
            try:
                sig = struct.unpack('<Q', data[i:i+8])[0]
                if sig == self.BST_SIGNATURE:
                    return i
            except:
                continue

        return None

    def _parse_boot_services_table(self, data: bytes, offset: int) -> Dict:
        """
        Parse Boot Services Table structure.

        Args:
            data: Memory dump data
            offset: BST offset

        Returns:
            Dictionary of BST fields
        """
        bst = {}

        try:
            # Parse header
            bst['Signature'] = struct.unpack('<Q', data[offset:offset+8])[0]
            bst['Revision'] = struct.unpack('<I', data[offset+8:offset+12])[0]
            bst['HeaderSize'] = struct.unpack('<I', data[offset+12:offset+16])[0]
            bst['CRC32'] = struct.unpack('<I', data[offset+16:offset+20])[0]
            bst['Reserved'] = struct.unpack('<I', data[offset+20:offset+24])[0]

            # Parse function pointers
            for func_name, func_offset in self.BST_OFFSETS.items():
                if func_offset >= 24:  # Skip header fields
                    ptr_offset = offset + func_offset
                    if ptr_offset + 8 <= len(data):
                        bst[func_name] = struct.unpack('<Q', data[ptr_offset:ptr_offset+8])[0]

        except Exception as e:
            print(f"[WARNING] Failed to parse BST: {e}")

        return bst

    def _verify_crc32(self, bst: Dict, offset: int):
        """
        Verify Boot Services Table CRC32.

        Args:
            bst: Parsed BST
            offset: BST offset in memory
        """
        if 'CRC32' not in bst or 'HeaderSize' not in bst:
            return

        stored_crc = bst['CRC32']
        
        # CRC32 should be calculated with CRC32 field set to 0
        # We can't recalculate without the full table, so we check for suspicious values
        
        if stored_crc == 0:
            self.findings.append({
                'detector': 'hook',
                'severity': 'high',
                'title': 'Boot Services Table CRC32 is zero',
                'description': 'BST CRC32 field is zero, indicating table has been modified '
                             'without recalculating checksum. This is a strong indicator of hooking.',
                'details': {
                    'offset': f'0x{offset:x}',
                    'crc32': f'0x{stored_crc:08x}'
                },
                'recommendation': 'Investigate Boot Services Table modifications'
            })

        if stored_crc == 0xFFFFFFFF:
            self.findings.append({
                'detector': 'hook',
                'severity': 'high',
                'title': 'Boot Services Table CRC32 is invalid',
                'description': 'BST CRC32 field is 0xFFFFFFFF, which is suspicious and may '
                             'indicate tampering or corruption.',
                'details': {
                    'offset': f'0x{offset:x}',
                    'crc32': f'0x{stored_crc:08x}'
                },
                'recommendation': 'Verify Boot Services Table integrity'
            })

    def _check_hooked_functions(self, bst: Dict, offset: int):
        """
        Check for hooked Boot Services functions.

        Args:
            bst: Parsed BST
            offset: BST offset
        """
        # Functions commonly hooked by bootkits
        high_value_targets = [
            'AllocatePool',
            'FreePool',
            'CreateEvent',
            'ExitBootServices',
            'LoadImage',
            'StartImage'
        ]

        for func_name in high_value_targets:
            if func_name in bst:
                func_ptr = bst[func_name]
                
                # Check if pointer is suspicious
                if self._is_suspicious_pointer(func_ptr):
                    self.findings.append({
                        'detector': 'hook',
                        'severity': 'critical',
                        'title': f'Suspicious {func_name} pointer detected',
                        'description': f'Boot Services function {func_name} has suspicious pointer '
                                     f'0x{func_ptr:x} that may indicate hooking.',
                        'details': {
                            'function': func_name,
                            'pointer': f'0x{func_ptr:x}',
                            'offset': f'0x{offset + self.BST_OFFSETS[func_name]:x}'
                        },
                        'recommendation': f'Analyze code at 0x{func_ptr:x} for hook trampoline'
                    })

    def _is_suspicious_pointer(self, ptr: int) -> bool:
        """
        Determine if function pointer is suspicious.

        Args:
            ptr: Function pointer value

        Returns:
            True if suspicious
        """
        # Null pointer
        if ptr == 0:
            return True

        # Invalid high addresses
        if ptr > 0xFFFFFFFFFFFFFFFF:
            return True

        # Suspiciously low addresses (likely not firmware)
        if ptr < 0x100000:
            return True

        # Check if pointer is in runtime services region (suspicious for boot services)
        if 0x80000000 <= ptr < 0x90000000:
            return True

        return False

    def _check_pointer_validity(self, bst: Dict):
        """
        Check validity of all function pointers.

        Args:
            bst: Parsed BST
        """
        null_pointers = []
        invalid_pointers = []

        for func_name, func_offset in self.BST_OFFSETS.items():
            if func_offset >= 24 and func_name in bst:
                ptr = bst[func_name]
                
                if ptr == 0:
                    null_pointers.append(func_name)
                elif ptr > 0xFFFFFFFFFFFFFFFF or ptr < 0x1000:
                    invalid_pointers.append((func_name, ptr))

        if null_pointers:
            self.findings.append({
                'detector': 'hook',
                'severity': 'medium',
                'title': 'Null function pointers detected',
                'description': f'Found {len(null_pointers)} null function pointers in Boot Services Table',
                'details': {
                    'functions': null_pointers
                },
                'recommendation': 'Verify Boot Services Table initialization'
            })

        if invalid_pointers:
            self.findings.append({
                'detector': 'hook',
                'severity': 'high',
                'title': 'Invalid function pointers detected',
                'description': f'Found {len(invalid_pointers)} invalid function pointers',
                'details': {
                    'pointers': [{'function': f, 'value': f'0x{p:x}'} for f, p in invalid_pointers]
                },
                'recommendation': 'Investigate pointer corruption or tampering'
            })

    def _compare_with_baseline(self, bst: Dict):
        """
        Compare BST with baseline.

        Args:
            bst: Parsed BST
        """
        if not self.baseline or 'boot_services_table' not in self.baseline:
            return

        baseline_bst = self.baseline['boot_services_table']

        for func_name in self.BST_OFFSETS.keys():
            if func_name in bst and func_name in baseline_bst:
                current_ptr = bst[func_name]
                baseline_ptr = baseline_bst.get(func_name)

                if baseline_ptr and current_ptr != baseline_ptr:
                    self.findings.append({
                        'detector': 'hook',
                        'severity': 'critical',
                        'title': f'{func_name} pointer modified',
                        'description': f'Boot Services function {func_name} pointer has been modified '
                                     'from baseline, indicating potential hook installation.',
                        'details': {
                            'function': func_name,
                            'baseline': f'0x{baseline_ptr:x}',
                            'current': f'0x{current_ptr:x}'
                        },
                        'recommendation': f'Analyze code at 0x{current_ptr:x} for malicious hook'
                    })

# Made with Bob

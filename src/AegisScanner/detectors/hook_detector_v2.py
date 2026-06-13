"""
Hook Detector V2 - Enhanced UEFI Boot Services Table Hook Analysis

Implements FV-based pointer validation and trampoline pattern detection
to eliminate false positives on real hardware.

Improvements:
- #7: Dynamic FV range detection instead of hardcoded address ranges
- #8: 14-byte trampoline pattern detection (MOV RAX, imm64; JMP RAX)

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import zlib
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
from dataclasses import dataclass


@dataclass
class FirmwareVolume:
    """Represents a UEFI Firmware Volume."""
    base_address: int
    size: int
    guid: bytes
    
    def contains(self, address: int) -> bool:
        """Check if address is within this FV."""
        return self.base_address <= address < (self.base_address + self.size)


@dataclass
class TrampolinePattern:
    """Represents a detected hook trampoline."""
    address: int
    target: int
    pattern_type: str  # "mov_rax_jmp", "jmp_indirect", etc.
    confidence: float  # 0.0 to 1.0


class HookDetectorV2:
    """Enhanced detector for UEFI Boot Services Table hooks with FV validation."""

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
        'ExitBootServices': 224,
        'SetVariable': 232  # Runtime Services, but often hooked
    }

    # Expected Boot Services Table signature
    BST_SIGNATURE = 0x56524553544f4f42  # "BOOTSERV"
    
    # UEFI Firmware Volume signature
    FV_SIGNATURE = b'_FVH'
    
    # Trampoline patterns (x86_64)
    TRAMPOLINE_PATTERNS = {
        # MOV RAX, imm64; JMP RAX (14 bytes)
        'mov_rax_jmp': {
            'pattern': [0x48, 0xB8],  # MOV RAX, imm64
            'jmp_offset': 10,
            'jmp_opcode': [0xFF, 0xE0],  # JMP RAX
            'size': 12,
            'confidence': 0.95
        },
        # JMP [RIP+offset] (6 bytes)
        'jmp_rip_indirect': {
            'pattern': [0xFF, 0x25],  # JMP [RIP+offset]
            'size': 6,
            'confidence': 0.85
        },
        # PUSH addr; RET (10 bytes)
        'push_ret': {
            'pattern': [0x68],  # PUSH imm32
            'ret_offset': 5,
            'ret_opcode': [0xC3],  # RET
            'size': 6,
            'confidence': 0.80
        }
    }

    def __init__(self, baseline: Optional[Dict] = None, strict_mode: bool = False):
        """
        Initialize enhanced hook detector.

        Args:
            baseline: Baseline Boot Services Table for comparison
            strict_mode: If True, flag any pointer outside FV as suspicious
        """
        self.baseline = baseline
        self.strict_mode = strict_mode
        self.findings = []
        self.firmware_volumes: List[FirmwareVolume] = []
        self.scanned_regions: Set[int] = set()

    def detect(self, target_path: str, fv_ranges: Optional[List[Tuple[int, int]]] = None) -> List[Dict]:
        """
        Analyze Boot Services Table for hooks with FV-based validation.

        Args:
            target_path: Path to memory dump or firmware image
            fv_ranges: Optional list of (base, size) tuples for known FV ranges

        Returns:
            List of findings
        """
        self.findings = []
        self.firmware_volumes = []

        # Load target data
        target_data = self._load_target(target_path)
        
        if not target_data:
            self.findings.append({
                'detector': 'hook_v2',
                'severity': 'medium',
                'title': 'Unable to load target',
                'description': f'Could not read target from {target_path}',
                'recommendation': 'Verify file format and accessibility'
            })
            return self.findings

        # Discover Firmware Volumes
        if fv_ranges:
            # Use provided FV ranges
            for base, size in fv_ranges:
                self.firmware_volumes.append(FirmwareVolume(base, size, b''))
        else:
            # Auto-discover FV ranges
            self._discover_firmware_volumes(target_data)

        # Locate Boot Services Table
        bst_offset = self._locate_boot_services_table(target_data)
        
        if bst_offset is None:
            self.findings.append({
                'detector': 'hook_v2',
                'severity': 'low',
                'title': 'Boot Services Table not found',
                'description': 'Could not locate Boot Services Table in target',
                'recommendation': 'Verify target is a valid memory dump or firmware image'
            })
            return self.findings

        # Parse Boot Services Table
        bst = self._parse_boot_services_table(target_data, bst_offset)

        # Verify CRC32
        self._verify_crc32(bst, bst_offset, target_data)

        # Check for hooked functions with FV validation
        self._check_hooked_functions_fv(bst, bst_offset, target_data)

        # Scan for trampolines at hook targets
        self._scan_for_trampolines(bst, target_data)

        # Compare against baseline
        if self.baseline:
            self._compare_with_baseline(bst)

        return self.findings

    def _load_target(self, target_path: str) -> Optional[bytes]:
        """Load target file."""
        target = Path(target_path)
        
        if not target.exists():
            return None

        try:
            with open(target, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"[WARNING] Failed to load target: {e}")
            return None

    def _discover_firmware_volumes(self, data: bytes):
        """
        Discover UEFI Firmware Volumes in memory dump.
        Uses data.find() for initial search to handle unaligned FVs.
        
        Args:
            data: Memory dump data
        """
        offset = 0
        while offset < len(data) - 64:
            # Use find() to locate next FV signature (handles unaligned FVs)
            next_fv = data.find(self.FV_SIGNATURE, offset)
            
            if next_fv == -1:
                # No more FVs found
                break
            
            offset = next_fv
            
            try:
                # Validate FV header structure
                if offset + 64 > len(data):
                    break
                
                # Parse FV header (simplified)
                fv_length = struct.unpack('<Q', data[offset+32:offset+40])[0]
                
                # Validate FV length
                if fv_length > 0 and fv_length < len(data) - offset and fv_length < 0x10000000:  # Max 256MB
                    # Extract GUID
                    guid = data[offset+16:offset+32]
                    
                    fv = FirmwareVolume(
                        base_address=offset,
                        size=fv_length,
                        guid=guid
                    )
                    self.firmware_volumes.append(fv)
                    
                    print(f"[INFO] Discovered FV at 0x{offset:x}, size 0x{fv_length:x}")
                    
                    # Skip to end of this FV for next search
                    offset += fv_length
                else:
                    # Invalid FV, skip past signature
                    offset += 4
            except (struct.error, ValueError, IndexError):
                # Parsing error, skip past this signature
                offset += 4

    def _locate_boot_services_table(self, data: bytes) -> Optional[int]:
        """Locate Boot Services Table in memory dump."""
        signature_bytes = struct.pack('<Q', self.BST_SIGNATURE)
        offset = data.find(signature_bytes)
        
        if offset != -1:
            return offset

        # Alternative search
        for i in range(0, len(data) - 24, 8):
            try:
                sig = struct.unpack('<Q', data[i:i+8])[0]
                if sig == self.BST_SIGNATURE:
                    return i
            except:
                continue

        return None

    def _parse_boot_services_table(self, data: bytes, offset: int) -> Dict:
        """Parse Boot Services Table structure."""
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

    def _verify_crc32(self, bst: Dict, offset: int, data: bytes):
        """
        Verify Boot Services Table CRC32 with actual calculation.
        
        Args:
            bst: Parsed BST
            offset: BST offset in memory
            data: Full memory dump
        """
        if 'CRC32' not in bst or 'HeaderSize' not in bst:
            return

        stored_crc = bst['CRC32']
        header_size = bst['HeaderSize']
        
        # Extract BST header data
        if offset + header_size > len(data):
            return
            
        bst_data = bytearray(data[offset:offset+header_size])
        
        # Zero out CRC32 field for calculation
        bst_data[16:20] = b'\x00\x00\x00\x00'
        
        # Calculate CRC32
        calculated_crc = zlib.crc32(bst_data) & 0xFFFFFFFF
        
        if stored_crc != calculated_crc:
            self.findings.append({
                'detector': 'hook_v2',
                'severity': 'critical',
                'title': 'Boot Services Table CRC32 mismatch',
                'description': 'BST CRC32 does not match calculated value, indicating table '
                             'has been modified without proper CRC update. Strong indicator of hooking.',
                'details': {
                    'offset': f'0x{offset:x}',
                    'stored_crc32': f'0x{stored_crc:08x}',
                    'calculated_crc32': f'0x{calculated_crc:08x}'
                },
                'recommendation': 'Investigate Boot Services Table modifications and verify hook installation'
            })

    def _is_pointer_in_fv(self, ptr: int) -> bool:
        """
        Check if pointer is within any discovered Firmware Volume.
        
        Args:
            ptr: Function pointer value
            
        Returns:
            True if pointer is within an FV
        """
        for fv in self.firmware_volumes:
            if fv.contains(ptr):
                return True
        return False

    def _check_hooked_functions_fv(self, bst: Dict, offset: int, data: bytes):
        """
        Check for hooked Boot Services functions using FV-based validation.
        
        Args:
            bst: Parsed BST
            offset: BST offset
            data: Memory dump data
        """
        # High-value targets for bootkits
        high_value_targets = [
            'AllocatePool',
            'FreePool',
            'CreateEvent',
            'ExitBootServices',
            'LoadImage',
            'StartImage',
            'SetVariable'
        ]

        for func_name in high_value_targets:
            if func_name not in bst:
                continue
                
            func_ptr = bst[func_name]
            
            # Skip null pointers (handled separately)
            if func_ptr == 0:
                continue
            
            # Check if pointer is outside all FVs
            if self.firmware_volumes and not self._is_pointer_in_fv(func_ptr):
                severity = 'critical' if self.strict_mode else 'high'
                
                self.findings.append({
                    'detector': 'hook_v2',
                    'severity': severity,
                    'title': f'{func_name} pointer outside Firmware Volume',
                    'description': f'Boot Services function {func_name} points to 0x{func_ptr:x}, '
                                 f'which is outside all discovered Firmware Volumes. This strongly '
                                 f'indicates a hook has been installed.',
                    'details': {
                        'function': func_name,
                        'pointer': f'0x{func_ptr:x}',
                        'offset': f'0x{offset + self.BST_OFFSETS[func_name]:x}',
                        'fv_count': len(self.firmware_volumes)
                    },
                    'recommendation': f'Analyze code at 0x{func_ptr:x} for hook trampoline pattern'
                })

    def _scan_for_trampolines(self, bst: Dict, data: bytes):
        """
        Scan Boot Services function targets for trampoline patterns.
        
        Args:
            bst: Parsed BST
            data: Memory dump data
        """
        for func_name, func_offset in self.BST_OFFSETS.items():
            if func_offset < 24 or func_name not in bst:
                continue
                
            func_ptr = bst[func_name]
            
            # Skip if already scanned or invalid
            if func_ptr == 0 or func_ptr in self.scanned_regions:
                continue
            
            # Mark as scanned
            self.scanned_regions.add(func_ptr)
            
            # Check if we can read at this address
            if func_ptr >= len(data) or func_ptr + 20 > len(data):
                continue
            
            # Scan for trampoline patterns
            trampolines = self._detect_trampoline_patterns(data, func_ptr)
            
            for trampoline in trampolines:
                self.findings.append({
                    'detector': 'hook_v2',
                    'severity': 'critical',
                    'title': f'Hook trampoline detected at {func_name}',
                    'description': f'Detected {trampoline.pattern_type} trampoline pattern at '
                                 f'0x{trampoline.address:x}, redirecting to 0x{trampoline.target:x}. '
                                 f'Confidence: {trampoline.confidence:.0%}',
                    'details': {
                        'function': func_name,
                        'trampoline_address': f'0x{trampoline.address:x}',
                        'target_address': f'0x{trampoline.target:x}',
                        'pattern_type': trampoline.pattern_type,
                        'confidence': f'{trampoline.confidence:.2f}'
                    },
                    'recommendation': f'Analyze hook handler at 0x{trampoline.target:x}'
                })

    def _detect_trampoline_patterns(self, data: bytes, address: int) -> List[TrampolinePattern]:
        """
        Detect trampoline patterns at given address.
        
        Args:
            data: Memory dump data
            address: Address to scan
            
        Returns:
            List of detected trampolines
        """
        trampolines = []
        
        # Check MOV RAX, imm64; JMP RAX pattern (14 bytes)
        pattern = self.TRAMPOLINE_PATTERNS['mov_rax_jmp']
        if (address + pattern['size'] <= len(data) and
            data[address:address+2] == bytes(pattern['pattern'])):
            
            # Extract target address from MOV RAX, imm64
            target = struct.unpack('<Q', data[address+2:address+10])[0]
            
            # Verify JMP RAX follows
            if data[address+10:address+12] == bytes(pattern['jmp_opcode']):
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='mov_rax_jmp',
                    confidence=pattern['confidence']
                ))
        
        # Check JMP [RIP+offset] pattern (6 bytes)
        pattern = self.TRAMPOLINE_PATTERNS['jmp_rip_indirect']
        if (address + pattern['size'] <= len(data) and
            data[address:address+2] == bytes(pattern['pattern'])):
            
            # Extract RIP-relative offset
            rip_offset = struct.unpack('<i', data[address+2:address+6])[0]
            
            # Calculate target (RIP after instruction + offset)
            target_addr = address + 6 + rip_offset
            
            # Read target from memory
            if target_addr + 8 <= len(data):
                target = struct.unpack('<Q', data[target_addr:target_addr+8])[0]
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='jmp_rip_indirect',
                    confidence=pattern['confidence']
                ))
        
        return trampolines

    def _compare_with_baseline(self, bst: Dict):
        """Compare BST with baseline."""
        if not self.baseline or 'boot_services_table' not in self.baseline:
            return

        baseline_bst = self.baseline['boot_services_table']

        for func_name in self.BST_OFFSETS.keys():
            if func_name in bst and func_name in baseline_bst:
                current_ptr = bst[func_name]
                baseline_ptr = baseline_bst.get(func_name)

                if baseline_ptr and current_ptr != baseline_ptr:
                    self.findings.append({
                        'detector': 'hook_v2',
                        'severity': 'critical',
                        'title': f'{func_name} pointer modified from baseline',
                        'description': f'Boot Services function {func_name} pointer has been modified '
                                     'from baseline, indicating hook installation.',
                        'details': {
                            'function': func_name,
                            'baseline': f'0x{baseline_ptr:x}',
                            'current': f'0x{current_ptr:x}',
                            'delta': f'0x{abs(current_ptr - baseline_ptr):x}'
                        },
                        'recommendation': f'Analyze code at 0x{current_ptr:x} for malicious hook'
                    })



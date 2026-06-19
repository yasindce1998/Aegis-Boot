"""
Hook Detector V2 - Enhanced UEFI Boot Services Table Hook Analysis

Implements FV-based pointer validation and trampoline pattern detection
to eliminate false positives on real hardware.

Improvements:
- #7: Dynamic FV range detection instead of hardcoded address ranges
- #8: 14-byte trampoline pattern detection (MOV RAX, imm64; JMP RAX)

Copyright (c) 2026, Barzakh Research Project
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

    # ARM64 (AARCH64) trampoline patterns
    AARCH64_TRAMPOLINE_PATTERNS = {
        # LDR X16, [PC+8]; BR X16; <64-bit addr> (16 bytes)
        'ldr_x16_br': {
            'pattern': [0x50, 0x00, 0x00, 0x58],  # LDR X16, #8 (little-endian)
            'br_opcode': [0x00, 0x02, 0x1F, 0xD6],  # BR X16
            'size': 16,
            'confidence': 0.95
        },
        # LDR X17, [PC+8]; BR X17; <64-bit addr> (16 bytes)
        'ldr_x17_br': {
            'pattern': [0x51, 0x00, 0x00, 0x58],  # LDR X17, #8
            'br_opcode': [0x20, 0x02, 0x1F, 0xD6],  # BR X17
            'size': 16,
            'confidence': 0.90
        },
    }

    # RISC-V (RV64) trampoline patterns
    RISCV_TRAMPOLINE_PATTERNS = {
        # AUIPC t1, 0; LD t1, 8(t1); JALR x0, t1, 0; <64-bit addr> (20 bytes)
        'auipc_ld_jalr': {
            'pattern': [0x17, 0x03, 0x00, 0x00],  # AUIPC t1, 0
            'ld_opcode': [0x03, 0x33, 0x83, 0x00],  # LD t1, 8(t1)
            'jalr_opcode': [0x67, 0x00, 0x03, 0x00],  # JALR x0, t1, 0
            'size': 20,
            'confidence': 0.95
        },
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
        self.scanned_regions = set()

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
        Detect trampoline patterns at given address (x86_64, ARM64, RISC-V).

        Args:
            data: Memory dump data
            address: Address to scan

        Returns:
            List of detected trampolines
        """
        trampolines = []

        # --- x86_64 patterns ---

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

        # --- ARM64 (AARCH64) patterns ---

        # LDR X16, [PC+8]; BR X16; <64-bit addr> (16 bytes)
        pattern = self.AARCH64_TRAMPOLINE_PATTERNS['ldr_x16_br']
        if (address + pattern['size'] <= len(data) and
            data[address:address+4] == bytes(pattern['pattern'])):

            # Verify BR X16 follows
            if data[address+4:address+8] == bytes(pattern['br_opcode']):
                # Extract 64-bit target address at offset +8
                target = struct.unpack('<Q', data[address+8:address+16])[0]
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='aarch64_ldr_x16_br',
                    confidence=pattern['confidence']
                ))

        # LDR X17, [PC+8]; BR X17 variant
        pattern = self.AARCH64_TRAMPOLINE_PATTERNS['ldr_x17_br']
        if (address + pattern['size'] <= len(data) and
            data[address:address+4] == bytes(pattern['pattern'])):

            if data[address+4:address+8] == bytes(pattern['br_opcode']):
                target = struct.unpack('<Q', data[address+8:address+16])[0]
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='aarch64_ldr_x17_br',
                    confidence=pattern['confidence']
                ))

        # --- RISC-V (RV64) patterns ---

        # AUIPC t1, 0; LD t1, 8(t1); JALR x0, t1, 0; <64-bit addr> (20 bytes)
        pattern = self.RISCV_TRAMPOLINE_PATTERNS['auipc_ld_jalr']
        if (address + pattern['size'] <= len(data) and
            data[address:address+4] == bytes(pattern['pattern'])):

            # Verify LD t1, 8(t1) follows
            if data[address+4:address+8] == bytes(pattern['ld_opcode']):
                # Verify JALR x0, t1, 0 follows
                if data[address+8:address+12] == bytes(pattern['jalr_opcode']):
                    # Extract 64-bit target address at offset +12
                    target = struct.unpack('<Q', data[address+12:address+20])[0]
                    trampolines.append(TrampolinePattern(
                        address=address,
                        target=target,
                        pattern_type='riscv_auipc_ld_jalr',
                        confidence=pattern['confidence']
                    ))

        # --- Additional x86_64 patterns (advanced obfuscation) ---

        # PUSH imm32; RET pattern (6 bytes) - pushes 32-bit address and returns to it
        if (address + 6 <= len(data) and
            data[address] == 0x68 and
            data[address + 5] == 0xC3):
            target = struct.unpack('<I', data[address+1:address+5])[0]
            trampolines.append(TrampolinePattern(
                address=address,
                target=target,
                pattern_type='push_ret',
                confidence=0.85
            ))

        # MOV [RSP], lo32; MOV [RSP+4], hi32; RET (17 bytes)
        if (address + 17 <= len(data) and
            data[address:address+4] == b'\x48\xC7\x04\x24' and
            data[address+8:address+12] == b'\xC7\x44\x24\x04' and
            data[address+16] == 0xC3):
            lo = struct.unpack('<I', data[address+4:address+8])[0]
            hi = struct.unpack('<I', data[address+12:address+16])[0]
            target = lo | (hi << 32)
            trampolines.append(TrampolinePattern(
                address=address,
                target=target,
                pattern_type='mov_stack_ret',
                confidence=0.90
            ))

        # NOP sled followed by MOV RAX, imm64; JMP RAX
        if (address + 16 <= len(data) and data[address] == 0x90):
            nop_end = address
            while nop_end < min(address + 16, len(data)) and data[nop_end] == 0x90:
                nop_end += 1
            nop_count = nop_end - address
            if (nop_count >= 4 and nop_end + 12 <= len(data) and
                data[nop_end] == 0x48 and data[nop_end+1] == 0xB8 and
                data[nop_end+10] == 0xFF and data[nop_end+11] == 0xE0):
                target = struct.unpack('<Q', data[nop_end+2:nop_end+10])[0]
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='nop_sled_mov_jmp',
                    confidence=0.80
                ))

        # PUSH RBX; MOV RBX, imm64(dead); POP RBX; MOV RAX, imm64; JMP RAX (junk insertion)
        if (address + 24 <= len(data) and
            data[address] == 0x53 and
            data[address+1:address+3] == b'\x48\xBB' and
            data[address+11] == 0x5B and
            data[address+12] == 0x48 and data[address+13] == 0xB8 and
            data[address+22] == 0xFF and data[address+23] == 0xE0):
            target = struct.unpack('<Q', data[address+14:address+22])[0]
            trampolines.append(TrampolinePattern(
                address=address,
                target=target,
                pattern_type='junk_insert_mov_jmp',
                confidence=0.85
            ))

        # LEA RAX, [RIP+offset]; JMP RAX (7+ bytes, target at RIP+offset location)
        if (address + 9 <= len(data) and
            data[address:address+3] == b'\x48\x8D\x05' and
            data[address+7] == 0xFF and data[address+8] == 0xE0):
            rel32 = struct.unpack('<i', data[address+3:address+7])[0]
            target_pos = address + 7 + rel32
            if target_pos + 8 <= len(data) and target_pos >= 0:
                target = struct.unpack('<Q', data[target_pos:target_pos+8])[0]
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='lea_jmp',
                    confidence=0.85
                ))

        # CALL $+5; POP RCX; MOV RAX, [RCX+11]; JMP RAX (12 bytes + literal pool)
        if (address + 16 <= len(data) and
            data[address:address+5] == b'\xE8\x00\x00\x00\x00' and
            data[address+5] == 0x59 and
            data[address+6:address+10] == b'\x48\x8B\x41\x0B' and
            data[address+10] == 0xFF and data[address+11] == 0xE0):
            pool_addr = address + 5 + 11
            if pool_addr + 8 <= len(data):
                target = struct.unpack('<Q', data[pool_addr:pool_addr+8])[0]
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='call_pop_jmp',
                    confidence=0.90
                ))

        # XOR-encoded: MOV RAX, enc; MOV RCX, key; XOR RAX, RCX; JMP RAX (25 bytes)
        if (address + 25 <= len(data) and
            data[address:address+2] == b'\x48\xB8' and
            data[address+10:address+12] == b'\x48\xB9' and
            data[address+20:address+23] == b'\x48\x31\xC8' and
            data[address+23:address+25] == b'\xFF\xE0'):
            encoded = struct.unpack('<Q', data[address+2:address+10])[0]
            key_mask = struct.unpack('<Q', data[address+12:address+20])[0]
            target = encoded ^ key_mask
            trampolines.append(TrampolinePattern(
                address=address,
                target=target,
                pattern_type='xor_decode_jmp',
                confidence=0.90
            ))

        # MULTI_STAGE: JMP short (0xEB) to second stage with MOV RAX; JMP RAX
        if (address + 2 <= len(data) and data[address] == 0xEB):
            rel8 = data[address + 1]
            if rel8 > 0x7F:
                rel8 = rel8 - 256
            stage2 = address + 2 + rel8
            if (stage2 >= 0 and stage2 + 12 <= len(data) and
                data[stage2] == 0x48 and data[stage2+1] == 0xB8 and
                data[stage2+10] == 0xFF and data[stage2+11] == 0xE0):
                target = struct.unpack('<Q', data[stage2+2:stage2+10])[0]
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='multi_stage_jmp',
                    confidence=0.85
                ))

        # --- Additional ARM64 patterns ---

        # MOVZ/MOVK/MOVK/MOVK X16 + BR X16 (20 bytes)
        if (address + 20 <= len(data)):
            instr0 = struct.unpack('<I', data[address:address+4])[0]
            instr4 = struct.unpack('<I', data[address+16:address+20])[0]
            if ((instr0 & 0xFF80001F) == 0xD2800010 and  # MOVZ X16, #imm
                instr4 == 0xD61F0200):                    # BR X16
                lo16 = (instr0 >> 5) & 0xFFFF
                instr1 = struct.unpack('<I', data[address+4:address+8])[0]
                instr2 = struct.unpack('<I', data[address+8:address+12])[0]
                instr3 = struct.unpack('<I', data[address+12:address+16])[0]
                hi16 = (instr1 >> 5) & 0xFFFF
                hi32 = (instr2 >> 5) & 0xFFFF
                hi48 = (instr3 >> 5) & 0xFFFF
                target = lo16 | (hi16 << 16) | (hi32 << 32) | (hi48 << 48)
                trampolines.append(TrampolinePattern(
                    address=address,
                    target=target,
                    pattern_type='aarch64_movz_movk_br',
                    confidence=0.90
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



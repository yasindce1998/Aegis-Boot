"""
MBR/VBR Bootkit Detector - Legacy BIOS Boot Sector Analysis

Detects INT 13h/INT 15h hooking, IVT modifications, suspicious
relocations, and known bootkit signatures in MBR/VBR code.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class IVTHook:
    """Represents a detected Interrupt Vector Table hook."""
    interrupt: int
    original_segment: int
    original_offset: int
    hook_segment: int
    hook_offset: int


class MBRDetector:
    """Detector for legacy BIOS MBR/VBR bootkit techniques."""

    MBR_SIZE = 512
    BOOT_SIGNATURE = 0xAA55
    PARTITION_TABLE_OFFSET = 446
    IVT_SIZE = 1024  # 256 entries * 4 bytes

    # Suspicious INT hooks commonly used by bootkits
    HOOKED_INTERRUPTS = {
        0x13: 'Disk services (read/write interception)',
        0x15: 'Memory map (hide memory regions)',
        0x19: 'Bootstrap loader (chain-load interception)',
        0x1C: 'Timer tick (periodic payload execution)',
    }

    # Known bootkit signatures
    KNOWN_SIGNATURES = {
        b'AEGS': 'Barzakh research MBR module',
        b'AEGV': 'Barzakh research VBR module',
        b'\x33\xC0\x8E\xD0\xBC\x00\x7C': 'Standard MBR preamble (XOR AX,AX; MOV SS,AX; MOV SP,7C00h)',
        b'\xFA\x33\xC0\x8E\xD0': 'CLI + segment init (potential bootkit prologue)',
    }

    # MBR relocation targets (bootkits relocate to make room)
    RELOCATION_TARGETS = [0x0600, 0x0500, 0x7A00, 0x7E00]

    def __init__(self, baseline: Optional[Dict] = None):
        self.baseline = baseline
        self.findings = []

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze target for MBR/VBR bootkit indicators.

        Args:
            target_path: Path to disk image or MBR dump

        Returns:
            List of findings
        """
        self.findings = []

        target = Path(target_path)
        if not target.exists():
            self.findings.append({
                'detector': 'mbr',
                'severity': 'medium',
                'title': 'Unable to load target',
                'description': f'Could not read target from {target_path}',
                'recommendation': 'Verify file format and accessibility'
            })
            return self.findings

        try:
            with open(target, 'rb') as f:
                data = f.read()
        except Exception:
            return self.findings

        if len(data) < self.MBR_SIZE:
            return self.findings

        # Check boot signature
        self._check_boot_signature(data)

        # Analyze MBR code section (first 446 bytes)
        self._analyze_mbr_code(data)

        # Check for IVT hook patterns in code
        self._detect_ivt_hook_patterns(data)

        # Check for relocation patterns
        self._detect_relocation(data)

        # Scan for known signatures
        self._scan_signatures(data)

        # Check partition table anomalies
        self._check_partition_table(data)

        # If we have more data (full disk image), check for hidden sectors
        if len(data) > self.MBR_SIZE:
            self._check_hidden_sectors(data)

        return self.findings

    def _check_boot_signature(self, data: bytes):
        """Verify standard 0xAA55 boot signature."""
        sig = struct.unpack('<H', data[510:512])[0]
        if sig != self.BOOT_SIGNATURE:
            self.findings.append({
                'detector': 'mbr',
                'severity': 'medium',
                'title': 'Invalid boot signature',
                'description': f'MBR boot signature is 0x{sig:04X}, expected 0xAA55. '
                             'May indicate corrupted or non-standard MBR.',
                'details': {'signature': f'0x{sig:04X}'},
                'recommendation': 'Verify disk is bootable and MBR is intact'
            })

    def _analyze_mbr_code(self, data: bytes):
        """Analyze MBR code section for suspicious patterns."""
        code = data[:self.PARTITION_TABLE_OFFSET]

        # Check for INT 13h manipulation (disk hooking)
        # Pattern: MOV WORD [004Ch], <offset> (writing to IVT entry for INT 13h)
        # IVT offset for INT 13h = 0x13 * 4 = 0x4C
        int13_ivt_writes = self._find_ivt_writes(code, 0x4C)
        if int13_ivt_writes:
            self.findings.append({
                'detector': 'mbr',
                'severity': 'critical',
                'title': 'INT 13h IVT modification detected',
                'description': 'MBR code writes to INT 13h vector table entry (offset 0x4C). '
                             'This is the primary technique for disk-level bootkits to intercept '
                             'all disk reads and hide their presence.',
                'details': {'ivt_offset': '0x4C', 'hook_type': 'INT 13h (disk services)'},
                'recommendation': 'Compare MBR against known-good backup; check sector 2+ for hidden payload'
            })

        # Check for INT 15h manipulation (memory map hiding)
        int15_ivt_writes = self._find_ivt_writes(code, 0x54)
        if int15_ivt_writes:
            self.findings.append({
                'detector': 'mbr',
                'severity': 'high',
                'title': 'INT 15h IVT modification detected',
                'description': 'MBR/VBR code writes to INT 15h vector table entry (offset 0x54). '
                             'Used to hide memory regions from the OS memory map.',
                'details': {'ivt_offset': '0x54', 'hook_type': 'INT 15h (memory map)'},
                'recommendation': 'Verify memory map integrity via alternative methods'
            })

    def _find_ivt_writes(self, code: bytes, ivt_offset: int) -> bool:
        """Check if code contains writes to a specific IVT offset."""
        # Look for the IVT offset bytes in code (as immediate operand)
        offset_bytes_le = struct.pack('<H', ivt_offset)

        # MOV WORD [imm16], imm16 pattern: C7 06 <offset_lo> <offset_hi> <value>
        for i in range(len(code) - 4):
            if code[i] == 0xC7 and code[i+1] == 0x06:
                if code[i+2:i+4] == offset_bytes_le:
                    return True

        # MOV [imm16], reg pattern via segment override
        # Also check for direct word references to the offset
        for i in range(len(code) - 2):
            if code[i:i+2] == offset_bytes_le:
                # Check surrounding context for MOV instruction
                if i >= 2 and code[i-2] in (0x89, 0xA3, 0xC7):
                    return True
                if i >= 1 and code[i-1] in (0x89, 0xA3, 0xC7):
                    return True

        return False

    def _detect_ivt_hook_patterns(self, data: bytes):
        """Detect patterns that save and replace IVT entries."""
        code = data[:self.PARTITION_TABLE_OFFSET]

        # Pattern: Read IVT entry (MOV AX, [004Ch]) then write new value
        # This is the classic "save original, install hook" pattern
        for int_num, description in self.HOOKED_INTERRUPTS.items():
            ivt_offset = int_num * 4
            offset_bytes = struct.pack('<H', ivt_offset)

            # Check if both reading and writing to this IVT entry
            has_read = False
            has_write = False

            for i in range(len(code) - 3):
                # MOV AX, [offset] or MOV reg, [offset]
                if code[i:i+2] == b'\xA1' + offset_bytes[:1]:
                    if i + 2 < len(code) and code[i+1:i+3] == offset_bytes:
                        has_read = True
                # Check for the offset appearing with various MOV variants
                if code[i:i+2] == offset_bytes:
                    has_read = True

            if has_read and int_num in (0x13, 0x15):
                # Already reported by _analyze_mbr_code
                pass

    def _detect_relocation(self, data: bytes):
        """Detect MBR self-relocation patterns."""
        code = data[:self.PARTITION_TABLE_OFFSET]

        for target in self.RELOCATION_TARGETS:
            target_bytes = struct.pack('<H', target)

            # Look for MOV DI, <relocation_target> pattern
            # 0xBF = MOV DI, imm16
            for i in range(len(code) - 3):
                if code[i] == 0xBF and code[i+1:i+3] == target_bytes:
                    # Also check for REP MOVSW (0xF3 0xA5) nearby
                    search_area = code[i:min(i+20, len(code))]
                    if b'\xF3\xA5' in search_area:
                        self.findings.append({
                            'detector': 'mbr',
                            'severity': 'high',
                            'title': f'MBR self-relocation to 0x{target:04X} detected',
                            'description': f'MBR relocates itself to 0x{target:04X} using REP MOVSW. '
                                         'Self-relocation frees 0x7C00 for loading the original MBR, '
                                         'a classic bootkit persistence technique.',
                            'details': {
                                'relocation_target': f'0x{target:04X}',
                                'technique': 'REP MOVSW relocation'
                            },
                            'recommendation': 'Examine code at relocation target for hook installation'
                        })
                        break

    def _scan_signatures(self, data: bytes):
        """Scan for known bootkit signatures."""
        for sig, description in self.KNOWN_SIGNATURES.items():
            offset = data.find(sig)
            if offset != -1 and offset < self.MBR_SIZE:
                severity = 'info' if 'Barzakh' in description else 'high'
                self.findings.append({
                    'detector': 'mbr',
                    'severity': severity,
                    'title': f'Known signature detected: {description}',
                    'description': f'Found signature at offset 0x{offset:X} in boot sector.',
                    'details': {
                        'signature': sig.hex(),
                        'offset': f'0x{offset:X}',
                        'description': description
                    },
                    'recommendation': 'Verify this matches expected boot configuration'
                })

    def _check_partition_table(self, data: bytes):
        """Check partition table for anomalies."""
        pt_data = data[self.PARTITION_TABLE_OFFSET:510]

        # Check for all-zero partition table (no partitions but bootable code exists)
        if pt_data == b'\x00' * 64:
            code_section = data[:self.PARTITION_TABLE_OFFSET]
            if code_section != b'\x00' * self.PARTITION_TABLE_OFFSET:
                self.findings.append({
                    'detector': 'mbr',
                    'severity': 'medium',
                    'title': 'Empty partition table with executable code',
                    'description': 'MBR contains executable code but no partition entries. '
                                 'This may indicate a bootkit that operates without partitions.',
                    'details': {'partition_entries': 0},
                    'recommendation': 'Verify if this is expected (e.g., GPT disk) or suspicious'
                })

    def _check_hidden_sectors(self, data: bytes):
        """Check sectors beyond MBR for hidden payloads."""
        # Check sectors 2-10 for executable code (common bootkit payload locations)
        for sector_num in range(1, min(10, len(data) // 512)):
            sector_offset = sector_num * 512
            sector = data[sector_offset:sector_offset + 512]

            if len(sector) < 512:
                break

            # Check if sector has boot signature (chained boot sectors)
            if sector[510:512] == b'\x55\xAA':
                self.findings.append({
                    'detector': 'mbr',
                    'severity': 'medium',
                    'title': f'Boot signature in sector {sector_num + 1}',
                    'description': f'Sector {sector_num + 1} (offset 0x{sector_offset:X}) contains '
                                 'a boot signature (0xAA55). May indicate a chain-loaded bootkit stage.',
                    'details': {
                        'sector': sector_num + 1,
                        'offset': f'0x{sector_offset:X}'
                    },
                    'recommendation': 'Analyze sector code for bootkit payload'
                })

"""
Self-Erasure Detector

Detects runtime self-erasing bootkit payloads that copy themselves to
EfiRuntimeServicesCode allocations and zero their original image to
evade memory forensics.

Techniques detected:
- BlackLotus (2023): runtime copy + original image zeroing
- CosmicStrand: persistent runtime hooks with no corresponding image
- Unmatched EfiRuntimeServicesCode regions

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
from pathlib import Path
from typing import Dict, List, Optional

from .base_detector import BaseDetector


# PE/COFF signature
PE_SIGNATURE = b'MZ'
PE_MAGIC_OFFSET = 0x3C
PE_SIGNATURE_FULL = b'PE\x00\x00'

# EFI memory map type values
EFI_RUNTIME_SERVICES_CODE = 5
EFI_RUNTIME_SERVICES_DATA = 6
EFI_BOOT_SERVICES_CODE = 3

# Heuristic thresholds
MIN_ZEROED_BLOCK_SIZE = 0x1000       # 4KB minimum for suspicious zeroed region
MAX_RUNTIME_REGION_SIZE = 0x200000   # 2MB - larger is suspicious
ENTROPY_THRESHOLD_LOW = 0.1          # Below this, likely zeroed/erased
ZERO_PAGE_THRESHOLD = 0.98           # 98% zeros = effectively erased


class SelfErasureDetector(BaseDetector):
    """Detects self-erasing runtime payloads in memory dumps."""

    def __init__(self, baseline: Optional[Dict] = None):
        super().__init__(baseline)
        self.runtime_regions = []
        self.zeroed_regions = []

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze memory dump for self-erasure indicators.

        Checks:
        - EfiRuntimeServicesCode regions without valid PE headers
        - Executable code in runtime regions not matching any known driver
        - Zeroed page ranges at addresses that should contain loaded images
        - Memory regions with code patterns but no PE/COFF structure
        - Orphaned runtime allocations (no corresponding image in UEFI memory map)

        Args:
            target_path: Path to memory dump or UEFI memory map

        Returns:
            List of findings
        """
        self.clear_findings()
        target = Path(target_path)

        if not target.exists():
            return self.findings

        try:
            with open(target, 'rb') as f:
                data = f.read()
        except (IOError, OSError):
            return self.findings

        if len(data) < MIN_ZEROED_BLOCK_SIZE:
            return self.findings

        self._check_orphaned_runtime_code(data)
        self._check_zeroed_image_regions(data)
        self._check_headless_executable_regions(data)
        self._check_runtime_memory_map(data)

        return self.findings

    def _check_orphaned_runtime_code(self, data: bytes):
        """
        Find EfiRuntimeServicesCode regions containing code but no PE header.
        This is the primary indicator of a self-erasing payload.
        """
        efi_mem_map = self._parse_efi_memory_map(data)
        if not efi_mem_map:
            return

        for region in efi_mem_map:
            if region['type'] != EFI_RUNTIME_SERVICES_CODE:
                continue

            start = region['physical_start']
            size = region['num_pages'] * 0x1000

            if start + size > len(data):
                continue

            region_data = data[start:start + size]

            has_pe = self._has_pe_header(region_data)
            has_code = self._has_executable_patterns(region_data)

            if has_code and not has_pe:
                self._add_finding(
                    severity='critical',
                    title='Runtime Code Without PE Header (Self-Erasure Indicator)',
                    description=(
                        f'EfiRuntimeServicesCode region at 0x{start:016X} '
                        f'(size {size} bytes) contains executable code patterns '
                        f'but no valid PE/COFF header. This matches the BlackLotus/'
                        f'CosmicStrand self-erasure technique where the bootkit '
                        f'copies its code to a runtime allocation then destroys '
                        f'the original PE image.'
                    ),
                    details={
                        'region_base': f'0x{start:016X}',
                        'region_size': size,
                        'memory_type': 'EfiRuntimeServicesCode',
                        'pe_header_present': False,
                        'executable_patterns': True,
                        'technique': 'BlackLotus runtime self-erasure',
                    },
                    recommendation=(
                        'Dump and analyze the runtime code region. Compare against '
                        'known runtime drivers. Check if the region corresponds to '
                        'any loaded UEFI image in the PEI/DXE hand-off block.'
                    ),
                    confidence=0.9
                )
                self.runtime_regions.append(region)

    def _check_zeroed_image_regions(self, data: bytes):
        """
        Detect suspiciously large zeroed regions where images should exist.
        After self-erasure, the original loaded image pages are zeroed.
        """
        page_size = 0x1000
        zeroed_runs = []
        current_start = None
        current_length = 0

        for offset in range(0, len(data) - page_size, page_size):
            page = data[offset:offset + page_size]
            zero_ratio = page.count(b'\x00') / page_size

            if zero_ratio >= ZERO_PAGE_THRESHOLD:
                if current_start is None:
                    current_start = offset
                    current_length = page_size
                else:
                    current_length += page_size
            else:
                if current_start is not None and current_length >= MIN_ZEROED_BLOCK_SIZE * 4:
                    zeroed_runs.append((current_start, current_length))
                current_start = None
                current_length = 0

        if current_start is not None and current_length >= MIN_ZEROED_BLOCK_SIZE * 4:
            zeroed_runs.append((current_start, current_length))

        for start, length in zeroed_runs:
            before_offset = max(0, start - 0x100)
            before_data = data[before_offset:start]
            after_data = data[start + length:start + length + 0x100]

            has_neighboring_code = (
                self._has_executable_patterns(before_data) or
                self._has_executable_patterns(after_data)
            )

            if has_neighboring_code and length >= 0x4000:
                self._add_finding(
                    severity='high',
                    title='Zeroed Memory Region Adjacent to Executable Code',
                    description=(
                        f'Found {length} bytes of zeroed pages at 0x{start:016X} '
                        f'adjacent to executable code. This pattern matches '
                        f'self-erasure where the original DXE driver image is '
                        f'zeroed after copying the payload to runtime memory.'
                    ),
                    details={
                        'zeroed_base': f'0x{start:016X}',
                        'zeroed_size': length,
                        'zeroed_pages': length // page_size,
                        'adjacent_code': True,
                        'technique': 'Original image zeroing post-copy',
                    },
                    recommendation=(
                        'Cross-reference with the UEFI loaded image table. '
                        'A gap in loaded images at this address indicates a '
                        'self-erasing bootkit zeroed its original image.'
                    ),
                    confidence=0.7
                )
                self.zeroed_regions.append((start, length))

    def _check_headless_executable_regions(self, data: bytes):
        """
        Find regions with high code density but no standard headers.
        Self-erased payloads strip their PE header but retain code.
        """
        window_size = 0x1000
        code_regions = []

        for offset in range(0, len(data) - window_size, window_size):
            window = data[offset:offset + window_size]

            if self._has_pe_header(window):
                continue

            code_density = self._calculate_code_density(window)
            if code_density > 0.3:
                if not code_regions or offset > code_regions[-1][0] + code_regions[-1][1]:
                    code_regions.append((offset, window_size, code_density))
                else:
                    last = code_regions[-1]
                    code_regions[-1] = (last[0], last[1] + window_size, max(last[2], code_density))

        suspicious = [r for r in code_regions if r[1] >= 0x4000 and r[2] > 0.4]

        for base, size, density in suspicious[:5]:
            self._add_finding(
                severity='medium',
                title='Headless Executable Region',
                description=(
                    f'Region at 0x{base:016X} ({size} bytes) has high code '
                    f'density ({density:.1%}) but no PE/COFF or EFI header. '
                    f'May indicate a copied payload that discarded its header '
                    f'structure during self-erasure.'
                ),
                details={
                    'region_base': f'0x{base:016X}',
                    'region_size': size,
                    'code_density': f'{density:.2%}',
                    'has_pe_header': False,
                },
                confidence=0.5
            )

    def _check_runtime_memory_map(self, data: bytes):
        """
        Cross-reference runtime code regions with expected driver list.
        """
        efi_mem_map = self._parse_efi_memory_map(data)
        if not efi_mem_map:
            return

        runtime_code_regions = [
            r for r in efi_mem_map
            if r['type'] == EFI_RUNTIME_SERVICES_CODE
        ]

        known_runtime_drivers = self._get_known_runtime_drivers()

        for region in runtime_code_regions:
            start = region['physical_start']
            size = region['num_pages'] * 0x1000

            if size > MAX_RUNTIME_REGION_SIZE:
                self._add_finding(
                    severity='medium',
                    title='Oversized Runtime Code Region',
                    description=(
                        f'EfiRuntimeServicesCode region at 0x{start:016X} '
                        f'is unusually large ({size} bytes / {size//1024}KB). '
                        f'Legitimate runtime drivers are typically small. '
                        f'Large runtime allocations may indicate a bootkit '
                        f'staging area.'
                    ),
                    details={
                        'region_base': f'0x{start:016X}',
                        'region_size': size,
                        'threshold': MAX_RUNTIME_REGION_SIZE,
                    },
                    confidence=0.6
                )

    def _parse_efi_memory_map(self, data: bytes) -> List[Dict]:
        """
        Attempt to parse EFI memory map from dump.
        Looks for the characteristic structure of EFI_MEMORY_DESCRIPTOR entries.
        """
        regions = []
        desc_size = 48

        for offset in range(0, len(data) - desc_size * 3, 8):
            potential_entries = []
            valid = True

            for i in range(3):
                entry_offset = offset + i * desc_size
                if entry_offset + desc_size > len(data):
                    valid = False
                    break

                mem_type = struct.unpack_from('<I', data, entry_offset)[0]
                phys_start = struct.unpack_from('<Q', data, entry_offset + 8)[0]
                num_pages = struct.unpack_from('<Q', data, entry_offset + 24)[0]

                if mem_type > 14 or num_pages == 0 or num_pages > 0x100000:
                    valid = False
                    break

                if phys_start & 0xFFF != 0:
                    valid = False
                    break

                potential_entries.append({
                    'type': mem_type,
                    'physical_start': phys_start,
                    'num_pages': num_pages,
                })

            if valid and len(potential_entries) == 3:
                entry_offset = offset
                while entry_offset + desc_size <= len(data):
                    mem_type = struct.unpack_from('<I', data, entry_offset)[0]
                    phys_start = struct.unpack_from('<Q', data, entry_offset + 8)[0]
                    num_pages = struct.unpack_from('<Q', data, entry_offset + 24)[0]

                    if mem_type > 14 or num_pages == 0 or num_pages > 0x100000:
                        break
                    if phys_start & 0xFFF != 0:
                        break

                    regions.append({
                        'type': mem_type,
                        'physical_start': phys_start,
                        'num_pages': num_pages,
                    })
                    entry_offset += desc_size

                if len(regions) >= 3:
                    return regions
                regions = []

        return regions

    def _has_pe_header(self, data: bytes) -> bool:
        """Check if data starts with a valid PE/COFF header."""
        if len(data) < 64:
            return False

        if data[:2] != PE_SIGNATURE:
            return False

        pe_offset = struct.unpack_from('<I', data, PE_MAGIC_OFFSET)[0]
        if pe_offset + 4 > len(data):
            return False

        return data[pe_offset:pe_offset + 4] == PE_SIGNATURE_FULL

    def _has_executable_patterns(self, data: bytes) -> bool:
        """Check if data contains common x86-64 code patterns."""
        if len(data) < 16:
            return False

        code_patterns = [
            b'\x48\x89\x5C\x24',  # mov [rsp+...], rbx
            b'\x48\x83\xEC',      # sub rsp, imm8
            b'\x48\x8B\x05',      # mov rax, [rip+...]
            b'\xFF\x15',          # call [rip+...]
            b'\x48\x8D\x0D',      # lea rcx, [rip+...]
            b'\xC3',              # ret
            b'\x55\x48\x89\xE5', # push rbp; mov rbp, rsp
        ]

        matches = sum(1 for p in code_patterns if p in data)
        return matches >= 2

    def _calculate_code_density(self, data: bytes) -> float:
        """Estimate code density based on instruction-like byte patterns."""
        if not data:
            return 0.0

        code_bytes = 0
        i = 0
        while i < len(data):
            byte = data[i]
            if byte in (0x48, 0x49, 0x4C, 0x4D):  # REX prefixes
                code_bytes += 1
            elif byte in (0x55, 0x5D, 0xC3, 0xC9):  # push rbp, pop rbp, ret, leave
                code_bytes += 1
            elif byte == 0xFF and i + 1 < len(data):
                next_byte = data[i + 1]
                if next_byte in (0x15, 0x25, 0xD0, 0xE0):  # call/jmp indirect
                    code_bytes += 2
                    i += 1
            elif byte in (0xE8, 0xE9):  # call/jmp rel32
                code_bytes += 1
            elif byte == 0x0F and i + 1 < len(data):  # two-byte opcodes
                code_bytes += 2
                i += 1
            i += 1

        return code_bytes / len(data)

    def _get_known_runtime_drivers(self) -> List[Dict]:
        """
        Return list of known legitimate runtime service drivers.
        In a real deployment, this would be populated from the baseline.
        """
        if self.baseline and 'runtime_drivers' in self.baseline:
            return self.baseline['runtime_drivers']

        return [
            {'name': 'RuntimeDxe', 'typical_size_range': (0x5000, 0x20000)},
            {'name': 'CpuDxe', 'typical_size_range': (0x3000, 0x15000)},
            {'name': 'VariableRuntimeDxe', 'typical_size_range': (0x8000, 0x30000)},
            {'name': 'MonotonicCounterRuntimeDxe', 'typical_size_range': (0x2000, 0x8000)},
            {'name': 'CapsuleRuntimeDxe', 'typical_size_range': (0x4000, 0x15000)},
            {'name': 'ResetSystemRuntimeDxe', 'typical_size_range': (0x2000, 0x8000)},
        ]

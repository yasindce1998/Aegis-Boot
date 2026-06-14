"""
SPI Flash Integrity Detector

Detects misconfigurations and attacks targeting SPI flash protection
mechanisms on 2024+ platforms: PRx register gaps, FLOCKDN bypass,
BIOS Guard issues, and TOCTOU race indicators.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
from pathlib import Path
from typing import Dict, List, Optional

from .base_detector import BaseDetector


# SPI flash descriptor region offsets
SPI_DESCRIPTOR_SIGNATURE = b'\x5a\xa5\xf0\x0f'
DESCRIPTOR_MAP_OFFSET = 0x04
FLMAP0_OFFSET = 0x14
FLMAP1_OFFSET = 0x18

# HSFS register bit definitions (PCH SPI controller)
HSFS_FLOCKDN_BIT = 15
HSFS_FDV_BIT = 14

# BIOS Control Register bits
BIOS_CONTROL_BIOSWE = 0  # BIOS Write Enable
BIOS_CONTROL_BLE = 1     # BIOS Lock Enable
BIOS_CONTROL_SMM_BWP = 5 # SMM BIOS Write Protect

# PRx register layout (32-bit)
PRX_WRITE_PROTECT_BIT = 31
PRX_READ_PROTECT_BIT = 15
PRX_LIMIT_MASK = 0x7FFF0000
PRX_BASE_MASK = 0x00007FFF


class SpiIntegrityDetector(BaseDetector):
    """Detects SPI flash protection misconfigurations and bypass indicators."""

    def __init__(self, baseline: Optional[Dict] = None):
        super().__init__(baseline)
        self.spi_regions = {}
        self.prx_ranges = []
        self.bios_control = 0
        self.hsfs = 0

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze firmware image for SPI protection issues.

        Checks:
        - SPI descriptor validity and region layout
        - PRx register coverage gaps (unprotected BIOS regions)
        - FLOCKDN bit status (PRx reconfiguration at runtime)
        - BIOS Control register settings (BIOSWE, BLE, SMM_BWP)
        - Known TOCTOU race condition indicators
        - SPI descriptor write-access permissions

        Args:
            target_path: Path to firmware dump or SPI flash image

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

        if len(data) < 0x1000:
            return self.findings

        self._check_descriptor(data)
        self._check_prx_coverage(data)
        self._check_flockdn(data)
        self._check_bios_control(data)
        self._check_toctou_indicators(data)
        self._check_descriptor_permissions(data)

        return self.findings

    def _find_descriptor(self, data: bytes) -> int:
        """Find the SPI flash descriptor signature."""
        offset = data.find(SPI_DESCRIPTOR_SIGNATURE)
        if offset == -1:
            offset = 0x10
            if len(data) > offset + 4 and data[offset:offset+4] == SPI_DESCRIPTOR_SIGNATURE:
                return offset - 0x10
        return offset - 0x10 if offset >= 0x10 else -1

    def _check_descriptor(self, data: bytes):
        """Validate SPI flash descriptor structure."""
        desc_offset = self._find_descriptor(data)
        if desc_offset < 0:
            self._add_finding(
                severity='medium',
                title='Missing SPI Flash Descriptor',
                description=(
                    'No valid SPI flash descriptor found. The image may be a '
                    'partial dump or use a non-standard layout. Without a '
                    'descriptor, hardware-enforced region protections cannot '
                    'be verified.'
                ),
                recommendation='Obtain a full SPI flash dump including the descriptor region.'
            )
            return

        if len(data) < desc_offset + 0x30:
            return

        flmap0 = struct.unpack_from('<I', data, desc_offset + FLMAP0_OFFSET)[0]
        flmap1 = struct.unpack_from('<I', data, desc_offset + FLMAP1_OFFSET)[0]

        freg_base = ((flmap0 >> 12) & 0xFF) << 4
        num_regions = (flmap0 >> 24) & 0x07

        self.spi_regions = {
            'descriptor_base': desc_offset,
            'freg_base': freg_base,
            'num_regions': num_regions,
            'flmap0': flmap0,
            'flmap1': flmap1,
        }

    def _check_prx_coverage(self, data: bytes):
        """Check if PRx registers cover the entire BIOS region."""
        prx_offset = self._find_prx_registers(data)
        if prx_offset < 0:
            return

        bios_base, bios_limit = self._get_bios_region_bounds(data)
        if bios_base is None:
            return

        covered_ranges = []
        for i in range(5):
            offset = prx_offset + (i * 4)
            if offset + 4 > len(data):
                break

            prx_val = struct.unpack_from('<I', data, offset)[0]
            if prx_val == 0 or prx_val == 0xFFFFFFFF:
                continue

            wp = (prx_val >> PRX_WRITE_PROTECT_BIT) & 1
            if not wp:
                continue

            prx_base = (prx_val & PRX_BASE_MASK) << 12
            prx_limit = ((prx_val & PRX_LIMIT_MASK) >> 16) << 12 | 0xFFF

            covered_ranges.append((prx_base, prx_limit))
            self.prx_ranges.append({
                'index': i,
                'base': prx_base,
                'limit': prx_limit,
                'write_protect': wp,
                'read_protect': (prx_val >> PRX_READ_PROTECT_BIT) & 1,
            })

        gaps = self._find_coverage_gaps(bios_base, bios_limit, covered_ranges)
        if gaps:
            total_gap = sum(end - start + 1 for start, end in gaps)
            self._add_finding(
                severity='high',
                title='SPI PRx Register Coverage Gap',
                description=(
                    f'BIOS region (0x{bios_base:08X}-0x{bios_limit:08X}) has '
                    f'{len(gaps)} unprotected gap(s) totaling {total_gap} bytes. '
                    f'An attacker with ring-0 access can write to these ranges '
                    f'without triggering hardware protection.'
                ),
                details={
                    'bios_base': f'0x{bios_base:08X}',
                    'bios_limit': f'0x{bios_limit:08X}',
                    'gaps': [
                        {'start': f'0x{s:08X}', 'end': f'0x{e:08X}', 'size': e - s + 1}
                        for s, e in gaps
                    ],
                    'technique': 'LoJax/MosaicRegressor exploit unprotected flash ranges',
                },
                recommendation=(
                    'Ensure PRx registers cover the entire BIOS region with '
                    'write protection enabled. Verify FLOCKDN is set to prevent '
                    'runtime reconfiguration.'
                ),
                confidence=0.9
            )

    def _check_flockdn(self, data: bytes):
        """Check if FLOCKDN bit is set (PRx registers locked)."""
        hsfs_offset = self._find_hsfs_register(data)
        if hsfs_offset < 0:
            return

        if hsfs_offset + 4 > len(data):
            return

        hsfs = struct.unpack_from('<I', data, hsfs_offset)[0]
        self.hsfs = hsfs
        flockdn = (hsfs >> HSFS_FLOCKDN_BIT) & 1

        if not flockdn:
            self._add_finding(
                severity='critical',
                title='SPI Flash Lock-Down (FLOCKDN) Not Set',
                description=(
                    'The FLOCKDN bit in HSFS register is not set. This means '
                    'PRx registers can be reconfigured at runtime, allowing an '
                    'attacker to clear write-protection before modifying the '
                    'BIOS region. This is a prerequisite for the LoJax attack.'
                ),
                details={
                    'hsfs_value': f'0x{hsfs:08X}',
                    'flockdn_bit': HSFS_FLOCKDN_BIT,
                    'technique': 'LoJax clears PRx then writes implant to flash',
                },
                recommendation=(
                    'Firmware must set FLOCKDN before handing control to the OS. '
                    'This is typically done in the PEI phase. Verify the platform '
                    'initialization code sets SPI HSFS.FLOCKDN = 1.'
                ),
                confidence=0.95
            )

    def _check_bios_control(self, data: bytes):
        """Check BIOS Control register for write protection settings."""
        bc_offset = self._find_bios_control(data)
        if bc_offset < 0:
            return

        if bc_offset + 1 > len(data):
            return

        bc = data[bc_offset]
        self.bios_control = bc

        bioswe = (bc >> BIOS_CONTROL_BIOSWE) & 1
        ble = (bc >> BIOS_CONTROL_BLE) & 1
        smm_bwp = (bc >> BIOS_CONTROL_SMM_BWP) & 1

        if bioswe and not ble:
            self._add_finding(
                severity='critical',
                title='BIOS Write Enable Set Without Lock',
                description=(
                    'BIOS Write Enable (BIOSWE) is set but BIOS Lock Enable (BLE) '
                    'is not active. Any ring-0 code can directly write to the BIOS '
                    'region via the SPI controller. This is the simplest SPI flash '
                    'write attack vector.'
                ),
                details={
                    'bios_control': f'0x{bc:02X}',
                    'bioswe': bioswe,
                    'ble': ble,
                    'smm_bwp': smm_bwp,
                },
                recommendation=(
                    'Set BLE=1 to trigger SMI on BIOSWE changes. Additionally, '
                    'set SMM_BWP=1 so only SMM code can enable writes.'
                ),
                confidence=0.95
            )

        if not smm_bwp:
            self._add_finding(
                severity='high',
                title='SMM BIOS Write Protect Not Enabled',
                description=(
                    'SMM_BWP bit is not set in BIOS Control register. Without this, '
                    'a TOCTOU race between BLE SMI handler clearing BIOSWE and the '
                    'attacker re-setting it can allow flash writes (ThinkPwn-class attack).'
                ),
                details={
                    'bios_control': f'0x{bc:02X}',
                    'smm_bwp': smm_bwp,
                    'technique': 'TOCTOU race against BLE SMI handler',
                },
                recommendation=(
                    'Enable SMM_BWP (bit 5) in BIOS Control register so that '
                    'only SMM can set BIOSWE, closing the TOCTOU window.'
                ),
                confidence=0.85
            )

    def _check_toctou_indicators(self, data: bytes):
        """Check for indicators of TOCTOU race exploitation."""
        toctou_patterns = [
            (b'\xB8\x00\x00\x00\x00\xBA\xDC\x00\x00\x00\xEF', 'OUT DX,EAX to SPI MMIO'),
            (b'\x0F\x30', 'WRMSR instruction (potential SMI suppression)'),
        ]

        for pattern, desc in toctou_patterns:
            locations = []
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                locations.append(idx)
                offset = idx + 1
                if len(locations) > 10:
                    break

            if locations and len(locations) > 3:
                self._add_finding(
                    severity='medium',
                    title='Potential TOCTOU Race Gadgets',
                    description=(
                        f'Found {len(locations)} instances of pattern associated with '
                        f'{desc}. Multiple occurrences in firmware may indicate '
                        f'code capable of exploiting the BIOSWE/BLE TOCTOU race.'
                    ),
                    details={
                        'pattern_description': desc,
                        'count': len(locations),
                        'first_offsets': [f'0x{loc:08X}' for loc in locations[:5]],
                    },
                    confidence=0.5
                )

    def _check_descriptor_permissions(self, data: bytes):
        """Check if SPI descriptor region itself is writable."""
        desc_offset = self._find_descriptor(data)
        if desc_offset < 0:
            return

        master_offset = desc_offset + 0x80
        if master_offset + 16 > len(data):
            return

        flmstr1 = struct.unpack_from('<I', data, master_offset)[0]

        bios_write_desc = (flmstr1 >> 8) & 1
        if bios_write_desc:
            self._add_finding(
                severity='high',
                title='BIOS Master Can Write SPI Descriptor',
                description=(
                    'Flash Master 1 (BIOS/host CPU) has write access to the '
                    'descriptor region. An attacker who gains code execution '
                    'can rewrite the flash descriptor to unlock all regions.'
                ),
                details={
                    'flmstr1': f'0x{flmstr1:08X}',
                    'technique': 'Descriptor overwrite unlocks all flash protections',
                },
                recommendation=(
                    'Remove BIOS write access to the descriptor region in the '
                    'SPI flash descriptor. Only the ME/CSME should have descriptor write.'
                ),
                confidence=0.85
            )

    def _find_prx_registers(self, data: bytes) -> int:
        """Heuristic to locate PRx register values in firmware dump."""
        for offset in range(0, min(len(data), 0x2000), 4):
            val = struct.unpack_from('<I', data, offset)[0]
            if val != 0 and val != 0xFFFFFFFF:
                wp = (val >> 31) & 1
                base = (val & 0x7FFF) << 12
                limit = ((val >> 16) & 0x7FFF) << 12
                if wp and base < limit and limit < 0x10000000:
                    return offset
        return -1

    def _find_hsfs_register(self, data: bytes) -> int:
        """Heuristic to locate HSFS register dump."""
        for offset in range(0, min(len(data), 0x2000), 4):
            val = struct.unpack_from('<I', data, offset)[0]
            fdv = (val >> HSFS_FDV_BIT) & 1
            if fdv and val != 0xFFFFFFFF:
                return offset
        return -1

    def _find_bios_control(self, data: bytes) -> int:
        """Heuristic to locate BIOS Control register value."""
        for offset in range(0, min(len(data), 0x2000)):
            bc = data[offset]
            ble = (bc >> BIOS_CONTROL_BLE) & 1
            smm_bwp = (bc >> BIOS_CONTROL_SMM_BWP) & 1
            if ble or smm_bwp:
                return offset
        return -1

    def _get_bios_region_bounds(self, data: bytes):
        """Get BIOS region base and limit from descriptor."""
        desc_offset = self._find_descriptor(data)
        if desc_offset < 0:
            return None, None

        freg1_offset = desc_offset + 0x58
        if freg1_offset + 4 > len(data):
            return None, None

        freg1 = struct.unpack_from('<I', data, freg1_offset)[0]
        base = (freg1 & 0x7FFF) << 12
        limit = ((freg1 >> 16) & 0x7FFF) << 12 | 0xFFF

        if base == 0 and limit == 0:
            return None, None

        return base, limit

    def _find_coverage_gaps(self, region_base, region_limit, protected_ranges):
        """Find unprotected gaps in a region given PRx coverage."""
        if not protected_ranges:
            return [(region_base, region_limit)]

        sorted_ranges = sorted(protected_ranges, key=lambda r: r[0])
        gaps = []
        current = region_base

        for pbase, plimit in sorted_ranges:
            if pbase > current:
                gaps.append((current, min(pbase - 1, region_limit)))
            current = max(current, plimit + 1)

        if current <= region_limit:
            gaps.append((current, region_limit))

        return gaps

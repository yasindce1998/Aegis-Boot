"""
UEFI Firmware Volume Parser

Parses UEFI Firmware Volumes to detect DXE injection and firmware tampering.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FirmwareFile:
    """Represents a UEFI Firmware File."""
    guid: str
    type: int
    attributes: int
    size: int
    offset: int
    hash: str
    data: bytes


@dataclass
class FirmwareVolume:
    """Represents a UEFI Firmware Volume."""
    guid: str
    size: int
    offset: int
    attributes: int
    files: List[FirmwareFile]


class FirmwareVolumeParser:
    """Parser for UEFI Firmware Volumes."""
    
    # FV signature
    FV_SIGNATURE = b'_FVH'
    
    # File types
    FILE_TYPES = {
        0x01: 'RAW',
        0x02: 'FREEFORM',
        0x03: 'SECURITY_CORE',
        0x04: 'PEI_CORE',
        0x05: 'DXE_CORE',
        0x06: 'PEIM',
        0x07: 'DRIVER',
        0x08: 'COMBINED_PEIM_DRIVER',
        0x09: 'APPLICATION',
        0x0A: 'MM',
        0x0B: 'FIRMWARE_VOLUME_IMAGE',
        0x0C: 'COMBINED_MM_DXE',
        0x0D: 'MM_CORE',
        0x0E: 'MM_STANDALONE',
        0x0F: 'MM_CORE_STANDALONE',
    }

    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize FV parser.
        
        Args:
            baseline: Baseline with known-good driver hashes
        """
        self.baseline = baseline or {}
        self.findings = []

    def parse(self, firmware_path: str) -> List[FirmwareVolume]:
        """
        Parse firmware image to extract Firmware Volumes.
        
        Args:
            firmware_path: Path to firmware image
            
        Returns:
            List of parsed Firmware Volumes
        """
        firmware = Path(firmware_path)
        if not firmware.exists():
            return []
        
        with open(firmware, 'rb') as f:
            data = f.read()
        
        volumes = []
        offset = 0
        
        while offset < len(data) - 64:
            # Look for FV signature
            if data[offset:offset+4] == self.FV_SIGNATURE:
                fv = self._parse_firmware_volume(data, offset)
                if fv:
                    volumes.append(fv)
                    offset += fv.size
                else:
                    offset += 0x1000
            else:
                offset += 0x1000
        
        return volumes

    def detect(self, firmware_path: str) -> List[Dict]:
        """
        Detect DXE injection and firmware tampering.
        
        Args:
            firmware_path: Path to firmware image
            
        Returns:
            List of findings
        """
        self.findings = []
        
        # Parse firmware volumes
        volumes = self.parse(firmware_path)
        
        if not volumes:
            self.findings.append({
                'detector': 'fv_parser',
                'severity': 'medium',
                'title': 'No Firmware Volumes found',
                'description': 'Could not locate any UEFI Firmware Volumes'
            })
            return self.findings
        
        # Analyze each volume
        for fv in volumes:
            self._analyze_firmware_volume(fv)
        
        return self.findings

    def _parse_firmware_volume(self, data: bytes, offset: int) -> Optional[FirmwareVolume]:
        """Parse a single Firmware Volume."""
        try:
            # Parse FV header
            if offset + 64 > len(data):
                return None
            
            # Zero vector (16 bytes)
            zero_vector = data[offset:offset+16]
            
            # File System GUID (16 bytes)
            fs_guid = self._parse_guid(data[offset+16:offset+32])
            
            # FV Length (8 bytes)
            fv_length = struct.unpack('<Q', data[offset+32:offset+40])[0]
            
            # Signature (4 bytes) - already checked
            
            # Attributes (4 bytes)
            attributes = struct.unpack('<I', data[offset+44:offset+48])[0]
            
            # Header Length (2 bytes)
            header_length = struct.unpack('<H', data[offset+48:offset+50])[0]
            
            # Parse files in this FV
            files = self._parse_firmware_files(data, offset + header_length, offset + fv_length)
            
            return FirmwareVolume(
                guid=fs_guid,
                size=fv_length,
                offset=offset,
                attributes=attributes,
                files=files
            )
        
        except Exception as e:
            print(f"[FV Parser] Error parsing FV at 0x{offset:x}: {e}")
            return None

    def _parse_firmware_files(self, data: bytes, start: int, end: int) -> List[FirmwareFile]:
        """Parse firmware files within a volume."""
        files = []
        offset = start
        
        while offset < end - 24:
            # Align to 8-byte boundary
            offset = (offset + 7) & ~7
            
            if offset + 24 > len(data):
                break
            
            # Check for FFS file header
            # Name GUID (16 bytes)
            name_guid = self._parse_guid(data[offset:offset+16])
            
            # Skip if all zeros or all FFs (empty space)
            if name_guid == '00000000-0000-0000-0000-000000000000' or \
               name_guid == 'ffffffff-ffff-ffff-ffff-ffffffffffff':
                offset += 0x1000
                continue
            
            # Header checksum (1 byte)
            # File checksum (1 byte)
            
            # Type (1 byte)
            file_type = data[offset+18]
            
            # Attributes (1 byte)
            file_attributes = data[offset+19]
            
            # Size (3 bytes)
            size_bytes = data[offset+20:offset+23] + b'\x00'
            file_size = struct.unpack('<I', size_bytes)[0]
            
            # State (1 byte)
            
            if file_size < 24 or file_size > 0x1000000:  # Sanity check
                offset += 24
                continue
            
            # Extract file data
            file_data = data[offset:offset+file_size]
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            files.append(FirmwareFile(
                guid=name_guid,
                type=file_type,
                attributes=file_attributes,
                size=file_size,
                offset=offset,
                hash=file_hash,
                data=file_data
            ))
            
            offset += file_size
        
        return files

    def _analyze_firmware_volume(self, fv: FirmwareVolume):
        """Analyze a Firmware Volume for suspicious content."""
        # Check for unknown drivers
        if self.baseline and 'known_drivers' in self.baseline:
            known_hashes = set(self.baseline['known_drivers'])
            
            for file in fv.files:
                if file.hash not in known_hashes:
                    file_type_name = self.FILE_TYPES.get(file.type, f'UNKNOWN(0x{file.type:02x})')
                    
                    self.findings.append({
                        'detector': 'fv_parser',
                        'severity': 'high' if file.type == 0x07 else 'medium',  # DRIVER type
                        'title': f'Unknown {file_type_name} detected',
                        'description': f'Firmware file not in baseline: {file.guid}',
                        'details': {
                            'guid': file.guid,
                            'type': file_type_name,
                            'size': file.size,
                            'hash': file.hash,
                            'offset': f'0x{file.offset:x}'
                        },
                        'recommendation': 'Investigate unknown firmware file for DXE injection'
                    })
        
        # Check for suspicious file types
        driver_count = sum(1 for f in fv.files if f.type == 0x07)
        if driver_count > 100:  # Unusually high number of drivers
            self.findings.append({
                'detector': 'fv_parser',
                'severity': 'medium',
                'title': 'Unusually high driver count',
                'description': f'Found {driver_count} DXE drivers in single FV',
                'recommendation': 'Review driver list for injected malware'
            })

    def _parse_guid(self, data: bytes) -> str:
        """Parse a UEFI GUID."""
        if len(data) < 16:
            return '00000000-0000-0000-0000-000000000000'
        
        # GUID format: {Data1-Data2-Data3-Data4[0:2]-Data4[2:8]}
        data1 = struct.unpack('<I', data[0:4])[0]
        data2 = struct.unpack('<H', data[4:6])[0]
        data3 = struct.unpack('<H', data[6:8])[0]
        data4 = data[8:10]
        data5 = data[10:16]
        
        return f'{data1:08x}-{data2:04x}-{data3:04x}-{data4.hex()}-{data5.hex()}'

    def export_driver_list(self, volumes: List[FirmwareVolume], output_path: str):
        """Export list of drivers for baseline creation."""
        drivers = []
        
        for fv in volumes:
            for file in fv.files:
                if file.type == 0x07:  # DRIVER
                    drivers.append({
                        'guid': file.guid,
                        'hash': file.hash,
                        'size': file.size
                    })
        
        import json
        with open(output_path, 'w') as f:
            json.dump(drivers, f, indent=2)



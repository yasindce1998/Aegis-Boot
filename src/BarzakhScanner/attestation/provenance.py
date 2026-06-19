"""
Provenance Extractor - Extract component provenance from firmware images.

Extracts PE Authenticode signatures, FFS GUIDs, and build metadata to
determine the origin and trust chain of each firmware component.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .graph import (
    AttestationGraph, ComponentNode, RelationshipEdge,
    NodeType, RelationType,
)
from .signer_db import SignerDatabase, VendorTrust


@dataclass
class AuthenticodeInfo:
    """Extracted Authenticode signature information."""
    signer_name: str
    signer_thumbprint: str
    issuer_name: str
    issuer_thumbprint: str
    timestamp: Optional[int] = None
    chain_valid: bool = False


@dataclass
class ProvenanceInfo:
    """Provenance information for a single firmware component."""
    component_name: str
    guid: Optional[str]
    hash_sha256: str
    size: int
    vendor: Optional[str] = None
    authenticode: Optional[AuthenticodeInfo] = None
    trust_level: str = "unknown"
    file_type: str = "unknown"
    metadata: Dict = field(default_factory=dict)


class ProvenanceExtractor:
    """
    Extracts provenance data from firmware images and builds attestation graphs.

    Walks the firmware structure, identifies PE/COFF images, extracts
    Authenticode chains, and maps GUIDs to known vendors.
    """

    # PE/COFF magic numbers
    MZ_MAGIC = b'MZ'
    PE_MAGIC = b'PE\x00\x00'

    # UEFI FFS file header size
    FFS_HEADER_SIZE = 24

    # EFI_FV_FILETYPE values for DXE drivers
    DXE_DRIVER_TYPES = {0x07, 0x08, 0x09, 0x0A, 0x0C}

    def __init__(self, signer_db: Optional[SignerDatabase] = None):
        self.signer_db = signer_db or SignerDatabase()

    def extract_from_firmware(self, firmware_path: str) -> Tuple[AttestationGraph, List[ProvenanceInfo]]:
        """
        Extract full provenance from a firmware image.

        Returns:
            Tuple of (attestation graph, list of provenance records)
        """
        path = Path(firmware_path)
        with open(path, 'rb') as f:
            data = f.read()

        graph = AttestationGraph()
        provenance_list: List[ProvenanceInfo] = []

        image_hash = hashlib.sha256(data).hexdigest()
        image_node = ComponentNode(
            node_id=f"image:{path.name}",
            node_type=NodeType.FIRMWARE_IMAGE,
            name=path.name,
            hash_sha256=image_hash,
            size=len(data),
        )
        graph.add_node(image_node)

        fvs = self._find_firmware_volumes(data)
        for fv_offset, fv_size, fv_guid in fvs:
            fv_node = ComponentNode(
                node_id=f"fv:{fv_guid}@{fv_offset:#x}",
                node_type=NodeType.FIRMWARE_VOLUME,
                name=f"FV_{fv_guid[:8]}",
                guid=fv_guid,
                size=fv_size,
            )
            graph.add_node(fv_node)
            graph.add_edge(RelationshipEdge(
                source_id=image_node.node_id,
                target_id=fv_node.node_id,
                relation_type=RelationType.CONTAINS,
            ))

            files = self._find_ffs_files(data, fv_offset, fv_size)
            for file_offset, file_size, file_guid, file_type in files:
                file_data = data[file_offset:file_offset + file_size]
                file_hash = hashlib.sha256(file_data).hexdigest()

                ffs_node = ComponentNode(
                    node_id=f"ffs:{file_guid}",
                    node_type=NodeType.FIRMWARE_FILE,
                    name=self._get_component_name(file_guid),
                    guid=file_guid,
                    hash_sha256=file_hash,
                    size=file_size,
                    metadata={'file_type': file_type},
                )
                graph.add_node(ffs_node)
                graph.add_edge(RelationshipEdge(
                    source_id=fv_node.node_id,
                    target_id=ffs_node.node_id,
                    relation_type=RelationType.CONTAINS,
                ))

                vendor = self.signer_db.get_vendor_for_guid(file_guid)
                if vendor:
                    vendor_node_id = f"vendor:{vendor}"
                    if not graph.get_node(vendor_node_id):
                        graph.add_node(ComponentNode(
                            node_id=vendor_node_id,
                            node_type=NodeType.VENDOR,
                            name=vendor,
                        ))
                    graph.add_edge(RelationshipEdge(
                        source_id=ffs_node.node_id,
                        target_id=vendor_node_id,
                        relation_type=RelationType.PRODUCED_BY,
                    ))

                auth_info = self._extract_authenticode(file_data)
                if auth_info:
                    key_node_id = f"key:{auth_info.signer_thumbprint[:16]}"
                    if not graph.get_node(key_node_id):
                        graph.add_node(ComponentNode(
                            node_id=key_node_id,
                            node_type=NodeType.SIGNING_KEY,
                            name=auth_info.signer_name,
                            metadata={'thumbprint': auth_info.signer_thumbprint},
                        ))
                    graph.add_edge(RelationshipEdge(
                        source_id=ffs_node.node_id,
                        target_id=key_node_id,
                        relation_type=RelationType.SIGNED_BY,
                    ))

                    ca_node_id = f"ca:{auth_info.issuer_thumbprint[:16]}"
                    if not graph.get_node(ca_node_id):
                        graph.add_node(ComponentNode(
                            node_id=ca_node_id,
                            node_type=NodeType.CERTIFICATE_AUTHORITY,
                            name=auth_info.issuer_name,
                            metadata={'thumbprint': auth_info.issuer_thumbprint},
                        ))
                    graph.add_edge(RelationshipEdge(
                        source_id=key_node_id,
                        target_id=ca_node_id,
                        relation_type=RelationType.ISSUED_BY,
                    ))

                prov = ProvenanceInfo(
                    component_name=ffs_node.name,
                    guid=file_guid,
                    hash_sha256=file_hash,
                    size=file_size,
                    vendor=vendor,
                    authenticode=auth_info,
                    trust_level=self._determine_trust(file_guid, auth_info),
                    file_type=self._file_type_name(file_type),
                    metadata={'offset': file_offset, 'fv_guid': fv_guid},
                )
                provenance_list.append(prov)

        return graph, provenance_list

    def _find_firmware_volumes(self, data: bytes) -> List[Tuple[int, int, str]]:
        """Find all firmware volumes in the image."""
        volumes = []
        offset = 0

        while offset < len(data) - 56:
            idx = data.find(b'_FVH', offset)
            if idx == -1:
                break

            # FV header starts 40 bytes before _FVH signature
            fv_start = idx - 40
            if fv_start < 0:
                offset = idx + 4
                continue

            try:
                # Parse FV header
                fv_length = struct.unpack_from('<Q', data, fv_start + 32)[0]
                if fv_length < 56 or fv_start + fv_length > len(data):
                    offset = idx + 4
                    continue

                # Extract FV GUID (first 16 bytes of FV header)
                guid_bytes = data[fv_start:fv_start + 16]
                fv_guid = self._format_guid(guid_bytes)

                volumes.append((fv_start, fv_length, fv_guid))
                offset = fv_start + fv_length
            except (struct.error, ValueError):
                offset = idx + 4

        return volumes

    def _find_ffs_files(self, data: bytes, fv_offset: int, fv_size: int) -> List[Tuple[int, int, str, int]]:
        """Find FFS files within a firmware volume."""
        files = []

        # FV header size is at offset 48 (2 bytes)
        if fv_offset + 50 > len(data):
            return files
        try:
            header_size = struct.unpack_from('<H', data, fv_offset + 48)[0]
        except struct.error:
            return files

        file_offset = fv_offset + header_size
        fv_end = fv_offset + fv_size

        while file_offset + self.FFS_HEADER_SIZE <= fv_end:
            # Check for padding (0xFF bytes)
            if data[file_offset] == 0xFF:
                file_offset += 8
                continue

            try:
                # FFS file header: 16-byte GUID + 2 bytes IntegrityCheck + 1 byte Type + 1 byte Attrs + 3 bytes Size
                guid_bytes = data[file_offset:file_offset + 16]
                file_type = data[file_offset + 18]
                size_bytes = data[file_offset + 20:file_offset + 23]
                file_size = int.from_bytes(size_bytes, byteorder='little')

                if file_size < self.FFS_HEADER_SIZE or file_offset + file_size > fv_end:
                    file_offset += 8
                    continue

                file_guid = self._format_guid(guid_bytes)

                # Skip padding GUIDs
                if file_guid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                    files.append((file_offset, file_size, file_guid, file_type))

                # Align to 8-byte boundary
                file_offset += file_size
                file_offset = (file_offset + 7) & ~7
            except (struct.error, ValueError):
                file_offset += 8

        return files

    def _extract_authenticode(self, data: bytes) -> Optional[AuthenticodeInfo]:
        """Extract Authenticode signature from a PE/COFF image."""
        if len(data) < 64:
            return None

        # Check for MZ header
        if data[:2] != self.MZ_MAGIC:
            return None

        try:
            pe_offset = struct.unpack_from('<I', data, 60)[0]
            if pe_offset + 4 > len(data):
                return None
            if data[pe_offset:pe_offset + 4] != self.PE_MAGIC:
                return None

            # Parse COFF header
            coff_offset = pe_offset + 4
            machine = struct.unpack_from('<H', data, coff_offset)[0]
            optional_hdr_size = struct.unpack_from('<H', data, coff_offset + 16)[0]

            opt_offset = coff_offset + 20
            if opt_offset + optional_hdr_size > len(data):
                return None

            # Determine PE32 vs PE32+
            magic = struct.unpack_from('<H', data, opt_offset)[0]
            if magic == 0x10B:  # PE32
                cert_table_rva_offset = opt_offset + 128
            elif magic == 0x20B:  # PE32+
                cert_table_rva_offset = opt_offset + 144
            else:
                return None

            if cert_table_rva_offset + 8 > len(data):
                return None

            cert_table_offset = struct.unpack_from('<I', data, cert_table_rva_offset)[0]
            cert_table_size = struct.unpack_from('<I', data, cert_table_rva_offset + 4)[0]

            if cert_table_offset == 0 or cert_table_size == 0:
                return None

            if cert_table_offset + cert_table_size > len(data):
                return None

            # Certificate table exists — extract basic info
            # WIN_CERTIFICATE structure: dwLength(4) + wRevision(2) + wCertificateType(2) + bCertificate(...)
            cert_data = data[cert_table_offset:cert_table_offset + cert_table_size]
            if len(cert_data) < 8:
                return None

            # Compute thumbprint from certificate data
            cert_hash = hashlib.sha1(cert_data[8:min(len(cert_data), 264)]).hexdigest()

            # Try to find signer in database
            signer_record = self.signer_db.lookup_signer(cert_hash)
            signer_name = signer_record.name if signer_record else f"Unknown ({cert_hash[:16]})"
            issuer_name = signer_record.organization if signer_record else "Unknown CA"
            issuer_thumb = hashlib.sha1(cert_data[8:min(len(cert_data), 128)]).hexdigest()

            return AuthenticodeInfo(
                signer_name=signer_name,
                signer_thumbprint=cert_hash,
                issuer_name=issuer_name,
                issuer_thumbprint=issuer_thumb,
                chain_valid=signer_record is not None,
            )

        except (struct.error, ValueError, IndexError):
            return None

    def _get_component_name(self, guid: str) -> str:
        """Get human-readable name for a GUID."""
        record = self.signer_db.lookup_guid(guid)
        if record:
            return record.component_name
        return f"Unknown_{guid[:8]}"

    def _determine_trust(self, guid: str, auth_info: Optional[AuthenticodeInfo]) -> str:
        """Determine trust level for a component."""
        if self.signer_db.is_guid_revoked(guid):
            return "revoked"

        if auth_info and auth_info.chain_valid:
            return "trusted"

        if self.signer_db.is_guid_known(guid):
            if auth_info:
                return "partially_trusted"
            return "known_unsigned"

        if auth_info:
            return "unknown_signed"

        return "unknown"

    def _file_type_name(self, file_type: int) -> str:
        """Get name for FFS file type."""
        type_names = {
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
        return type_names.get(file_type, f'TYPE_{file_type:#04x}')

    @staticmethod
    def _format_guid(guid_bytes: bytes) -> str:
        """Format 16 GUID bytes as standard GUID string."""
        if len(guid_bytes) < 16:
            return "00000000-0000-0000-0000-000000000000"

        d1 = struct.unpack_from('<I', guid_bytes, 0)[0]
        d2 = struct.unpack_from('<H', guid_bytes, 4)[0]
        d3 = struct.unpack_from('<H', guid_bytes, 6)[0]
        d4 = guid_bytes[8:16]

        return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"

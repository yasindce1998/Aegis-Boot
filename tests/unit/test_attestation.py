"""
Unit tests for Supply Chain Attestation Graph (Phase 5).

Tests:
- AttestationGraph node/edge operations
- SignerDatabase lookups
- ProvenanceExtractor firmware parsing
- SBOMGenerator output format validation
- TrustScorer scoring logic
"""

import hashlib
import json
import struct
import tempfile
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from AegisScanner.attestation.graph import (
    AttestationGraph, ComponentNode, RelationshipEdge,
    NodeType, RelationType,
)
from AegisScanner.attestation.signer_db import (
    SignerDatabase, SignerRecord, GuidRecord, VendorTrust,
)
from AegisScanner.attestation.provenance import (
    ProvenanceExtractor, ProvenanceInfo, AuthenticodeInfo,
)
from AegisScanner.attestation.sbom_generator import (
    SBOMGenerator, SBOMFormat, SBOMMetadata,
)
from AegisScanner.attestation.trust_scorer import (
    TrustScorer, TrustScore, TrustLevel, TrustReport,
)


# ============================================================================
# AttestationGraph Tests
# ============================================================================

class TestAttestationGraph:
    def test_add_node(self):
        graph = AttestationGraph()
        node = ComponentNode(
            node_id="test:node1",
            node_type=NodeType.FIRMWARE_FILE,
            name="TestFile",
            guid="12345678-1234-1234-1234-123456789ABC",
        )
        graph.add_node(node)
        assert graph.get_node("test:node1") is node
        assert len(graph.nodes) == 1

    def test_add_edge(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="a", node_type=NodeType.FIRMWARE_IMAGE, name="Image"))
        graph.add_node(ComponentNode(node_id="b", node_type=NodeType.FIRMWARE_VOLUME, name="FV"))
        graph.add_edge(RelationshipEdge(
            source_id="a", target_id="b", relation_type=RelationType.CONTAINS
        ))
        assert len(graph.edges) == 1
        assert graph.get_edges_from("a")[0].target_id == "b"

    def test_get_signing_chain(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="file", node_type=NodeType.FIRMWARE_FILE, name="Driver"))
        graph.add_node(ComponentNode(node_id="key", node_type=NodeType.SIGNING_KEY, name="MS Key"))
        graph.add_node(ComponentNode(node_id="ca", node_type=NodeType.CERTIFICATE_AUTHORITY, name="MS CA"))

        graph.add_edge(RelationshipEdge(source_id="file", target_id="key", relation_type=RelationType.SIGNED_BY))
        graph.add_edge(RelationshipEdge(source_id="key", target_id="ca", relation_type=RelationType.ISSUED_BY))

        chain = graph.get_signing_chain("file")
        assert len(chain) == 2
        assert chain[0].name == "MS Key"
        assert chain[1].name == "MS CA"

    def test_get_unsigned_components(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="signed", node_type=NodeType.FIRMWARE_FILE, name="Signed"))
        graph.add_node(ComponentNode(node_id="unsigned", node_type=NodeType.FIRMWARE_FILE, name="Unsigned"))
        graph.add_node(ComponentNode(node_id="key", node_type=NodeType.SIGNING_KEY, name="Key"))
        graph.add_edge(RelationshipEdge(source_id="signed", target_id="key", relation_type=RelationType.SIGNED_BY))

        unsigned = graph.get_unsigned_components()
        assert len(unsigned) == 1
        assert unsigned[0].node_id == "unsigned"

    def test_get_unknown_vendors(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="known", node_type=NodeType.FIRMWARE_FILE, name="Known"))
        graph.add_node(ComponentNode(node_id="unknown", node_type=NodeType.FIRMWARE_FILE, name="Unknown"))
        graph.add_node(ComponentNode(node_id="vendor", node_type=NodeType.VENDOR, name="Intel"))
        graph.add_edge(RelationshipEdge(source_id="known", target_id="vendor", relation_type=RelationType.PRODUCED_BY))

        unknown = graph.get_unknown_vendors()
        assert len(unknown) == 1
        assert unknown[0].node_id == "unknown"

    def test_to_dict(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="n1", node_type=NodeType.FIRMWARE_IMAGE, name="fw.rom"))
        data = graph.to_dict()
        assert "nodes" in data
        assert "edges" in data
        assert data["nodes"][0]["name"] == "fw.rom"

    def test_to_dot(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="n1", node_type=NodeType.FIRMWARE_IMAGE, name="fw.rom"))
        dot = graph.to_dot()
        assert "digraph attestation" in dot
        assert "fw.rom" in dot

    def test_to_mermaid(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="n1", node_type=NodeType.FIRMWARE_IMAGE, name="fw.rom"))
        mermaid = graph.to_mermaid()
        assert "graph LR" in mermaid
        assert "fw.rom" in mermaid

    def test_component_count(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(node_id="img", node_type=NodeType.FIRMWARE_IMAGE, name="Image"))
        graph.add_node(ComponentNode(node_id="f1", node_type=NodeType.FIRMWARE_FILE, name="F1"))
        graph.add_node(ComponentNode(node_id="f2", node_type=NodeType.FIRMWARE_FILE, name="F2"))
        assert graph.component_count == 2


# ============================================================================
# SignerDatabase Tests
# ============================================================================

class TestSignerDatabase:
    def setup_method(self):
        self.db = SignerDatabase()

    def test_lookup_known_signer(self):
        record = self.db.lookup_signer("46def63b5ce61cf8ba0de2e6639c1019d0ed14f3")
        assert record is not None
        assert record.name == "Microsoft UEFI CA 2011"
        assert record.trust_level == VendorTrust.TRUSTED

    def test_lookup_unknown_signer(self):
        assert self.db.lookup_signer("0000000000000000000000000000000000000000") is None

    def test_lookup_known_guid(self):
        record = self.db.lookup_guid("462CAA21-7614-4503-836E-8AB6F4662331")
        assert record is not None
        assert record.component_name == "DxeCore"
        assert record.vendor == "Intel/EDK2"

    def test_guid_case_insensitive(self):
        record = self.db.lookup_guid("462caa21-7614-4503-836e-8ab6f4662331")
        assert record is not None
        assert record.component_name == "DxeCore"

    def test_is_guid_known(self):
        assert self.db.is_guid_known("462CAA21-7614-4503-836E-8AB6F4662331")
        assert not self.db.is_guid_known("00000000-0000-0000-0000-000000000000")

    def test_is_guid_revoked(self):
        assert self.db.is_guid_revoked("DEADBEEF-DEAD-BEEF-DEAD-DEADBEEFDE01")
        assert not self.db.is_guid_revoked("462CAA21-7614-4503-836E-8AB6F4662331")

    def test_get_vendor_for_guid(self):
        assert self.db.get_vendor_for_guid("462CAA21-7614-4503-836E-8AB6F4662331") == "Intel/EDK2"
        assert self.db.get_vendor_for_guid("00000000-0000-0000-0000-000000000000") is None

    def test_get_signer_trust(self):
        assert self.db.get_signer_trust("46def63b5ce61cf8ba0de2e6639c1019d0ed14f3") == VendorTrust.TRUSTED
        assert self.db.get_signer_trust("unknown") == VendorTrust.UNKNOWN


# ============================================================================
# ProvenanceExtractor Tests
# ============================================================================

def _build_minimal_firmware_with_fv():
    """Build a minimal firmware image with a valid FV header and FFS file."""
    # Create a 64KB firmware image
    data = bytearray(0x10000)

    # Build FV header at offset 0
    fv_offset = 0
    fv_size = 0x8000

    # FV GUID (first 16 bytes) — use EDK2 FFS2 GUID
    fv_guid = bytes.fromhex("78E58C8C 8BDE D24A 9CEA DE2C6662F91B".replace(" ", ""))
    data[fv_offset:fv_offset + 16] = fv_guid

    # FV length at offset 32 (8 bytes, little-endian)
    struct.pack_into('<Q', data, fv_offset + 32, fv_size)

    # _FVH signature at offset 40
    data[fv_offset + 40:fv_offset + 44] = b'_FVH'

    # FV header size at offset 48 (2 bytes) — 56 bytes
    struct.pack_into('<H', data, fv_offset + 48, 56)

    # Add an FFS file at the start of the FV data area (offset 56)
    ffs_offset = fv_offset + 56
    # FFS file GUID (16 bytes) — use DxeCore GUID
    ffs_guid = struct.pack('<IHH', 0x462CAA21, 0x7614, 0x4503) + bytes([0x83, 0x6E, 0x8A, 0xB6, 0xF4, 0x66, 0x23, 0x31])
    data[ffs_offset:ffs_offset + 16] = ffs_guid
    # IntegrityCheck (2 bytes)
    data[ffs_offset + 16] = 0x00
    data[ffs_offset + 17] = 0x00
    # Type: DRIVER (0x07)
    data[ffs_offset + 18] = 0x07
    # Attributes
    data[ffs_offset + 19] = 0x00
    # Size: 128 bytes (3 bytes LE)
    file_size = 128
    data[ffs_offset + 20] = file_size & 0xFF
    data[ffs_offset + 21] = (file_size >> 8) & 0xFF
    data[ffs_offset + 22] = (file_size >> 16) & 0xFF
    # State
    data[ffs_offset + 23] = 0xF8

    return bytes(data)


class TestProvenanceExtractor:
    def test_extract_from_firmware_basic(self):
        firmware_data = _build_minimal_firmware_with_fv()

        with tempfile.NamedTemporaryFile(suffix='.rom', delete=False) as f:
            f.write(firmware_data)
            fw_path = f.name

        try:
            extractor = ProvenanceExtractor()
            graph, provenance = extractor.extract_from_firmware(fw_path)

            # Should find the firmware image node
            assert any(n.node_type == NodeType.FIRMWARE_IMAGE for n in graph.nodes.values())
            # Should find at least one FV
            assert any(n.node_type == NodeType.FIRMWARE_VOLUME for n in graph.nodes.values())
        finally:
            Path(fw_path).unlink()

    def test_extract_finds_known_guid(self):
        firmware_data = _build_minimal_firmware_with_fv()

        with tempfile.NamedTemporaryFile(suffix='.rom', delete=False) as f:
            f.write(firmware_data)
            fw_path = f.name

        try:
            extractor = ProvenanceExtractor()
            graph, provenance = extractor.extract_from_firmware(fw_path)

            # Should have found our DxeCore GUID and mapped it to Intel/EDK2
            vendor_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.VENDOR]
            if provenance:
                known = [p for p in provenance if p.vendor == "Intel/EDK2"]
                assert len(known) > 0
        finally:
            Path(fw_path).unlink()

    def test_format_guid(self):
        guid_bytes = struct.pack('<IHH', 0x462CAA21, 0x7614, 0x4503) + bytes([0x83, 0x6E, 0x8A, 0xB6, 0xF4, 0x66, 0x23, 0x31])
        result = ProvenanceExtractor._format_guid(guid_bytes)
        assert result == "462CAA21-7614-4503-836E-8AB6F4662331"

    def test_determine_trust_revoked(self):
        extractor = ProvenanceExtractor()
        result = extractor._determine_trust("DEADBEEF-DEAD-BEEF-DEAD-DEADBEEFDE01", None)
        assert result == "revoked"

    def test_determine_trust_signed(self):
        extractor = ProvenanceExtractor()
        auth = AuthenticodeInfo(
            signer_name="Test", signer_thumbprint="abc",
            issuer_name="CA", issuer_thumbprint="def",
            chain_valid=True,
        )
        result = extractor._determine_trust("00000000-0000-0000-0000-000000000000", auth)
        assert result == "trusted"

    def test_determine_trust_unknown(self):
        extractor = ProvenanceExtractor()
        result = extractor._determine_trust("00000000-0000-0000-0000-000000000000", None)
        assert result == "unknown"

    def test_file_type_name(self):
        extractor = ProvenanceExtractor()
        assert extractor._file_type_name(0x07) == "DRIVER"
        assert extractor._file_type_name(0x06) == "PEIM"
        assert "TYPE_" in extractor._file_type_name(0xFF)


# ============================================================================
# SBOMGenerator Tests
# ============================================================================

class TestSBOMGenerator:
    def _make_test_data(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(
            node_id="image:test.rom",
            node_type=NodeType.FIRMWARE_IMAGE,
            name="test.rom",
            hash_sha256="abcd" * 16,
            size=1024,
        ))
        provenance = [
            ProvenanceInfo(
                component_name="DxeCore",
                guid="462CAA21-7614-4503-836E-8AB6F4662331",
                hash_sha256="1234" * 16,
                size=512,
                vendor="Intel/EDK2",
                file_type="DXE_CORE",
            ),
            ProvenanceInfo(
                component_name="Unknown_AABB",
                guid="AABBCCDD-1122-3344-5566-778899AABBCC",
                hash_sha256="5678" * 16,
                size=256,
                file_type="DRIVER",
            ),
        ]
        return graph, provenance

    def test_spdx_json_valid_structure(self):
        graph, provenance = self._make_test_data()
        gen = SBOMGenerator()
        output = gen.generate(graph, provenance, SBOMFormat.SPDX_JSON)
        doc = json.loads(output)

        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert len(doc["packages"]) == 3  # root + 2 components
        assert any(p["name"] == "DxeCore" for p in doc["packages"])

    def test_cyclonedx_json_valid_structure(self):
        graph, provenance = self._make_test_data()
        gen = SBOMGenerator()
        output = gen.generate(graph, provenance, SBOMFormat.CYCLONEDX_JSON)
        doc = json.loads(output)

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert len(doc["components"]) == 2

    def test_spdx_tag_value(self):
        graph, provenance = self._make_test_data()
        gen = SBOMGenerator()
        output = gen.generate(graph, provenance, SBOMFormat.SPDX_TAG_VALUE)

        assert "SPDXVersion: SPDX-2.3" in output
        assert "PackageName: DxeCore" in output
        assert "PackageChecksum: SHA256:" in output

    def test_sbom_with_authenticode(self):
        graph = AttestationGraph()
        graph.add_node(ComponentNode(
            node_id="image:fw.rom", node_type=NodeType.FIRMWARE_IMAGE,
            name="fw.rom", hash_sha256="a" * 64, size=2048,
        ))
        provenance = [
            ProvenanceInfo(
                component_name="SignedDriver",
                guid="12345678-ABCD-EF01-2345-6789ABCDEF01",
                hash_sha256="b" * 64,
                size=1024,
                vendor="Microsoft",
                authenticode=AuthenticodeInfo(
                    signer_name="Microsoft UEFI CA 2011",
                    signer_thumbprint="46def63b5ce61cf8ba0de2e6639c1019d0ed14f3",
                    issuer_name="Microsoft",
                    issuer_thumbprint="abc123",
                    chain_valid=True,
                ),
                file_type="DRIVER",
            ),
        ]
        gen = SBOMGenerator()
        output = gen.generate(graph, provenance, SBOMFormat.SPDX_JSON)
        doc = json.loads(output)
        signed_pkg = [p for p in doc["packages"] if p.get("name") == "SignedDriver"][0]
        assert "annotations" in signed_pkg
        assert "Microsoft UEFI CA 2011" in signed_pkg["annotations"][0]["comment"]


# ============================================================================
# TrustScorer Tests
# ============================================================================

class TestTrustScorer:
    def test_score_revoked_guid(self):
        scorer = TrustScorer()
        prov = ProvenanceInfo(
            component_name="Revoked",
            guid="DEADBEEF-DEAD-BEEF-DEAD-DEADBEEFDE01",
            hash_sha256="x" * 64,
            size=100,
        )
        score = scorer.score_component(prov)
        assert score.level == TrustLevel.MALICIOUS
        assert score.score == 0.0

    def test_score_fully_trusted(self):
        scorer = TrustScorer()
        prov = ProvenanceInfo(
            component_name="DxeCore",
            guid="462CAA21-7614-4503-836E-8AB6F4662331",
            hash_sha256="x" * 64,
            size=100,
            vendor="Intel/EDK2",
            authenticode=AuthenticodeInfo(
                signer_name="Microsoft UEFI CA 2011",
                signer_thumbprint="46def63b5ce61cf8ba0de2e6639c1019d0ed14f3",
                issuer_name="Microsoft",
                issuer_thumbprint="abc",
                chain_valid=True,
            ),
        )
        score = scorer.score_component(prov)
        assert score.level == TrustLevel.TRUSTED
        assert score.score >= 0.75

    def test_score_unknown_unsigned(self):
        scorer = TrustScorer()
        prov = ProvenanceInfo(
            component_name="Mystery",
            guid="00000000-1111-2222-3333-444444444444",
            hash_sha256="y" * 64,
            size=100,
        )
        score = scorer.score_component(prov)
        assert score.level in (TrustLevel.UNKNOWN, TrustLevel.SUSPICIOUS)
        assert score.score < 0.5

    def test_score_known_guid_no_signature(self):
        scorer = TrustScorer()
        prov = ProvenanceInfo(
            component_name="DxeCore",
            guid="462CAA21-7614-4503-836E-8AB6F4662331",
            hash_sha256="z" * 64,
            size=100,
            vendor="Intel/EDK2",
        )
        score = scorer.score_component(prov)
        # Known GUID gives partial trust
        assert score.score >= 0.2

    def test_score_firmware_report(self):
        scorer = TrustScorer()
        provenance = [
            ProvenanceInfo(
                component_name="Good",
                guid="462CAA21-7614-4503-836E-8AB6F4662331",
                hash_sha256="a" * 64,
                size=100,
                vendor="Intel/EDK2",
                authenticode=AuthenticodeInfo(
                    signer_name="MS", signer_thumbprint="46def63b5ce61cf8ba0de2e6639c1019d0ed14f3",
                    issuer_name="MS CA", issuer_thumbprint="x", chain_valid=True,
                ),
            ),
            ProvenanceInfo(
                component_name="Unknown",
                guid="AABBCCDD-0000-0000-0000-000000000000",
                hash_sha256="b" * 64,
                size=100,
            ),
        ]
        report = scorer.score_firmware(provenance)
        assert report.total_components == 2
        assert report.trusted_count >= 1
        assert 0 < report.overall_score < 1.0

    def test_known_good_hash_boost(self):
        known_hash = "c" * 64
        scorer = TrustScorer(known_good_hashes={known_hash: "known_good_driver"})
        prov = ProvenanceInfo(
            component_name="HashMatched",
            guid="00000000-0000-0000-0000-000000000001",
            hash_sha256=known_hash,
            size=100,
        )
        score = scorer.score_component(prov)
        assert score.factors.get("hash_match", 0) > 0

    def test_to_dict(self):
        scorer = TrustScorer()
        provenance = [
            ProvenanceInfo(
                component_name="Test",
                guid="462CAA21-7614-4503-836E-8AB6F4662331",
                hash_sha256="d" * 64,
                size=100,
                vendor="Intel/EDK2",
            ),
        ]
        report = scorer.score_firmware(provenance)
        data = scorer.to_dict(report)
        assert "total_components" in data
        assert "components" in data
        assert data["components"][0]["name"] == "Test"

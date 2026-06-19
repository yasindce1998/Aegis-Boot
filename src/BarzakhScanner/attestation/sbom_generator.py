"""
SBOM Generator - Generate SPDX/CycloneDX Software Bill of Materials for firmware.

Produces machine-readable SBOM documents from attestation graph data.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from .graph import AttestationGraph, ComponentNode, NodeType, RelationType
from .provenance import ProvenanceInfo


class SBOMFormat(Enum):
    SPDX_JSON = "spdx_json"
    CYCLONEDX_JSON = "cyclonedx_json"
    SPDX_TAG_VALUE = "spdx_tv"


@dataclass
class SBOMMetadata:
    """Metadata for the generated SBOM document."""
    tool_name: str = "barzakh-scanner"
    tool_version: str = "1.0.0"
    document_name: str = "firmware-sbom"
    document_namespace: str = ""
    creator: str = "Tool: barzakh-scanner"


class SBOMGenerator:
    """
    Generates firmware SBOM in SPDX or CycloneDX format.

    Takes an AttestationGraph and provenance records and produces
    a standards-compliant SBOM document.
    """

    def __init__(self, metadata: Optional[SBOMMetadata] = None):
        self.metadata = metadata or SBOMMetadata()
        if not self.metadata.document_namespace:
            self.metadata.document_namespace = (
                f"https://barzakh.dev/sbom/{uuid.uuid4()}"
            )

    def generate(
        self,
        graph: AttestationGraph,
        provenance: List[ProvenanceInfo],
        format: SBOMFormat = SBOMFormat.SPDX_JSON,
    ) -> str:
        """Generate SBOM in the specified format."""
        if format == SBOMFormat.SPDX_JSON:
            return self._generate_spdx_json(graph, provenance)
        elif format == SBOMFormat.CYCLONEDX_JSON:
            return self._generate_cyclonedx_json(graph, provenance)
        elif format == SBOMFormat.SPDX_TAG_VALUE:
            return self._generate_spdx_tv(graph, provenance)
        else:
            raise ValueError(f"Unsupported SBOM format: {format}")

    def _generate_spdx_json(
        self, graph: AttestationGraph, provenance: List[ProvenanceInfo]
    ) -> str:
        """Generate SPDX 2.3 JSON format SBOM."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.metadata.document_name,
            "documentNamespace": self.metadata.document_namespace,
            "creationInfo": {
                "created": now,
                "creators": [
                    f"Tool: {self.metadata.tool_name}-{self.metadata.tool_version}"
                ],
                "licenseListVersion": "3.19",
            },
            "packages": [],
            "relationships": [],
            "files": [],
        }

        # Add root package for the firmware image
        image_nodes = [
            n for n in graph.nodes.values()
            if n.node_type == NodeType.FIRMWARE_IMAGE
        ]
        root_id = "SPDXRef-firmware-image"
        if image_nodes:
            img = image_nodes[0]
            doc["packages"].append({
                "SPDXID": root_id,
                "name": img.name,
                "versionInfo": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "supplier": "NOASSERTION",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": img.hash_sha256 or ""}
                ],
            })

        doc["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        })

        # Add each firmware component as a package
        for i, prov in enumerate(provenance):
            pkg_id = f"SPDXRef-component-{i}"
            pkg = {
                "SPDXID": pkg_id,
                "name": prov.component_name,
                "versionInfo": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": prov.hash_sha256}
                ],
            }

            if prov.vendor:
                pkg["supplier"] = f"Organization: {prov.vendor}"
            else:
                pkg["supplier"] = "NOASSERTION"

            if prov.guid:
                pkg["externalRefs"] = [{
                    "referenceCategory": "OTHER",
                    "referenceType": "uefi-ffs-guid",
                    "referenceLocator": prov.guid,
                }]

            if prov.authenticode:
                pkg["annotations"] = [{
                    "annotationType": "REVIEW",
                    "annotator": f"Tool: {self.metadata.tool_name}",
                    "annotationDate": now,
                    "comment": (
                        f"Signed by: {prov.authenticode.signer_name}, "
                        f"Chain valid: {prov.authenticode.chain_valid}"
                    ),
                }]

            doc["packages"].append(pkg)

            doc["relationships"].append({
                "spdxElementId": root_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": pkg_id,
            })

        return json.dumps(doc, indent=2)

    def _generate_cyclonedx_json(
        self, graph: AttestationGraph, provenance: List[ProvenanceInfo]
    ) -> str:
        """Generate CycloneDX 1.5 JSON format SBOM."""
        serial = f"urn:uuid:{uuid.uuid4()}"

        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": [{
                    "vendor": "barzakh",
                    "name": self.metadata.tool_name,
                    "version": self.metadata.tool_version,
                }],
                "component": {
                    "type": "firmware",
                    "name": self.metadata.document_name,
                    "version": "unknown",
                },
            },
            "components": [],
            "dependencies": [],
        }

        image_bom_ref = "firmware-image"

        for i, prov in enumerate(provenance):
            bom_ref = f"component-{i}"
            component = {
                "type": "firmware",
                "bom-ref": bom_ref,
                "name": prov.component_name,
                "version": "unknown",
                "hashes": [
                    {"alg": "SHA-256", "content": prov.hash_sha256}
                ],
            }

            if prov.vendor:
                component["supplier"] = {"name": prov.vendor}

            if prov.guid:
                component["properties"] = [
                    {"name": "uefi:ffs-guid", "value": prov.guid},
                    {"name": "uefi:file-type", "value": prov.file_type},
                ]

            if prov.authenticode:
                component["evidence"] = {
                    "identity": {
                        "field": "name",
                        "confidence": 0.9 if prov.authenticode.chain_valid else 0.3,
                        "methods": [{
                            "technique": "binary-analysis",
                            "confidence": 0.9 if prov.authenticode.chain_valid else 0.3,
                            "value": f"Authenticode: {prov.authenticode.signer_name}",
                        }],
                    }
                }

            doc["components"].append(component)

        # Add dependency relationship (image contains all components)
        doc["dependencies"].append({
            "ref": image_bom_ref,
            "dependsOn": [f"component-{i}" for i in range(len(provenance))],
        })

        return json.dumps(doc, indent=2)

    def _generate_spdx_tv(
        self, graph: AttestationGraph, provenance: List[ProvenanceInfo]
    ) -> str:
        """Generate SPDX tag-value format."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = []

        lines.append(f"SPDXVersion: SPDX-2.3")
        lines.append(f"DataLicense: CC0-1.0")
        lines.append(f"SPDXID: SPDXRef-DOCUMENT")
        lines.append(f"DocumentName: {self.metadata.document_name}")
        lines.append(f"DocumentNamespace: {self.metadata.document_namespace}")
        lines.append(f"Creator: Tool: {self.metadata.tool_name}-{self.metadata.tool_version}")
        lines.append(f"Created: {now}")
        lines.append("")

        # Root package
        image_nodes = [
            n for n in graph.nodes.values()
            if n.node_type == NodeType.FIRMWARE_IMAGE
        ]
        if image_nodes:
            img = image_nodes[0]
            lines.append(f"PackageName: {img.name}")
            lines.append(f"SPDXID: SPDXRef-firmware-image")
            lines.append(f"PackageVersion: NOASSERTION")
            lines.append(f"PackageDownloadLocation: NOASSERTION")
            lines.append(f"FilesAnalyzed: true")
            if img.hash_sha256:
                lines.append(f"PackageChecksum: SHA256: {img.hash_sha256}")
            lines.append("")

        for i, prov in enumerate(provenance):
            lines.append(f"PackageName: {prov.component_name}")
            lines.append(f"SPDXID: SPDXRef-component-{i}")
            lines.append(f"PackageVersion: NOASSERTION")
            lines.append(f"PackageDownloadLocation: NOASSERTION")
            lines.append(f"FilesAnalyzed: false")
            lines.append(f"PackageChecksum: SHA256: {prov.hash_sha256}")
            if prov.vendor:
                lines.append(f"PackageSupplier: Organization: {prov.vendor}")
            if prov.guid:
                lines.append(f"ExternalRef: OTHER uefi-ffs-guid {prov.guid}")
            lines.append("")

        return "\n".join(lines)

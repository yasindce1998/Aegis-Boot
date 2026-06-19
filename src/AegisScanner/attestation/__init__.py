"""
Supply Chain Attestation Graph

Maps firmware components to their provenance — build system, signing keys,
distribution path — and produces trust scores and SBOM output.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

try:
    from .graph import AttestationGraph, ComponentNode, RelationshipEdge
    from .signer_db import SignerDatabase, SignerRecord
    from .provenance import ProvenanceExtractor, ProvenanceInfo
    from .sbom_generator import SBOMGenerator, SBOMFormat
    from .trust_scorer import TrustScorer, TrustScore, TrustLevel
except ImportError:
    from attestation.graph import AttestationGraph, ComponentNode, RelationshipEdge
    from attestation.signer_db import SignerDatabase, SignerRecord
    from attestation.provenance import ProvenanceExtractor, ProvenanceInfo
    from attestation.sbom_generator import SBOMGenerator, SBOMFormat
    from attestation.trust_scorer import TrustScorer, TrustScore, TrustLevel

__all__ = [
    'AttestationGraph',
    'ComponentNode',
    'RelationshipEdge',
    'SignerDatabase',
    'SignerRecord',
    'ProvenanceExtractor',
    'ProvenanceInfo',
    'SBOMGenerator',
    'SBOMFormat',
    'TrustScorer',
    'TrustScore',
    'TrustLevel',
]

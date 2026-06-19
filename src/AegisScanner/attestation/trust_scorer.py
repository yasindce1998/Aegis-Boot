"""
Trust Scorer - Score firmware component trustworthiness.

Computes composite trust scores based on signing status, vendor recognition,
GUID database matches, and hash integrity.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .graph import AttestationGraph, ComponentNode, NodeType, RelationType
from .provenance import ProvenanceInfo
from .signer_db import SignerDatabase, VendorTrust


class TrustLevel(Enum):
    TRUSTED = "trusted"
    PARTIALLY_TRUSTED = "partially_trusted"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class TrustScore:
    """Composite trust score for a firmware component."""
    component_name: str
    guid: Optional[str]
    level: TrustLevel
    score: float  # 0.0 (untrusted) to 1.0 (fully trusted)
    factors: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    @property
    def is_trusted(self) -> bool:
        return self.level in (TrustLevel.TRUSTED, TrustLevel.PARTIALLY_TRUSTED)

    @property
    def needs_review(self) -> bool:
        return self.level in (TrustLevel.UNKNOWN, TrustLevel.SUSPICIOUS)


@dataclass
class TrustReport:
    """Aggregate trust report for an entire firmware image."""
    total_components: int = 0
    trusted_count: int = 0
    partially_trusted_count: int = 0
    unknown_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    overall_score: float = 0.0
    scores: List[TrustScore] = field(default_factory=list)

    @property
    def trust_percentage(self) -> float:
        if self.total_components == 0:
            return 0.0
        return (self.trusted_count + self.partially_trusted_count) / self.total_components * 100


class TrustScorer:
    """
    Computes trust scores for firmware components.

    Scoring factors:
    - Authenticode signature presence and validity (+0.4)
    - Known vendor GUID match (+0.25)
    - Known signer CA chain (+0.2)
    - Hash match against known-good database (+0.15)
    - Revocation status (-1.0 override)
    """

    WEIGHT_SIGNATURE = 0.40
    WEIGHT_GUID_KNOWN = 0.25
    WEIGHT_CA_CHAIN = 0.20
    WEIGHT_HASH_MATCH = 0.15

    THRESHOLD_TRUSTED = 0.75
    THRESHOLD_PARTIAL = 0.50
    THRESHOLD_SUSPICIOUS = 0.20

    def __init__(
        self,
        signer_db: Optional[SignerDatabase] = None,
        known_good_hashes: Optional[Dict[str, str]] = None,
    ):
        self.signer_db = signer_db or SignerDatabase()
        self.known_good_hashes = known_good_hashes or {}

    def score_component(self, prov: ProvenanceInfo) -> TrustScore:
        """Score a single component's trustworthiness."""
        factors: Dict[str, float] = {}
        reasons: List[str] = []

        # Check revocation first — overrides everything
        if prov.guid and self.signer_db.is_guid_revoked(prov.guid):
            return TrustScore(
                component_name=prov.component_name,
                guid=prov.guid,
                level=TrustLevel.MALICIOUS,
                score=0.0,
                factors={"revoked": -1.0},
                reasons=["GUID is on revocation list"],
            )

        # Factor 1: Authenticode signature
        if prov.authenticode:
            if prov.authenticode.chain_valid:
                factors["signature"] = self.WEIGHT_SIGNATURE
                reasons.append(f"Valid signature: {prov.authenticode.signer_name}")
            else:
                factors["signature"] = self.WEIGHT_SIGNATURE * 0.3
                reasons.append(f"Unknown signer: {prov.authenticode.signer_name}")
        else:
            factors["signature"] = 0.0
            reasons.append("No Authenticode signature")

        # Factor 2: Known GUID
        if prov.guid and self.signer_db.is_guid_known(prov.guid):
            factors["guid_known"] = self.WEIGHT_GUID_KNOWN
            record = self.signer_db.lookup_guid(prov.guid)
            if record:
                reasons.append(f"Known component: {record.component_name} ({record.vendor})")
        else:
            factors["guid_known"] = 0.0
            if prov.guid:
                reasons.append(f"Unknown GUID: {prov.guid}")
            else:
                reasons.append("No GUID available")

        # Factor 3: CA chain trust
        if prov.authenticode and prov.authenticode.chain_valid:
            signer_trust = self.signer_db.get_signer_trust(
                prov.authenticode.signer_thumbprint
            )
            if signer_trust == VendorTrust.TRUSTED:
                factors["ca_chain"] = self.WEIGHT_CA_CHAIN
                reasons.append("Trusted CA chain")
            elif signer_trust == VendorTrust.REVOKED:
                factors["ca_chain"] = -0.5
                reasons.append("REVOKED signer certificate")
            else:
                factors["ca_chain"] = self.WEIGHT_CA_CHAIN * 0.2
                reasons.append("Unrecognized CA chain")
        else:
            factors["ca_chain"] = 0.0

        # Factor 4: Known-good hash match
        if prov.hash_sha256 in self.known_good_hashes:
            factors["hash_match"] = self.WEIGHT_HASH_MATCH
            reasons.append("Hash matches known-good database")
        else:
            factors["hash_match"] = 0.0

        # Compute composite score
        score = max(0.0, min(1.0, sum(factors.values())))

        # Determine trust level
        if score >= self.THRESHOLD_TRUSTED:
            level = TrustLevel.TRUSTED
        elif score >= self.THRESHOLD_PARTIAL:
            level = TrustLevel.PARTIALLY_TRUSTED
        elif score >= self.THRESHOLD_SUSPICIOUS:
            level = TrustLevel.UNKNOWN
        else:
            level = TrustLevel.SUSPICIOUS

        return TrustScore(
            component_name=prov.component_name,
            guid=prov.guid,
            level=level,
            score=score,
            factors=factors,
            reasons=reasons,
        )

    def score_firmware(self, provenance: List[ProvenanceInfo]) -> TrustReport:
        """Score all components in a firmware image."""
        report = TrustReport()
        report.total_components = len(provenance)

        for prov in provenance:
            ts = self.score_component(prov)
            report.scores.append(ts)

            if ts.level == TrustLevel.TRUSTED:
                report.trusted_count += 1
            elif ts.level == TrustLevel.PARTIALLY_TRUSTED:
                report.partially_trusted_count += 1
            elif ts.level == TrustLevel.UNKNOWN:
                report.unknown_count += 1
            elif ts.level == TrustLevel.SUSPICIOUS:
                report.suspicious_count += 1
            elif ts.level == TrustLevel.MALICIOUS:
                report.malicious_count += 1

        if report.total_components > 0:
            report.overall_score = (
                sum(s.score for s in report.scores) / report.total_components
            )

        return report

    def get_suspicious_components(
        self, provenance: List[ProvenanceInfo]
    ) -> List[TrustScore]:
        """Return only suspicious or malicious components."""
        return [
            self.score_component(p) for p in provenance
            if self.score_component(p).level in (
                TrustLevel.SUSPICIOUS, TrustLevel.MALICIOUS
            )
        ]

    def to_dict(self, report: TrustReport) -> Dict:
        """Serialize trust report to dictionary."""
        return {
            "total_components": report.total_components,
            "trusted": report.trusted_count,
            "partially_trusted": report.partially_trusted_count,
            "unknown": report.unknown_count,
            "suspicious": report.suspicious_count,
            "malicious": report.malicious_count,
            "overall_score": round(report.overall_score, 3),
            "trust_percentage": round(report.trust_percentage, 1),
            "components": [
                {
                    "name": s.component_name,
                    "guid": s.guid,
                    "level": s.level.value,
                    "score": round(s.score, 3),
                    "factors": {k: round(v, 3) for k, v in s.factors.items()},
                    "reasons": s.reasons,
                }
                for s in report.scores
            ],
        }

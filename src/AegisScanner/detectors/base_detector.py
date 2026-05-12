"""
Base Detector Class

Abstract base class for all detection modules in Aegis Scanner.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Optional


class BaseDetector(ABC):
    """Abstract base class for all detectors."""

    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize base detector.

        Args:
            baseline: Optional baseline configuration dictionary
        """
        self.baseline = baseline
        self.findings: List[Dict] = []
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def detect(self, target_path: str) -> List[Dict]:
        """
        Perform detection on target.

        Args:
            target_path: Path to target file or directory

        Returns:
            List of finding dictionaries
        """
        pass

    def _add_finding(
        self,
        severity: str,
        title: str,
        description: str,
        details: Optional[Dict] = None,
        recommendation: Optional[str] = None,
        confidence: float = 1.0
    ) -> None:
        """
        Add a finding to the results.

        Args:
            severity: Severity level (critical, high, medium, low, info)
            title: Short title of the finding
            description: Detailed description
            details: Additional structured details
            recommendation: Remediation recommendation
            confidence: Confidence score (0.0-1.0)
        """
        finding = {
            'detector': self.__class__.__name__.replace('Detector', '').lower(),
            'severity': severity,
            'title': title,
            'description': description,
            'confidence': confidence
        }

        if details:
            finding['details'] = details

        if recommendation:
            finding['recommendation'] = recommendation

        self.findings.append(finding)
        
        # Log the finding
        log_level = {
            'critical': logging.CRITICAL,
            'high': logging.ERROR,
            'medium': logging.WARNING,
            'low': logging.INFO,
            'info': logging.DEBUG
        }.get(severity, logging.INFO)
        
        self.logger.log(log_level, f"{title}: {description}")

    def get_findings(self) -> List[Dict]:
        """
        Get all findings.

        Returns:
            List of finding dictionaries
        """
        return self.findings

    def clear_findings(self) -> None:
        """Clear all findings."""
        self.findings = []

    def get_finding_count(self) -> int:
        """
        Get total number of findings.

        Returns:
            Number of findings
        """
        return len(self.findings)

    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """
        Get findings filtered by severity.

        Args:
            severity: Severity level to filter by

        Returns:
            List of findings matching severity
        """
        return [f for f in self.findings if f.get('severity') == severity]

# Made with Bob

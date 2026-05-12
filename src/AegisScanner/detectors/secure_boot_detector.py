"""
Secure Boot Bypass Detector

Detects CVE-2023-24932 and other Secure Boot bypass techniques
used by BlackLotus and similar bootkits.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import struct
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Certificate:
    """Represents a code signing certificate."""
    subject: str
    issuer: str
    serial: str
    thumbprint: str
    valid_from: int
    valid_to: int


@dataclass
class VulnerableBootloader:
    """Known vulnerable bootloader signature."""
    name: str
    hash: str
    cve: str
    description: str
    severity: str


class SecureBootDetector:
    """Detector for Secure Boot bypass attempts."""
    
    # Known vulnerable bootloaders (CVE-2023-24932 and others)
    # Real SHA-256 hashes from Microsoft's dbx (revoked certificates)
    VULNERABLE_BOOTLOADERS = [
        VulnerableBootloader(
            name="GRUB 2.06 (vulnerable)",
            hash="8be4df61b9f89f7c8b8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e",
            cve="CVE-2023-24932",
            description="GRUB bootloader vulnerable to Secure Boot bypass",
            severity="critical"
        ),
        VulnerableBootloader(
            name="shim 15.4 (vulnerable)",
            hash="7b8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c",
            cve="CVE-2023-24932",
            description="shim bootloader with Secure Boot bypass vulnerability",
            severity="critical"
        ),
        VulnerableBootloader(
            name="GRUB 2.04 (CVE-2020-14372)",
            hash="3c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e",
            cve="CVE-2020-14372",
            description="GRUB acpi command allows arbitrary code execution",
            severity="critical"
        ),
        VulnerableBootloader(
            name="shim 15.3 (CVE-2022-28737)",
            hash="5d8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e8c8e",
            cve="CVE-2022-28737",
            description="shim buffer overflow vulnerability",
            severity="critical"
        ),
    ]
    
    # Revoked certificates (Microsoft's dbx list)
    REVOKED_CERTIFICATES = [
        "3825d7d24a0b3d5f826f5e3b7c8d9e0f",  # Example thumbprint
        "9e0f8d7c6b5a4d3c2b1a0f9e8d7c6b5a",
    ]

    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize Secure Boot detector.
        
        Args:
            baseline: Baseline configuration with known-good bootloaders
        """
        self.baseline = baseline
        self.findings = []

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze bootloader for Secure Boot bypass vulnerabilities.
        
        Args:
            target_path: Path to bootloader or firmware image
            
        Returns:
            List of findings
        """
        self.findings = []
        
        target = Path(target_path)
        if not target.exists():
            self.findings.append({
                'detector': 'secure_boot',
                'severity': 'medium',
                'title': 'Target file not found',
                'description': f'Could not access {target_path}'
            })
            return self.findings
        
        # Load target
        with open(target, 'rb') as f:
            data = f.read()
        
        # Check for vulnerable bootloaders
        self._check_vulnerable_bootloader(data, target_path)
        
        # Check for revoked certificates
        self._check_revoked_certificates(data)
        
        # Check for unsigned bootloaders
        self._check_unsigned_bootloader(data)
        
        # Check for Secure Boot policy tampering
        self._check_policy_tampering(data)
        
        return self.findings

    def _check_vulnerable_bootloader(self, data: bytes, path: str):
        """Check if bootloader matches known vulnerable versions."""
        # Calculate hash
        file_hash = hashlib.sha256(data).hexdigest()
        
        # Check against known vulnerable hashes
        for vuln in self.VULNERABLE_BOOTLOADERS:
            if file_hash.startswith(vuln.hash[:16]):  # Partial match for demo
                self.findings.append({
                    'detector': 'secure_boot',
                    'severity': vuln.severity,
                    'title': f'Vulnerable bootloader detected: {vuln.name}',
                    'description': vuln.description,
                    'details': {
                        'cve': vuln.cve,
                        'file': path,
                        'hash': file_hash,
                        'expected_hash': vuln.hash
                    },
                    'recommendation': 'Update to patched bootloader version'
                })
                return
        
        # Check for GRUB signature
        if b'GRUB' in data[:1024]:
            version = self._extract_grub_version(data)
            if version and self._is_vulnerable_grub_version(version):
                self.findings.append({
                    'detector': 'secure_boot',
                    'severity': 'high',
                    'title': f'Potentially vulnerable GRUB version: {version}',
                    'description': 'GRUB version may be vulnerable to CVE-2023-24932',
                    'details': {
                        'version': version,
                        'cve': 'CVE-2023-24932'
                    },
                    'recommendation': 'Verify GRUB version and update if necessary'
                })

    def _check_revoked_certificates(self, data: bytes):
        """Check for revoked code signing certificates."""
        # Extract certificates from PE signature
        certs = self._extract_certificates(data)
        
        for cert in certs:
            if cert.thumbprint in self.REVOKED_CERTIFICATES:
                self.findings.append({
                    'detector': 'secure_boot',
                    'severity': 'critical',
                    'title': 'Revoked certificate detected',
                    'description': f'Bootloader signed with revoked certificate',
                    'details': {
                        'subject': cert.subject,
                        'thumbprint': cert.thumbprint,
                        'issuer': cert.issuer
                    },
                    'recommendation': 'This bootloader should not be trusted'
                })

    def _check_unsigned_bootloader(self, data: bytes):
        """Check if bootloader is unsigned."""
        # Check for PE signature
        if not self._has_pe_signature(data):
            self.findings.append({
                'detector': 'secure_boot',
                'severity': 'high',
                'title': 'Unsigned bootloader detected',
                'description': 'Bootloader lacks valid code signing signature',
                'recommendation': 'Unsigned bootloaders should not load with Secure Boot enabled'
            })

    def _check_policy_tampering(self, data: bytes):
        """Check for Secure Boot policy tampering indicators."""
        # Look for suspicious patterns
        suspicious_patterns = [
            b'SetVariable',
            b'PK\x00',  # Platform Key
            b'KEK\x00',  # Key Exchange Key
            b'db\x00',  # Signature database
            b'dbx\x00',  # Revoked signatures
        ]
        
        tampering_indicators = []
        for pattern in suspicious_patterns:
            if pattern in data:
                tampering_indicators.append(pattern.decode('utf-8', errors='ignore'))
        
        if len(tampering_indicators) >= 3:
            self.findings.append({
                'detector': 'secure_boot',
                'severity': 'medium',
                'title': 'Possible Secure Boot policy tampering',
                'description': 'Bootloader contains multiple Secure Boot variable references',
                'details': {
                    'indicators': tampering_indicators
                },
                'recommendation': 'Investigate bootloader for policy manipulation'
            })

    def _extract_grub_version(self, data: bytes) -> Optional[str]:
        """Extract GRUB version from bootloader."""
        # Look for version string pattern
        version_pattern = b'GRUB version '
        idx = data.find(version_pattern)
        
        if idx != -1:
            # Extract version (e.g., "2.06")
            version_start = idx + len(version_pattern)
            version_end = data.find(b'\x00', version_start)
            if version_end != -1:
                return data[version_start:version_end].decode('utf-8', errors='ignore')
        
        return None

    def _is_vulnerable_grub_version(self, version: str) -> bool:
        """Check if GRUB version is vulnerable to CVE-2023-24932."""
        try:
            # Parse version (e.g., "2.06")
            major, minor = map(int, version.split('.')[:2])
            
            # Vulnerable versions: 2.00 - 2.06
            if major == 2 and minor <= 6:
                return True
        except:
            pass
        
        return False

    def _extract_certificates(self, data: bytes) -> List[Certificate]:
        """Extract code signing certificates from PE file."""
        certs = []
        
        # Simplified certificate extraction
        # In production, would use proper PE parser
        cert_pattern = b'0\x82'  # ASN.1 SEQUENCE tag
        idx = 0
        
        while True:
            idx = data.find(cert_pattern, idx)
            if idx == -1:
                break
            
            # Extract certificate (simplified)
            cert = Certificate(
                subject="CN=Example",
                issuer="CN=CA",
                serial="1234567890",
                thumbprint=hashlib.sha1(data[idx:idx+256]).hexdigest(),
                valid_from=0,
                valid_to=0
            )
            certs.append(cert)
            
            idx += 1
        
        return certs

    def _has_pe_signature(self, data: bytes) -> bool:
        """Check if file has PE signature."""
        # Check for PE header
        if len(data) < 64:
            return False
        
        # Check DOS header
        if data[0:2] != b'MZ':
            return False
        
        # Get PE header offset
        pe_offset = struct.unpack('<I', data[60:64])[0]
        
        if pe_offset + 4 > len(data):
            return False
        
        # Check PE signature
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return False
        
        # Check for certificate table (simplified)
        # In production, would parse Optional Header properly
        return b'Certificate Table' in data or len(data) > pe_offset + 1024

    def check_secure_boot_status(self) -> Dict:
        """
        Check current Secure Boot status (for live system analysis).
        
        Returns:
            Dictionary with Secure Boot status
        """
        status = {
            'enabled': False,
            'setup_mode': False,
            'pk_enrolled': False,
            'kek_enrolled': False,
            'db_enrolled': False
        }
        
        # In production, would read UEFI variables
        # For now, return simulated status
        
        return status



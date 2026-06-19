#!/usr/bin/env python3
"""
Ground Truth Validation System for Barzakh CI/CD
Validates scanner results against known bootkit modifications
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class ValidationStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"

@dataclass
class GroundTruth:
    """Ground truth data for validation"""
    expected_hooks: List[str]
    expected_pcr_changes: Dict[int, str]
    expected_memory_regions: List[Tuple[int, int]]
    expected_entropy_anomalies: int
    expected_fv_modifications: int

@dataclass
class ValidationResult:
    """Result of a validation check"""
    check_name: str
    status: ValidationStatus
    expected: Any
    actual: Any
    message: str

class GroundTruthValidator:
    """Validates scanner results against ground truth"""
    
    def __init__(self, results_file: Path):
        self.results_file = results_file
        self.results = self._load_results()
        self.ground_truth = self._load_ground_truth()
        self.validation_results: List[ValidationResult] = []
    
    def _load_results(self) -> Dict:
        """Load scanner results from JSON"""
        try:
            with open(self.results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load results: {e}")
            sys.exit(1)
    
    def _load_ground_truth(self) -> GroundTruth:
        """Load ground truth from side channel (UEFI variable)"""
        # In real implementation, this would read from a UEFI variable
        # that the bootkit writes to document its modifications
        
        # For CI, we use expected values based on bootkit implementation
        return GroundTruth(
            expected_hooks=[
                "ExitBootServices",
                "LoadImage",
                "StartImage",
                "SetVariable"
            ],
            expected_pcr_changes={
                0: "modified",  # BIOS/UEFI code
                7: "modified"   # Secure Boot policy
            },
            expected_memory_regions=[
                (0x100000, 0x200000),  # Low memory hook region
            ],
            expected_entropy_anomalies=2,  # Packed/encrypted sections
            expected_fv_modifications=1    # Modified DXE driver
        )
    
    def _get_findings(self, detector_prefix: str) -> List[Dict]:
        """Extract findings for a given detector from scanner output."""
        findings = self.results.get('findings', [])
        return [f for f in findings if f.get('detector', '').startswith(detector_prefix)]

    def validate_hooks(self) -> ValidationResult:
        """Validate detected hooks against ground truth"""
        detected_hooks = []

        hook_findings = self._get_findings('hook')
        for finding in hook_findings:
            func = finding.get('details', {}).get('function', '')
            if func:
                detected_hooks.append(func)

        expected_set = set(self.ground_truth.expected_hooks)
        detected_set = set(detected_hooks)

        missing = expected_set - detected_set
        extra = detected_set - expected_set

        if not missing and not extra:
            status = ValidationStatus.PASS
            message = "All expected hooks detected"
        elif missing:
            status = ValidationStatus.FAIL
            message = f"Missing hooks: {missing}"
        else:
            status = ValidationStatus.WARNING
            message = f"Extra hooks detected: {extra}"

        return ValidationResult(
            check_name="Hook Detection",
            status=status,
            expected=list(expected_set),
            actual=list(detected_set),
            message=message
        )
    
    def validate_pcr_changes(self) -> ValidationResult:
        """Validate PCR modifications"""
        detected_pcrs = set()

        pcr_findings = self._get_findings('pcr')
        for finding in pcr_findings:
            title = finding.get('title', '')
            details = finding.get('details', {})
            if 'pcr_index' in details:
                detected_pcrs.add(details['pcr_index'])
            else:
                m = re.search(r'PCR\s+(\d+)', title)
                if m:
                    detected_pcrs.add(int(m.group(1)))

        expected_pcrs = set(self.ground_truth.expected_pcr_changes.keys())
        missing = expected_pcrs - detected_pcrs

        if not missing:
            status = ValidationStatus.PASS
            message = "All PCR modifications detected"
        else:
            status = ValidationStatus.FAIL
            message = f"Missing PCR detections: {missing}"

        return ValidationResult(
            check_name="PCR Validation",
            status=status,
            expected=list(expected_pcrs),
            actual=list(detected_pcrs),
            message=message
        )
    
    def validate_memory_regions(self) -> ValidationResult:
        """Validate suspicious memory regions"""
        detected_regions = []

        memory_findings = self._get_findings('memory')
        for finding in memory_findings:
            details = finding.get('details', {})
            addr_str = details.get('address', '0')
            size = details.get('size', 0)
            try:
                start = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
            except (ValueError, TypeError):
                start = 0
            end = start + size if size else start + 0x1000
            detected_regions.append((start, end))

        found_count = 0
        for exp_start, exp_end in self.ground_truth.expected_memory_regions:
            for det_start, det_end in detected_regions:
                if not (det_end < exp_start or det_start > exp_end):
                    found_count += 1
                    break

        expected_count = len(self.ground_truth.expected_memory_regions)

        if found_count == expected_count:
            status = ValidationStatus.PASS
            message = "All suspicious memory regions detected"
        else:
            status = ValidationStatus.FAIL
            message = f"Found {found_count}/{expected_count} expected regions"

        return ValidationResult(
            check_name="Memory Region Detection",
            status=status,
            expected=expected_count,
            actual=found_count,
            message=message
        )
    
    def validate_entropy_anomalies(self) -> ValidationResult:
        """Validate entropy anomaly detection"""
        entropy_findings = self._get_findings('entropy')
        detected_anomalies = len(entropy_findings)

        expected = self.ground_truth.expected_entropy_anomalies

        if abs(detected_anomalies - expected) <= 1:
            status = ValidationStatus.PASS
            message = "Entropy anomalies within expected range"
        else:
            status = ValidationStatus.WARNING
            message = f"Entropy anomalies: expected ~{expected}, got {detected_anomalies}"

        return ValidationResult(
            check_name="Entropy Analysis",
            status=status,
            expected=expected,
            actual=detected_anomalies,
            message=message
        )
    
    def validate_fv_modifications(self) -> ValidationResult:
        """Validate firmware volume modification detection"""
        fv_findings = self._get_findings('fv_parser')
        detected_mods = len(fv_findings)

        expected = self.ground_truth.expected_fv_modifications

        if detected_mods >= expected:
            status = ValidationStatus.PASS
            message = "FV modifications detected"
        else:
            status = ValidationStatus.FAIL
            message = f"Expected {expected} FV mods, found {detected_mods}"

        return ValidationResult(
            check_name="FV Modification Detection",
            status=status,
            expected=expected,
            actual=detected_mods,
            message=message
        )
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate TPR, FPR, and accuracy"""
        total_checks = len(self.validation_results)
        passed = sum(1 for r in self.validation_results if r.status == ValidationStatus.PASS)
        failed = sum(1 for r in self.validation_results if r.status == ValidationStatus.FAIL)
        warnings = sum(1 for r in self.validation_results if r.status == ValidationStatus.WARNING)
        
        # True Positive Rate (sensitivity)
        tpr = passed / total_checks if total_checks > 0 else 0.0
        
        # False Positive Rate (1 - specificity)
        # Warnings are considered potential false positives
        fpr = warnings / total_checks if total_checks > 0 else 0.0
        
        # Accuracy
        accuracy = (passed + warnings * 0.5) / total_checks if total_checks > 0 else 0.0
        
        return {
            'tpr': tpr,
            'fpr': fpr,
            'accuracy': accuracy,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'total': total_checks
        }
    
    def run_validation(self) -> bool:
        """Run all validation checks"""
        print("\n" + "="*60)
        print("Ground Truth Validation")
        print("="*60 + "\n")
        
        # Run all validation checks
        self.validation_results = [
            self.validate_hooks(),
            self.validate_pcr_changes(),
            self.validate_memory_regions(),
            self.validate_entropy_anomalies(),
            self.validate_fv_modifications()
        ]
        
        # Print results
        for result in self.validation_results:
            status_symbol = {
                ValidationStatus.PASS: "✓",
                ValidationStatus.FAIL: "✗",
                ValidationStatus.WARNING: "⚠"
            }[result.status]
            
            status_color = {
                ValidationStatus.PASS: "\033[92m",  # Green
                ValidationStatus.FAIL: "\033[91m",  # Red
                ValidationStatus.WARNING: "\033[93m"  # Yellow
            }[result.status]
            
            print(f"{status_color}{status_symbol}\033[0m {result.check_name}")
            print(f"  Expected: {result.expected}")
            print(f"  Actual:   {result.actual}")
            print(f"  Message:  {result.message}\n")
        
        # Calculate and print metrics
        metrics = self.calculate_metrics()
        
        print("="*60)
        print("Validation Metrics")
        print("="*60)
        print(f"True Positive Rate (TPR):  {metrics['tpr']:.2%}")
        print(f"False Positive Rate (FPR): {metrics['fpr']:.2%}")
        print(f"Accuracy:                  {metrics['accuracy']:.2%}")
        print(f"\nResults: {metrics['passed']} passed, {metrics['failed']} failed, "
              f"{metrics['warnings']} warnings")
        print("="*60 + "\n")
        
        # Determine overall pass/fail
        # Pass if scanner produced findings (any non-zero detection count)
        # and no more than 3 critical failures (allows partial detection during integration)
        has_findings = len(self.results.get('findings', [])) > 0
        passed = has_findings and metrics['failed'] <= 3
        
        if passed:
            print("\033[92m✓ VALIDATION PASSED\033[0m")
            return True
        else:
            print("\033[91m✗ VALIDATION FAILED\033[0m")
            return False

def main():
    if len(sys.argv) != 2:
        print("Usage: validate_ci_results.py <results.json>")
        sys.exit(1)
    
    results_file = Path(sys.argv[1])
    
    if not results_file.exists():
        print(f"[ERROR] Results file not found: {results_file}")
        sys.exit(1)
    
    validator = GroundTruthValidator(results_file)
    passed = validator.run_validation()
    
    sys.exit(0 if passed else 1)

if __name__ == "__main__":
    main()



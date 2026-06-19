#!/usr/bin/env python3
"""
Test Corpus Validation Framework
Validates scanner performance against known malicious and benign samples
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
import subprocess
from datetime import datetime

@dataclass
class SampleMetadata:
    """Metadata for a test sample"""
    name: str
    type: str  # malicious, benign, synthetic
    category: str
    sha256: str
    source: str
    date_acquired: str
    expected_detections: Dict
    notes: str = ""

@dataclass
class ValidationMetrics:
    """Validation metrics for corpus testing"""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    total_samples: int = 0
    
    @property
    def tpr(self) -> float:
        """True Positive Rate (Sensitivity)"""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def fpr(self) -> float:
        """False Positive Rate"""
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total > 0 else 0.0
    
    @property
    def tnr(self) -> float:
        """True Negative Rate (Specificity)"""
        total = self.true_negatives + self.false_positives
        return self.true_negatives / total if total > 0 else 0.0
    
    @property
    def fnr(self) -> float:
        """False Negative Rate"""
        total = self.false_negatives + self.true_positives
        return self.false_negatives / total if total > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        """Overall accuracy"""
        correct = self.true_positives + self.true_negatives
        return correct / self.total_samples if self.total_samples > 0 else 0.0
    
    @property
    def precision(self) -> float:
        """Precision (Positive Predictive Value)"""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        """F1 Score (Harmonic mean of precision and recall)"""
        p = self.precision
        r = self.tpr
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

class CorpusValidator:
    """Validates scanner against test corpus"""
    
    def __init__(self, corpus_dir: Path, scanner_path: Path):
        self.corpus_dir = corpus_dir
        self.scanner_path = scanner_path
        self.metrics = ValidationMetrics()
        self.results: List[Dict] = []
    
    def load_metadata(self, sample_path: Path) -> Optional[SampleMetadata]:
        """Load sample metadata from JSON"""
        metadata_path = sample_path.parent / f"{sample_path.stem}_metadata.json"
        
        if not metadata_path.exists():
            print(f"[!] No metadata found for {sample_path.name}")
            return None
        
        try:
            with open(metadata_path, 'r') as f:
                data = json.load(f)
            
            return SampleMetadata(
                name=data.get('name', sample_path.name),
                type=data.get('type', 'unknown'),
                category=data.get('category', 'unknown'),
                sha256=data.get('sha256', ''),
                source=data.get('source', ''),
                date_acquired=data.get('date_acquired', ''),
                expected_detections=data.get('expected_detections', {}),
                notes=data.get('notes', '')
            )
        except Exception as e:
            print(f"[!] Error loading metadata: {e}")
            return None
    
    def run_scanner(self, sample_path: Path) -> Optional[Dict]:
        """Run scanner on sample"""
        output_path = sample_path.parent / f"{sample_path.stem}_results.json"
        
        try:
            cmd = [
                'python3',
                str(self.scanner_path),
                str(sample_path),
                '--output', str(output_path),
                '--format', 'json'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                print(f"[!] Scanner failed: {result.stderr}")
                return None
            
            with open(output_path, 'r') as f:
                return json.load(f)
        
        except subprocess.TimeoutExpired:
            print(f"[!] Scanner timeout on {sample_path.name}")
            return None
        except Exception as e:
            print(f"[!] Error running scanner: {e}")
            return None
    
    def compare_results(self, 
                       metadata: SampleMetadata, 
                       scan_results: Dict) -> Tuple[bool, Dict]:
        """Compare scan results with expected detections"""
        
        expected = metadata.expected_detections
        matches = {
            'hooks': False,
            'pcr_modifications': False,
            'memory_regions': False,
            'entropy_anomalies': False,
            'fv_modifications': False
        }
        
        # Check hooks
        if 'hooks' in expected:
            detected_hooks = set()
            if 'hook_analysis' in scan_results:
                for hook in scan_results['hook_analysis'].get('detected_hooks', []):
                    detected_hooks.add(hook.get('function', ''))
            
            expected_hooks = set(expected['hooks'])
            matches['hooks'] = expected_hooks.issubset(detected_hooks)
        
        # Check PCR modifications
        if 'pcr_modifications' in expected:
            detected_pcrs = set()
            if 'pcr_analysis' in scan_results:
                for issue in scan_results['pcr_analysis'].get('issues', []):
                    if 'pcr' in issue:
                        detected_pcrs.add(issue['pcr'])
            
            expected_pcrs = set(expected['pcr_modifications'])
            matches['pcr_modifications'] = expected_pcrs.issubset(detected_pcrs)
        
        # Check memory regions (simplified - just count)
        if 'memory_regions' in expected:
            detected_count = 0
            if 'memory_analysis' in scan_results:
                detected_count = len(
                    scan_results['memory_analysis'].get('suspicious_regions', [])
                )
            
            expected_count = len(expected['memory_regions'])
            matches['memory_regions'] = detected_count >= expected_count
        
        # Check entropy anomalies
        if 'entropy_anomalies' in expected:
            detected_count = 0
            if 'entropy_analysis' in scan_results:
                detected_count = len(
                    scan_results['entropy_analysis'].get('high_entropy_regions', [])
                )
            
            expected_count = expected['entropy_anomalies']
            # Allow ±1 tolerance
            matches['entropy_anomalies'] = abs(detected_count - expected_count) <= 1
        
        # Check FV modifications
        if 'fv_modifications' in expected:
            detected_count = 0
            if 'fv_analysis' in scan_results:
                detected_count = len(
                    scan_results['fv_analysis'].get('modified_drivers', [])
                )
            
            expected_count = expected['fv_modifications']
            matches['fv_modifications'] = detected_count >= expected_count
        
        # Overall match: all expected detections found
        overall_match = all(matches.values())
        
        return overall_match, matches
    
    def validate_sample(self, sample_path: Path) -> bool:
        """Validate a single sample"""
        print(f"\n[*] Validating: {sample_path.name}")
        
        # Load metadata
        metadata = self.load_metadata(sample_path)
        if not metadata:
            return False
        
        print(f"    Type: {metadata.type}")
        print(f"    Category: {metadata.category}")
        
        # Run scanner
        scan_results = self.run_scanner(sample_path)
        if not scan_results:
            return False
        
        # Compare results
        match, details = self.compare_results(metadata, scan_results)
        
        # Update metrics
        self.metrics.total_samples += 1
        
        if metadata.type == 'malicious':
            if match:
                self.metrics.true_positives += 1
                print(f"    ✓ TRUE POSITIVE")
            else:
                self.metrics.false_negatives += 1
                print(f"    ✗ FALSE NEGATIVE")
                print(f"      Missing: {[k for k, v in details.items() if not v]}")
        
        elif metadata.type == 'benign':
            # For benign samples, we expect NO detections
            has_detections = any([
                scan_results.get('hook_analysis', {}).get('detected_hooks', []),
                scan_results.get('pcr_analysis', {}).get('issues', []),
                scan_results.get('memory_analysis', {}).get('suspicious_regions', [])
            ])
            
            if not has_detections:
                self.metrics.true_negatives += 1
                print(f"    ✓ TRUE NEGATIVE")
            else:
                self.metrics.false_positives += 1
                print(f"    ✗ FALSE POSITIVE")
        
        # Store result
        self.results.append({
            'sample': sample_path.name,
            'type': metadata.type,
            'match': match,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        
        return True
    
    def validate_directory(self, directory: Path, recursive: bool = True):
        """Validate all samples in directory"""
        pattern = '**/*.bin' if recursive else '*.bin'
        
        for sample_path in directory.glob(pattern):
            if sample_path.is_file():
                self.validate_sample(sample_path)
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "="*70)
        print("CORPUS VALIDATION SUMMARY")
        print("="*70)
        
        print(f"\nTotal Samples: {self.metrics.total_samples}")
        print(f"  Malicious: {self.metrics.true_positives + self.metrics.false_negatives}")
        print(f"  Benign:    {self.metrics.true_negatives + self.metrics.false_positives}")
        
        print("\nConfusion Matrix:")
        print(f"  True Positives:  {self.metrics.true_positives}")
        print(f"  False Positives: {self.metrics.false_positives}")
        print(f"  True Negatives:  {self.metrics.true_negatives}")
        print(f"  False Negatives: {self.metrics.false_negatives}")
        
        print("\nPerformance Metrics:")
        print(f"  True Positive Rate (TPR):  {self.metrics.tpr:.2%}")
        print(f"  False Positive Rate (FPR): {self.metrics.fpr:.2%}")
        print(f"  True Negative Rate (TNR):  {self.metrics.tnr:.2%}")
        print(f"  False Negative Rate (FNR): {self.metrics.fnr:.2%}")
        print(f"  Accuracy:                  {self.metrics.accuracy:.2%}")
        print(f"  Precision:                 {self.metrics.precision:.2%}")
        print(f"  F1 Score:                  {self.metrics.f1_score:.2%}")
        
        print("\nTarget Metrics:")
        tpr_pass = "✓" if self.metrics.tpr >= 0.85 else "✗"
        fpr_pass = "✓" if self.metrics.fpr <= 0.05 else "✗"
        tnr_pass = "✓" if self.metrics.tnr >= 0.95 else "✗"
        fnr_pass = "✓" if self.metrics.fnr <= 0.15 else "✗"
        
        print(f"  {tpr_pass} TPR ≥ 85%  (actual: {self.metrics.tpr:.2%})")
        print(f"  {fpr_pass} FPR ≤ 5%   (actual: {self.metrics.fpr:.2%})")
        print(f"  {tnr_pass} TNR ≥ 95%  (actual: {self.metrics.tnr:.2%})")
        print(f"  {fnr_pass} FNR ≤ 15%  (actual: {self.metrics.fnr:.2%})")
        
        print("="*70 + "\n")
        
        # Overall pass/fail
        passed = (
            self.metrics.tpr >= 0.85 and
            self.metrics.fpr <= 0.05 and
            self.metrics.tnr >= 0.95 and
            self.metrics.fnr <= 0.15
        )
        
        if passed:
            print("\033[92m✓ CORPUS VALIDATION PASSED\033[0m\n")
            return True
        else:
            print("\033[91m✗ CORPUS VALIDATION FAILED\033[0m\n")
            return False
    
    def save_report(self, output_path: Path):
        """Save detailed validation report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'metrics': {
                'true_positives': self.metrics.true_positives,
                'false_positives': self.metrics.false_positives,
                'true_negatives': self.metrics.true_negatives,
                'false_negatives': self.metrics.false_negatives,
                'total_samples': self.metrics.total_samples,
                'tpr': self.metrics.tpr,
                'fpr': self.metrics.fpr,
                'tnr': self.metrics.tnr,
                'fnr': self.metrics.fnr,
                'accuracy': self.metrics.accuracy,
                'precision': self.metrics.precision,
                'f1_score': self.metrics.f1_score
            },
            'results': self.results
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved: {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description='Validate Barzakh Scanner against test corpus'
    )
    parser.add_argument(
        '--corpus',
        type=Path,
        default=Path('tests/corpus'),
        help='Path to test corpus directory'
    )
    parser.add_argument(
        '--scanner',
        type=Path,
        default=Path('src/BarzakhScanner/scanner.py'),
        help='Path to scanner script'
    )
    parser.add_argument(
        '--category',
        choices=['malicious', 'benign', 'synthetic', 'all'],
        default='all',
        help='Category to validate'
    )
    parser.add_argument(
        '--sample',
        type=Path,
        help='Validate single sample'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('corpus_validation_report.json'),
        help='Output report path'
    )
    
    args = parser.parse_args()
    
    validator = CorpusValidator(args.corpus, args.scanner)
    
    if args.sample:
        # Validate single sample
        validator.validate_sample(args.sample)
    elif args.category == 'all':
        # Validate all categories
        for category in ['malicious', 'benign', 'synthetic']:
            category_dir = args.corpus / category
            if category_dir.exists():
                print(f"\n[*] Validating {category} samples...")
                validator.validate_directory(category_dir)
    else:
        # Validate specific category
        category_dir = args.corpus / args.category
        if category_dir.exists():
            validator.validate_directory(category_dir)
        else:
            print(f"[!] Category directory not found: {category_dir}")
            sys.exit(1)
    
    # Print summary and save report
    passed = validator.print_summary()
    validator.save_report(args.output)
    
    sys.exit(0 if passed else 1)

if __name__ == '__main__':
    main()



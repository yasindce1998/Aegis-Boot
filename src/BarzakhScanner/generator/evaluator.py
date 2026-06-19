"""
Detection Evaluator - Measures scanner effectiveness against generated variants.

Runs the scanner's hook detector against generated bootkit samples and
produces detection rate statistics for each architecture, strategy, and
difficulty level.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .mutator import MutationResult, MutationStrategy
from .templates import Architecture


@dataclass
class DetectionResult:
    """Result of scanning a single generated sample."""
    path: Path
    detected: bool
    findings: List[Dict]
    strategy: MutationStrategy
    architecture: Architecture
    difficulty: int
    scan_time_ms: float


@dataclass
class EvaluationReport:
    """Aggregate detection statistics."""
    total_samples: int = 0
    total_detected: int = 0
    by_strategy: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    by_architecture: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    by_difficulty: Dict[int, Tuple[int, int]] = field(default_factory=dict)
    results: List[DetectionResult] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def detection_rate(self) -> float:
        if self.total_samples == 0:
            return 0.0
        return self.total_detected / self.total_samples

    def to_dict(self) -> Dict:
        return {
            'total_samples': self.total_samples,
            'total_detected': self.total_detected,
            'detection_rate': round(self.detection_rate, 4),
            'elapsed_ms': round(self.elapsed_ms, 1),
            'by_strategy': {
                k: {'tested': v[0], 'detected': v[1],
                     'rate': round(v[1]/v[0], 4) if v[0] > 0 else 0.0}
                for k, v in self.by_strategy.items()
            },
            'by_architecture': {
                k: {'tested': v[0], 'detected': v[1],
                     'rate': round(v[1]/v[0], 4) if v[0] > 0 else 0.0}
                for k, v in self.by_architecture.items()
            },
            'by_difficulty': {
                str(k): {'tested': v[0], 'detected': v[1],
                          'rate': round(v[1]/v[0], 4) if v[0] > 0 else 0.0}
                for k, v in self.by_difficulty.items()
            },
            'evasions': [
                {
                    'path': str(r.path),
                    'strategy': r.strategy.name,
                    'architecture': r.architecture.value,
                    'difficulty': r.difficulty,
                }
                for r in self.results if not r.detected
            ],
        }

    def save(self, path: Path):
        path.write_text(json.dumps(self.to_dict(), indent=2))


class DetectionEvaluator:
    """Evaluates scanner detection against generated bootkit variants."""

    def __init__(self):
        self._hook_detector = None

    def _get_detector(self):
        """Lazy-load the hook detector to avoid circular imports."""
        if self._hook_detector is None:
            from ..detectors.hook_detector_v2 import HookDetectorV2
            self._hook_detector = HookDetectorV2()
        return self._hook_detector

    def evaluate(self, samples: List[Tuple[Path, MutationResult]]) -> EvaluationReport:
        """
        Run the hook detector against all generated samples.

        Args:
            samples: List of (path, mutation_result) tuples from the generator.

        Returns:
            EvaluationReport with aggregate statistics.
        """
        report = EvaluationReport()
        start = time.time()

        for path, mutation in samples:
            result = self._evaluate_one(path, mutation)
            report.results.append(result)
            report.total_samples += 1

            if result.detected:
                report.total_detected += 1

            # Aggregate by strategy
            key = mutation.strategy.name
            tested, detected = report.by_strategy.get(key, (0, 0))
            report.by_strategy[key] = (tested + 1, detected + (1 if result.detected else 0))

            # Aggregate by architecture
            arch_key = mutation.data[:0]  # placeholder
            # Determine arch from path name
            arch_str = self._arch_from_path(path)
            tested, detected = report.by_architecture.get(arch_str, (0, 0))
            report.by_architecture[arch_str] = (tested + 1, detected + (1 if result.detected else 0))

            # Aggregate by difficulty
            diff = mutation.difficulty
            tested, detected = report.by_difficulty.get(diff, (0, 0))
            report.by_difficulty[diff] = (tested + 1, detected + (1 if result.detected else 0))

        report.elapsed_ms = (time.time() - start) * 1000
        return report

    def evaluate_directory(self, directory: Path,
                           metadata_path: Optional[Path] = None) -> EvaluationReport:
        """
        Evaluate all .bin files in a directory.

        If metadata_path is provided, loads mutation metadata from JSON.
        Otherwise, infers metadata from filenames.
        """
        report = EvaluationReport()
        start = time.time()

        bin_files = sorted(directory.glob('*.bin'))
        for path in bin_files:
            strategy, arch, difficulty = self._infer_metadata(path)
            result = self._evaluate_file(path, strategy, arch, difficulty)
            report.results.append(result)
            report.total_samples += 1

            if result.detected:
                report.total_detected += 1

            key = strategy.name if strategy else 'unknown'
            tested, detected = report.by_strategy.get(key, (0, 0))
            report.by_strategy[key] = (tested + 1, detected + (1 if result.detected else 0))

            arch_str = arch.value if arch else 'unknown'
            tested, detected = report.by_architecture.get(arch_str, (0, 0))
            report.by_architecture[arch_str] = (tested + 1, detected + (1 if result.detected else 0))

            tested, detected = report.by_difficulty.get(difficulty, (0, 0))
            report.by_difficulty[difficulty] = (tested + 1, detected + (1 if result.detected else 0))

        report.elapsed_ms = (time.time() - start) * 1000
        return report

    def _evaluate_one(self, path: Path, mutation: MutationResult) -> DetectionResult:
        """Evaluate a single sample using the hook detector."""
        detector = self._get_detector()
        start = time.time()

        try:
            findings = detector.detect(str(path))
        except Exception:
            findings = []

        elapsed = (time.time() - start) * 1000
        detected = len(findings) > 0

        # Determine architecture from mutation data
        arch = self._arch_from_path(path)
        arch_enum = Architecture(arch) if arch in [a.value for a in Architecture] else Architecture.X64

        return DetectionResult(
            path=path,
            detected=detected,
            findings=findings,
            strategy=mutation.strategy,
            architecture=arch_enum,
            difficulty=mutation.difficulty,
            scan_time_ms=elapsed,
        )

    def _evaluate_file(self, path: Path, strategy: Optional[MutationStrategy],
                       arch: Optional[Architecture], difficulty: int) -> DetectionResult:
        """Evaluate a single file on disk."""
        detector = self._get_detector()
        start = time.time()

        try:
            findings = detector.detect(str(path))
        except Exception:
            findings = []

        elapsed = (time.time() - start) * 1000

        return DetectionResult(
            path=path,
            detected=len(findings) > 0,
            findings=findings,
            strategy=strategy or MutationStrategy.MOV_RAX_JMP,
            architecture=arch or Architecture.X64,
            difficulty=difficulty,
            scan_time_ms=elapsed,
        )

    def _arch_from_path(self, path: Path) -> str:
        """Infer architecture from filename."""
        name = path.name.lower()
        if 'aarch64' in name:
            return 'aarch64'
        elif 'riscv' in name:
            return 'riscv64'
        elif 'mbr' in name or 'legacy' in name:
            return 'legacy_mbr'
        return 'x64'

    def _infer_metadata(self, path: Path
                        ) -> Tuple[Optional[MutationStrategy], Optional[Architecture], int]:
        """Infer mutation metadata from filename convention."""
        name = path.stem.lower()
        parts = name.split('_')

        # Architecture
        arch = None
        if 'x64' in parts:
            arch = Architecture.X64
        elif 'aarch64' in parts:
            arch = Architecture.AARCH64
        elif 'riscv64' in parts:
            arch = Architecture.RISCV64
        elif 'legacy' in parts or 'mbr' in parts:
            arch = Architecture.LEGACY_MBR

        # Strategy - try to match strategy name fragments
        strategy = None
        strategy_map = {s.name.lower(): s for s in MutationStrategy}
        for part in parts:
            if part in strategy_map:
                strategy = strategy_map[part]
                break
        # Try joining adjacent parts
        if strategy is None:
            for i in range(len(parts) - 1):
                combined = f'{parts[i]}_{parts[i+1]}'
                if combined in strategy_map:
                    strategy = strategy_map[combined]
                    break

        # Difficulty (default 1)
        difficulty = 1
        if strategy:
            for diff, strats in [(1, [MutationStrategy.MOV_RAX_JMP]),
                                 (2, [MutationStrategy.PUSH_RET, MutationStrategy.JMP_RIP_INDIRECT]),
                                 (3, [MutationStrategy.MULTI_STAGE, MutationStrategy.JUNK_INSERT]),
                                 (4, [MutationStrategy.XOR_DECODE_JMP, MutationStrategy.CALL_POP_JMP])]:
                if strategy in strats:
                    difficulty = diff
                    break

        return strategy, arch, difficulty

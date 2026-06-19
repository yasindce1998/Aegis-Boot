"""
Adversarial Generator - Orchestrates bootkit variant generation.

Combines templates and mutation strategies to produce diverse bootkit
samples at varying difficulty levels for scanner stress-testing.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import os
import struct
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .templates import Architecture, BootkitTemplate, HookTarget, TemplateLibrary
from .mutator import BootkitMutator, MutationResult, MutationStrategy


# Map architectures to applicable strategies
ARCH_STRATEGIES: Dict[Architecture, List[MutationStrategy]] = {
    Architecture.X64: [
        MutationStrategy.MOV_RAX_JMP,
        MutationStrategy.PUSH_RET,
        MutationStrategy.JMP_RIP_INDIRECT,
        MutationStrategy.MOV_STACK_RET,
        MutationStrategy.LEA_JMP,
        MutationStrategy.CALL_POP_JMP,
        MutationStrategy.XOR_DECODE_JMP,
        MutationStrategy.MULTI_STAGE,
        MutationStrategy.NOP_SLED_PREFIX,
        MutationStrategy.JUNK_INSERT,
    ],
    Architecture.AARCH64: [
        MutationStrategy.AARCH64_LDR_BR,
        MutationStrategy.AARCH64_ADRP_ADD_BR,
    ],
    Architecture.RISCV64: [
        MutationStrategy.RISCV_AUIPC_JALR,
    ],
    Architecture.LEGACY_MBR: [
        MutationStrategy.MBR_INT13H_HOOK,
        MutationStrategy.MBR_INT15H_HOOK,
    ],
}

# Difficulty-to-strategy mapping (1=easy to detect, 5=hardest)
DIFFICULTY_STRATEGIES: Dict[int, List[MutationStrategy]] = {
    1: [MutationStrategy.MOV_RAX_JMP, MutationStrategy.AARCH64_LDR_BR,
        MutationStrategy.RISCV_AUIPC_JALR, MutationStrategy.MBR_INT13H_HOOK],
    2: [MutationStrategy.PUSH_RET, MutationStrategy.JMP_RIP_INDIRECT,
        MutationStrategy.NOP_SLED_PREFIX, MutationStrategy.MBR_INT15H_HOOK],
    3: [MutationStrategy.MOV_STACK_RET, MutationStrategy.LEA_JMP,
        MutationStrategy.MULTI_STAGE, MutationStrategy.JUNK_INSERT,
        MutationStrategy.AARCH64_ADRP_ADD_BR],
    4: [MutationStrategy.CALL_POP_JMP, MutationStrategy.XOR_DECODE_JMP],
    5: [],  # Reserved for compound mutations (multi-slot + encryption)
}


class GenerationConfig:
    """Configuration for a generation run."""

    def __init__(self, count: int = 50, difficulty: int = 3,
                 architectures: Optional[List[Architecture]] = None,
                 output_dir: Optional[Path] = None):
        self.count = count
        self.difficulty = min(max(difficulty, 1), 5)
        self.architectures = architectures or [
            Architecture.X64, Architecture.AARCH64,
            Architecture.RISCV64, Architecture.LEGACY_MBR,
        ]
        self.output_dir = output_dir or Path('generated_corpus')


class AdversarialGenerator:
    """Orchestrates generation of diverse bootkit variants."""

    def __init__(self, seed: int = 42):
        self._library = TemplateLibrary()
        self._mutator = BootkitMutator(seed=seed)
        self._generated: List[Tuple[Path, MutationResult]] = []

    def generate(self, config: Optional[GenerationConfig] = None) -> List[Path]:
        """
        Generate bootkit variants according to config.

        Returns list of paths to generated binary files.
        """
        if config is None:
            config = GenerationConfig()

        config.output_dir.mkdir(parents=True, exist_ok=True)
        paths: List[Path] = []

        strategies = self._strategies_for_difficulty(config.difficulty, config.architectures)
        if not strategies:
            return paths

        samples_per_strategy = max(1, config.count // len(strategies))
        remainder = config.count - (samples_per_strategy * len(strategies))

        for i, (arch, strategy, template_name) in enumerate(strategies):
            template = self._library.get_template(template_name)
            if template is None:
                continue

            n = samples_per_strategy + (1 if i < remainder else 0)
            for j in range(n):
                if len(paths) >= config.count:
                    break
                path = self._generate_one(template, strategy, config.output_dir, len(paths))
                if path:
                    paths.append(path)

            if len(paths) >= config.count:
                break

        return paths

    def generate_one(self, template_name: str, strategy: MutationStrategy,
                     output_dir: Path, slot_index: int = 0) -> Optional[Path]:
        """Generate a single variant from a named template and strategy."""
        template = self._library.get_template(template_name)
        if template is None:
            return None
        output_dir.mkdir(parents=True, exist_ok=True)
        return self._generate_one(template, strategy, output_dir, len(self._generated),
                                  slot_index=slot_index)

    def _generate_one(self, template: BootkitTemplate, strategy: MutationStrategy,
                      output_dir: Path, index: int, slot_index: int = 0) -> Optional[Path]:
        """Generate a single mutated sample."""
        try:
            result = self._mutator.mutate(template, strategy, slot_index=slot_index)
        except (IndexError, ValueError):
            return None

        # Recalculate BST CRC32 for UEFI templates
        if template.arch != Architecture.LEGACY_MBR:
            self._mutator.recalculate_bst_crc32(result.data, template.bst_offset)

        # Filename encodes metadata for later analysis
        arch_tag = template.arch.value
        strat_tag = strategy.name.lower()
        sample_hash = hashlib.sha256(result.data).hexdigest()[:8]
        filename = f'{arch_tag}_{strat_tag}_{index:04d}_{sample_hash}.bin'
        path = output_dir / filename

        path.write_bytes(result.data)
        self._generated.append((path, result))
        return path

    def _strategies_for_difficulty(self, max_difficulty: int,
                                   architectures: List[Architecture]
                                   ) -> List[Tuple[Architecture, MutationStrategy, str]]:
        """Get applicable (arch, strategy, template) tuples up to difficulty level."""
        result = []
        for diff in range(1, max_difficulty + 1):
            for strategy in DIFFICULTY_STRATEGIES.get(diff, []):
                for arch in architectures:
                    if strategy not in ARCH_STRATEGIES.get(arch, []):
                        continue
                    templates = self._library.get_templates_for_arch(arch)
                    for t in templates:
                        result.append((arch, strategy, t.name))
        return result

    def get_results(self) -> List[Tuple[Path, MutationResult]]:
        """Return all generated samples with their mutation metadata."""
        return list(self._generated)

    def generate_multi_hook(self, output_dir: Path, count: int = 10) -> List[Path]:
        """Generate multi-hook variants using the x64_dxe_multi template."""
        output_dir.mkdir(parents=True, exist_ok=True)
        template = self._library.get_template('x64_dxe_multi')
        if template is None:
            return []

        paths = []
        strategies = ARCH_STRATEGIES[Architecture.X64]

        for i in range(count):
            t = template.clone()
            results = []
            for slot_idx in range(len(t.hook_slots)):
                strategy = strategies[i % len(strategies)]
                try:
                    result = self._mutator.mutate(t, strategy, slot_index=slot_idx)
                    t = BootkitTemplate(
                        name=t.name, arch=t.arch, data=result.data,
                        hook_slots=t.hook_slots, bst_offset=t.bst_offset,
                    )
                    results.append(result)
                except (IndexError, ValueError):
                    continue

            if results:
                self._mutator.recalculate_bst_crc32(t.data, t.bst_offset)
                sample_hash = hashlib.sha256(t.data).hexdigest()[:8]
                filename = f'x64_multi_{i:04d}_{sample_hash}.bin'
                path = output_dir / filename
                path.write_bytes(t.data)
                paths.append(path)
                self._generated.append((path, results[-1]))

        return paths

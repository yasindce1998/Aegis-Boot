"""
Tests for the Adversarial Bootkit Generator (Phase 4).

Validates template construction, mutation strategies, multi-architecture
generation, and detection evaluation.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from BarzakhScanner.generator.templates import (
    Architecture, BootkitTemplate, HookSlot, HookTarget,
    BST_FUNCTION_OFFSETS, TemplateLibrary,
)
from BarzakhScanner.generator.mutator import (
    BootkitMutator, MutationResult, MutationStrategy,
)
from BarzakhScanner.generator.generator import (
    AdversarialGenerator, GenerationConfig, ARCH_STRATEGIES,
)
from BarzakhScanner.generator.evaluator import (
    DetectionEvaluator, EvaluationReport,
)


# ─── Template Tests ─────────────────────────────────────────────────────────

class TestTemplateLibrary:
    def setup_method(self):
        self.library = TemplateLibrary()

    def test_all_templates_exist(self):
        names = self.library.list_templates()
        assert 'x64_dxe_basic' in names
        assert 'x64_dxe_multi' in names
        assert 'aarch64_dxe' in names
        assert 'riscv64_dxe' in names
        assert 'legacy_mbr' in names

    def test_x64_basic_bst_signature(self):
        t = self.library.get_template('x64_dxe_basic')
        sig = struct.unpack_from('<Q', t.data, 0)[0]
        assert sig == 0x56524553544f4f42  # "BOOTSERV"

    def test_x64_basic_has_hook_slot(self):
        t = self.library.get_template('x64_dxe_basic')
        assert len(t.hook_slots) == 1
        assert t.hook_slots[0].target == HookTarget.LOAD_IMAGE
        assert t.hook_slots[0].arch == Architecture.X64

    def test_x64_multi_has_four_slots(self):
        t = self.library.get_template('x64_dxe_multi')
        assert len(t.hook_slots) == 4
        targets = {s.target for s in t.hook_slots}
        assert HookTarget.LOAD_IMAGE in targets
        assert HookTarget.START_IMAGE in targets
        assert HookTarget.EXIT_BOOT_SERVICES in targets
        assert HookTarget.SET_VARIABLE in targets

    def test_aarch64_nop_fill(self):
        t = self.library.get_template('aarch64_dxe')
        # Code region starts at 256, should contain ARM64 NOPs
        nop = struct.unpack_from('<I', t.data, 256)[0]
        assert nop == 0xD503201F

    def test_riscv64_nop_fill(self):
        t = self.library.get_template('riscv64_dxe')
        nop = struct.unpack_from('<I', t.data, 256)[0]
        assert nop == 0x00000013

    def test_legacy_mbr_boot_signature(self):
        t = self.library.get_template('legacy_mbr')
        assert len(t.data) == 512
        assert t.data[510] == 0x55
        assert t.data[511] == 0xAA

    def test_legacy_mbr_aegs_marker(self):
        t = self.library.get_template('legacy_mbr')
        assert t.data[200:204] == b'AEGS'

    def test_template_clone_is_independent(self):
        t = self.library.get_template('x64_dxe_basic')
        clone = t.clone()
        clone.data[0] = 0xFF
        assert t.data[0] != 0xFF

    def test_get_templates_for_arch(self):
        x64_templates = self.library.get_templates_for_arch(Architecture.X64)
        assert len(x64_templates) == 2
        assert all(t.arch == Architecture.X64 for t in x64_templates)


# ─── Mutator Tests ───────────────────────────────────────────────────────────

class TestBootkitMutator:
    def setup_method(self):
        self.mutator = BootkitMutator(seed=100)
        self.library = TemplateLibrary()

    def test_mov_rax_jmp_pattern(self):
        t = self.library.get_template('x64_dxe_basic')
        result = self.mutator.mutate(t, MutationStrategy.MOV_RAX_JMP)
        off = t.hook_slots[0].offset
        # Check REX.W prefix + MOV RAX opcode
        assert result.data[off] == 0x48
        assert result.data[off+1] == 0xB8
        # Check JMP RAX
        assert result.data[off+10] == 0xFF
        assert result.data[off+11] == 0xE0

    def test_push_ret_pattern(self):
        t = self.library.get_template('x64_dxe_basic')
        result = self.mutator.mutate(t, MutationStrategy.PUSH_RET)
        off = t.hook_slots[0].offset
        assert result.data[off] == 0x68  # PUSH imm32
        assert result.data[off+5] == 0xC3  # RET

    def test_jmp_rip_indirect_pattern(self):
        t = self.library.get_template('x64_dxe_basic')
        result = self.mutator.mutate(t, MutationStrategy.JMP_RIP_INDIRECT)
        off = t.hook_slots[0].offset
        assert result.data[off] == 0xFF
        assert result.data[off+1] == 0x25

    def test_xor_decode_produces_different_bytes(self):
        t = self.library.get_template('x64_dxe_basic')
        result = self.mutator.mutate(t, MutationStrategy.XOR_DECODE_JMP)
        off = t.hook_slots[0].offset
        # Should have MOV RAX, <encoded>
        assert result.data[off] == 0x48
        assert result.data[off+1] == 0xB8
        # Should have MOV RCX, <key>
        assert result.data[off+10] == 0x48
        assert result.data[off+11] == 0xB9

    def test_multi_stage_jmp_short(self):
        t = self.library.get_template('x64_dxe_basic')
        result = self.mutator.mutate(t, MutationStrategy.MULTI_STAGE)
        off = t.hook_slots[0].offset
        # Stage 1: JMP short
        assert result.data[off] == 0xEB
        # Stage 2 at off+32: MOV RAX
        assert result.data[off+32] == 0x48
        assert result.data[off+33] == 0xB8

    def test_nop_sled_prefix(self):
        t = self.library.get_template('x64_dxe_basic')
        result = self.mutator.mutate(t, MutationStrategy.NOP_SLED_PREFIX)
        off = t.hook_slots[0].offset
        # First bytes should be NOPs
        assert result.data[off] == 0x90

    def test_aarch64_ldr_br(self):
        t = self.library.get_template('aarch64_dxe')
        result = self.mutator.mutate(t, MutationStrategy.AARCH64_LDR_BR)
        off = t.hook_slots[0].offset
        ldr = struct.unpack_from('<I', result.data, off)[0]
        br = struct.unpack_from('<I', result.data, off+4)[0]
        assert ldr == 0x58000050  # LDR X16, #8
        assert br == 0xD61F0200   # BR X16

    def test_aarch64_movz_movk_br(self):
        t = self.library.get_template('aarch64_dxe')
        result = self.mutator.mutate(t, MutationStrategy.AARCH64_ADRP_ADD_BR)
        off = t.hook_slots[0].offset
        # Last instruction should be BR X16
        br = struct.unpack_from('<I', result.data, off+16)[0]
        assert br == 0xD61F0200

    def test_riscv_auipc_jalr(self):
        t = self.library.get_template('riscv64_dxe')
        result = self.mutator.mutate(t, MutationStrategy.RISCV_AUIPC_JALR)
        off = t.hook_slots[0].offset
        auipc = struct.unpack_from('<I', result.data, off)[0]
        ld = struct.unpack_from('<I', result.data, off+4)[0]
        jalr = struct.unpack_from('<I', result.data, off+8)[0]
        assert auipc == 0x00000317
        assert ld == 0x00833303
        assert jalr == 0x00030067

    def test_mbr_int13h_hook(self):
        t = self.library.get_template('legacy_mbr')
        result = self.mutator.mutate(t, MutationStrategy.MBR_INT13H_HOOK)
        off = t.hook_slots[0].offset
        # MOV WORD [004Ch], ...
        assert result.data[off] == 0xC7
        assert result.data[off+1] == 0x06
        assert result.data[off+2] == 0x4C
        assert result.data[off+3] == 0x00

    def test_bst_pointer_patched(self):
        t = self.library.get_template('x64_dxe_basic')
        original_ptr = struct.unpack_from('<Q', t.data, BST_FUNCTION_OFFSETS[HookTarget.LOAD_IMAGE])[0]
        result = self.mutator.mutate(t, MutationStrategy.MOV_RAX_JMP)
        new_ptr = struct.unpack_from('<Q', result.data, BST_FUNCTION_OFFSETS[HookTarget.LOAD_IMAGE])[0]
        # Pointer should now point to hook slot offset
        assert new_ptr == t.hook_slots[0].offset
        assert new_ptr != original_ptr

    def test_deterministic_with_same_seed(self):
        m1 = BootkitMutator(seed=999)
        m2 = BootkitMutator(seed=999)
        t = self.library.get_template('x64_dxe_basic')
        r1 = m1.mutate(t, MutationStrategy.MOV_RAX_JMP)
        r2 = m2.mutate(t, MutationStrategy.MOV_RAX_JMP)
        assert r1.data == r2.data
        assert r1.hook_address == r2.hook_address


# ─── Generator Tests ─────────────────────────────────────────────────────────

class TestAdversarialGenerator:
    def test_generate_basic(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=42)
            config = GenerationConfig(
                count=5,
                difficulty=2,
                output_dir=Path(tmp),
            )
            paths = gen.generate(config)
            assert len(paths) <= 5
            assert all(p.exists() for p in paths)
            assert all(p.suffix == '.bin' for p in paths)

    def test_generate_respects_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=1)
            config = GenerationConfig(count=10, difficulty=3, output_dir=Path(tmp))
            paths = gen.generate(config)
            assert len(paths) == 10

    def test_generate_difficulty_1_only_basic(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=7)
            config = GenerationConfig(
                count=4, difficulty=1,
                architectures=[Architecture.X64],
                output_dir=Path(tmp),
            )
            paths = gen.generate(config)
            # Difficulty 1 only has MOV_RAX_JMP for x64
            for p in paths:
                assert 'mov_rax_jmp' in p.name

    def test_generate_architecture_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=3)
            config = GenerationConfig(
                count=5, difficulty=2,
                architectures=[Architecture.AARCH64],
                output_dir=Path(tmp),
            )
            paths = gen.generate(config)
            for p in paths:
                assert 'aarch64' in p.name

    def test_generate_multi_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=11)
            paths = gen.generate_multi_hook(Path(tmp), count=3)
            assert len(paths) == 3
            for p in paths:
                assert 'x64_multi' in p.name
                # Multi-hook files should be larger (BST + 4 slots)
                assert p.stat().st_size > 400

    def test_generate_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=5)
            path = gen.generate_one(
                'x64_dxe_basic', MutationStrategy.PUSH_RET, Path(tmp),
            )
            assert path is not None
            assert path.exists()
            assert 'push_ret' in path.name.lower()

    def test_get_results_tracks_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=0)
            config = GenerationConfig(count=3, difficulty=1, output_dir=Path(tmp))
            gen.generate(config)
            results = gen.get_results()
            assert len(results) == 3


# ─── Evaluator Tests ─────────────────────────────────────────────────────────

class TestDetectionEvaluator:
    def test_evaluate_detects_basic_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = AdversarialGenerator(seed=42)
            config = GenerationConfig(
                count=5, difficulty=1,
                architectures=[Architecture.X64],
                output_dir=Path(tmp),
            )
            gen.generate(config)
            samples = gen.get_results()

            evaluator = DetectionEvaluator()
            report = evaluator.evaluate(samples)
            assert report.total_samples == 5
            # Basic MOV RAX; JMP RAX should be detectable
            assert report.detection_rate > 0.0

    def test_evaluate_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            gen = AdversarialGenerator(seed=7)
            config = GenerationConfig(count=3, difficulty=1, output_dir=tmp_path)
            gen.generate(config)

            evaluator = DetectionEvaluator()
            report = evaluator.evaluate_directory(tmp_path)
            assert report.total_samples == 3

    def test_report_to_dict(self):
        report = EvaluationReport(
            total_samples=10,
            total_detected=8,
            by_strategy={'MOV_RAX_JMP': (5, 5), 'XOR_DECODE_JMP': (5, 3)},
            by_architecture={'x64': (10, 8)},
            by_difficulty={1: (5, 5), 4: (5, 3)},
        )
        d = report.to_dict()
        assert d['detection_rate'] == 0.8
        assert d['by_strategy']['MOV_RAX_JMP']['rate'] == 1.0
        assert d['by_strategy']['XOR_DECODE_JMP']['rate'] == 0.6

    def test_report_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = EvaluationReport(total_samples=5, total_detected=4)
            out = Path(tmp) / 'report.json'
            report.save(out)
            assert out.exists()
            import json
            data = json.loads(out.read_text())
            assert data['detection_rate'] == 0.8

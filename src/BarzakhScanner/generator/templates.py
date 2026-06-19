"""
Bootkit Templates - Base binary templates for mutation.

Provides minimal EFI DXE driver shells and legacy MBR templates with
hook slots that the mutator can fill with various hooking techniques.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Architecture(Enum):
    X64 = 'x64'
    AARCH64 = 'aarch64'
    RISCV64 = 'riscv64'
    LEGACY_MBR = 'legacy_mbr'


class HookTarget(Enum):
    LOAD_IMAGE = 'LoadImage'
    START_IMAGE = 'StartImage'
    EXIT_BOOT_SERVICES = 'ExitBootServices'
    ALLOCATE_POOL = 'AllocatePool'
    FREE_POOL = 'FreePool'
    CREATE_EVENT = 'CreateEvent'
    SET_TIMER = 'SetTimer'
    SET_VARIABLE = 'SetVariable'
    GET_VARIABLE = 'GetVariable'
    LOCATE_PROTOCOL = 'LocateProtocol'


# BST offsets for each hookable function (x86_64 UEFI)
BST_FUNCTION_OFFSETS = {
    HookTarget.ALLOCATE_POOL: 64,
    HookTarget.FREE_POOL: 72,
    HookTarget.CREATE_EVENT: 80,
    HookTarget.SET_TIMER: 88,
    HookTarget.LOAD_IMAGE: 192,
    HookTarget.START_IMAGE: 200,
    HookTarget.EXIT_BOOT_SERVICES: 224,
    HookTarget.SET_VARIABLE: 232,
}


@dataclass
class HookSlot:
    """Represents a fillable hook location in a template."""
    offset: int
    size: int
    target: HookTarget
    arch: Architecture


@dataclass
class BootkitTemplate:
    """Base binary template with hook slots."""
    name: str
    arch: Architecture
    data: bytearray
    hook_slots: List[HookSlot] = field(default_factory=list)
    bst_offset: int = 0
    description: str = ''

    def clone(self) -> 'BootkitTemplate':
        return BootkitTemplate(
            name=self.name,
            arch=self.arch,
            data=bytearray(self.data),
            hook_slots=list(self.hook_slots),
            bst_offset=self.bst_offset,
            description=self.description,
        )


class TemplateLibrary:
    """Library of base bootkit templates for each architecture."""

    BST_SIGNATURE = 0x56524553544f4f42  # "BOOTSERV"

    def __init__(self):
        self._templates: Dict[str, BootkitTemplate] = {}
        self._build_templates()

    def _build_templates(self):
        self._templates['x64_dxe_basic'] = self._build_x64_dxe_template()
        self._templates['x64_dxe_multi'] = self._build_x64_multi_hook_template()
        self._templates['aarch64_dxe'] = self._build_aarch64_template()
        self._templates['riscv64_dxe'] = self._build_riscv64_template()
        self._templates['legacy_mbr'] = self._build_legacy_mbr_template()

    def get_template(self, name: str) -> Optional[BootkitTemplate]:
        return self._templates.get(name)

    def list_templates(self) -> List[str]:
        return list(self._templates.keys())

    def get_templates_for_arch(self, arch: Architecture) -> List[BootkitTemplate]:
        return [t for t in self._templates.values() if t.arch == arch]

    def _build_bst_region(self, hook_target_addr: int = 0x1000) -> bytearray:
        """Build a minimal Boot Services Table with valid signature and pointers."""
        bst = bytearray(240)
        struct.pack_into('<Q', bst, 0, self.BST_SIGNATURE)
        struct.pack_into('<I', bst, 8, 0x00020046)  # Revision 2.70
        struct.pack_into('<I', bst, 12, 240)  # HeaderSize

        # Fill function pointers with a "legitimate" base address
        fv_base = 0x7E000000
        for offset in range(24, 240, 8):
            struct.pack_into('<Q', bst, offset, fv_base + offset * 16)

        # Zero CRC32 for now (will be recalculated by mutator)
        struct.pack_into('<I', bst, 16, 0)
        return bst

    def _build_x64_dxe_template(self) -> BootkitTemplate:
        """Minimal x86_64 memory image: BST + code region with hook slot."""
        # Layout: [BST (240 bytes)] [padding (16 bytes)] [code region (256 bytes)]
        bst = self._build_bst_region()
        padding = bytearray(16)
        code_region = bytearray(256)

        # NOP sled in code region
        for i in range(256):
            code_region[i] = 0x90  # NOP

        data = bst + padding + code_region
        hook_slot_offset = 256  # Start of code region

        template = BootkitTemplate(
            name='x64_dxe_basic',
            arch=Architecture.X64,
            data=data,
            hook_slots=[
                HookSlot(offset=hook_slot_offset, size=64, target=HookTarget.LOAD_IMAGE, arch=Architecture.X64),
            ],
            bst_offset=0,
            description='Basic x64 DXE with single LoadImage hook slot',
        )
        return template

    def _build_x64_multi_hook_template(self) -> BootkitTemplate:
        """x86_64 image with multiple hook slots for different BST functions."""
        bst = self._build_bst_region()
        padding = bytearray(16)
        # 4 hook slots, 64 bytes each
        code_region = bytearray(64 * 4)
        for i in range(len(code_region)):
            code_region[i] = 0x90

        data = bst + padding + code_region

        targets = [
            HookTarget.LOAD_IMAGE,
            HookTarget.START_IMAGE,
            HookTarget.EXIT_BOOT_SERVICES,
            HookTarget.SET_VARIABLE,
        ]
        slots = []
        for i, target in enumerate(targets):
            slots.append(HookSlot(
                offset=256 + i * 64,
                size=64,
                target=target,
                arch=Architecture.X64,
            ))

        return BootkitTemplate(
            name='x64_dxe_multi',
            arch=Architecture.X64,
            data=data,
            hook_slots=slots,
            bst_offset=0,
            description='x64 DXE with LoadImage/StartImage/EBS/SetVariable hooks',
        )

    def _build_aarch64_template(self) -> BootkitTemplate:
        """ARM64 memory image with BST and trampoline slot."""
        bst = self._build_bst_region()
        padding = bytearray(16)
        code_region = bytearray(128)
        # Fill with ARM64 NOPs (0xD503201F)
        for i in range(0, 128, 4):
            struct.pack_into('<I', code_region, i, 0xD503201F)

        data = bst + padding + code_region

        return BootkitTemplate(
            name='aarch64_dxe',
            arch=Architecture.AARCH64,
            data=data,
            hook_slots=[
                HookSlot(offset=256, size=64, target=HookTarget.LOAD_IMAGE, arch=Architecture.AARCH64),
            ],
            bst_offset=0,
            description='ARM64 DXE with LDR/BR trampoline slot',
        )

    def _build_riscv64_template(self) -> BootkitTemplate:
        """RISC-V 64 memory image with BST and trampoline slot."""
        bst = self._build_bst_region()
        padding = bytearray(16)
        code_region = bytearray(128)
        # Fill with RISC-V NOPs (ADDI x0, x0, 0 = 0x00000013)
        for i in range(0, 128, 4):
            struct.pack_into('<I', code_region, i, 0x00000013)

        data = bst + padding + code_region

        return BootkitTemplate(
            name='riscv64_dxe',
            arch=Architecture.RISCV64,
            data=data,
            hook_slots=[
                HookSlot(offset=256, size=64, target=HookTarget.LOAD_IMAGE, arch=Architecture.RISCV64),
            ],
            bst_offset=0,
            description='RISC-V DXE with AUIPC/LD/JALR trampoline slot',
        )

    def _build_legacy_mbr_template(self) -> BootkitTemplate:
        """Legacy 512-byte MBR with INT 13h hook slot."""
        mbr = bytearray(512)

        # Standard MBR entry: CLI; XOR AX,AX; MOV DS,AX; MOV SS,AX; MOV SP,7C00h; STI
        entry_code = bytes([
            0xFA,                       # CLI
            0x33, 0xC0,                 # XOR AX, AX
            0x8E, 0xD8,                 # MOV DS, AX
            0x8E, 0xD0,                 # MOV SS, AX
            0xBC, 0x00, 0x7C,           # MOV SP, 0x7C00
            0xFB,                       # STI
        ])
        mbr[:len(entry_code)] = entry_code

        # Self-relocation stub at offset 11
        reloc_code = bytes([
            0xBE, 0x00, 0x7C,           # MOV SI, 0x7C00
            0xBF, 0x00, 0x06,           # MOV DI, 0x0600
            0xB9, 0x00, 0x01,           # MOV CX, 256
            0xF3, 0xA5,                 # REP MOVSW
        ])
        mbr[11:11+len(reloc_code)] = reloc_code

        # Hook slot starts at offset 32 (room for INT 13h hook code)
        hook_slot_start = 32

        # Boot signature
        mbr[510] = 0x55
        mbr[511] = 0xAA

        # AEGS marker for scanner detection
        mbr[200:204] = b'AEGS'

        return BootkitTemplate(
            name='legacy_mbr',
            arch=Architecture.LEGACY_MBR,
            data=mbr,
            hook_slots=[
                HookSlot(offset=hook_slot_start, size=100, target=HookTarget.LOAD_IMAGE, arch=Architecture.LEGACY_MBR),
            ],
            bst_offset=0,
            description='Legacy MBR with INT 13h hook slot',
        )

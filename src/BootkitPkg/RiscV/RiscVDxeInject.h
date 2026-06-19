/** @file
  RISC-V DXE Injection Module Header

  RISC-V specific Boot Services table hooking using AUIPC+JALR trampolines.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __RISCV_DXE_INJECT_H__
#define __RISCV_DXE_INJECT_H__

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/TimerLib.h>

//
// Module identification
//
#define BARZAKH_SIGNATURE  SIGNATURE_32('A','E','G','S')
#define BARZAKH_VERSION    0x00030000  // v3.0 RISC-V

//
// Configuration (set at build time)
//
#ifndef AEGIS_ALLOWED_UUID
#define AEGIS_ALLOWED_UUID  "00000000-0000-0000-0000-000000000000"
#endif

#ifndef AEGIS_EXPIRY_DATE
#define AEGIS_EXPIRY_DATE   "2027-05-11"
#endif

//
// RISC-V trampoline structure (12 bytes)
//
// AUIPC t1, hi20     ; Load PC + upper-20-bit offset into t1
// JALR  x0, t1, lo12 ; Jump to t1 + lower-12-bit offset (no link)
//
// For absolute addresses we use a load-from-literal-pool variant:
// AUIPC t1, 0        ; t1 = PC
// LD    t1, 8(t1)    ; t1 = *(PC + 8)  (load 64-bit target)
// JALR  x0, t1, 0   ; Jump to target
// <64-bit address>   ; Literal pool entry
//
#define RISCV_TRAMPOLINE_SIZE  20  // 3 instructions (12 bytes) + 8-byte address

#pragma pack(1)
typedef struct {
  UINT32    Auipc;        // AUIPC t1, 0
  UINT32    Ld;           // LD t1, 8(t1)
  UINT32    Jalr;         // JALR x0, t1, 0
  UINT64    TargetAddr;   // Absolute target address (literal pool)
} RISCV_TRAMPOLINE;
#pragma pack()

// AUIPC t1, 0  =>  0x00000317 (rd=t1=x6, imm=0)
#define RISCV_AUIPC_T1_0    0x00000317
// LD t1, 8(t1) =>  0x00833303 (rd=t1, rs1=t1, imm=8, funct3=011)
#define RISCV_LD_T1_8_T1    0x00833303
// JALR x0, t1, 0 => 0x00030067 (rd=x0, rs1=t1, imm=0)
#define RISCV_JALR_X0_T1_0  0x00030067

//
// Hook tracking structure
//
typedef struct {
  UINT32                    Signature;
  UINT32                    Version;
  BOOLEAN                   HooksInstalled;
  EFI_ALLOCATE_POOL         OriginalAllocatePool;
  EFI_FREE_POOL             OriginalFreePool;
  EFI_CREATE_EVENT          OriginalCreateEvent;
  EFI_IMAGE_LOAD            OriginalLoadImage;
  EFI_IMAGE_START           OriginalStartImage;
  UINTN                     HookCount;
  UINT64                    InstallTime;
} RISCV_HOOK_CONTEXT;

//
// Function prototypes
//
EFI_STATUS
EFIAPI
RiscVDxeInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

EFI_STATUS
InstallRiscVBstHooks (
  IN OUT RISCV_HOOK_CONTEXT  *Context
  );

EFI_STATUS
RemoveRiscVBstHooks (
  IN RISCV_HOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
RiscVHookedLoadImage (
  IN  BOOLEAN                  BootPolicy,
  IN  EFI_HANDLE               ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN  VOID                     *SourceBuffer OPTIONAL,
  IN  UINTN                    SourceSize,
  OUT EFI_HANDLE               *ImageHandle
  );

EFI_STATUS
EFIAPI
RiscVHookedStartImage (
  IN  EFI_HANDLE  ImageHandle,
  OUT UINTN       *ExitDataSize,
  OUT CHAR16      **ExitData OPTIONAL
  );

#endif // __RISCV_DXE_INJECT_H__

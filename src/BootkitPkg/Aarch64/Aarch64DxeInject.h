/** @file
  AARCH64 DXE Injection Module Header

  ARM64-specific Boot Services table hooking using LDR/BR trampolines.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __AARCH64_DXE_INJECT_H__
#define __AARCH64_DXE_INJECT_H__

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
#include <Protocol/Smbios.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/SmBios.h>

//
// Module identification
//
#define AEGIS_BOOT_SIGNATURE  SIGNATURE_32('A','E','G','S')
#define AEGIS_BOOT_VERSION    0x00020000  // v2.0 AARCH64

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
// ARM64 trampoline structure (16 bytes)
// LDR X16, [PC+8]    ; 0x58000050
// BR  X16            ; 0xD61F0200
// <64-bit target>
//
#define AARCH64_TRAMPOLINE_SIZE  16

#pragma pack(1)
typedef struct {
  UINT32    LdrX16;       // LDR X16, #8 = 0x58000050
  UINT32    BrX16;        // BR X16 = 0xD61F0200
  UINT64    TargetAddr;   // Absolute target address
} AARCH64_TRAMPOLINE;
#pragma pack()

#define AARCH64_LDR_X16_LITERAL  0x58000050
#define AARCH64_BR_X16           0xD61F0200

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
} AARCH64_HOOK_CONTEXT;

//
// Function prototypes
//
EFI_STATUS
EFIAPI
Aarch64DxeInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

EFI_STATUS
InstallAarch64BstHooks (
  IN OUT AARCH64_HOOK_CONTEXT  *Context
  );

EFI_STATUS
RemoveAarch64BstHooks (
  IN AARCH64_HOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Aarch64HookedLoadImage (
  IN  BOOLEAN                  BootPolicy,
  IN  EFI_HANDLE               ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN  VOID                     *SourceBuffer OPTIONAL,
  IN  UINTN                    SourceSize,
  OUT EFI_HANDLE               *ImageHandle
  );

EFI_STATUS
EFIAPI
Aarch64HookedStartImage (
  IN  EFI_HANDLE  ImageHandle,
  OUT UINTN       *ExitDataSize,
  OUT CHAR16      **ExitData OPTIONAL
  );

VOID
Aarch64LogTelemetry (
  IN CONST CHAR16  *Message
  );

#endif // __AARCH64_DXE_INJECT_H__

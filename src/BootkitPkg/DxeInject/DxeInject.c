/** @file
  DXE Injection Module Implementation

  Implements DXE phase implantation and Boot Services table hooking
  for academic research purposes. Includes comprehensive kill-switches
  and telemetry logging.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeInject.h"
#include "KillSwitch.h"

//
// Global hook context
//
STATIC AEGIS_HOOK_CONTEXT  mHookContext = {
  .Signature       = AEGIS_BOOT_SIGNATURE,
  .Version         = AEGIS_BOOT_VERSION,
  .HooksInstalled  = FALSE,
  .HookCount       = 0,
  .InstallTime     = 0
};

//
// Configuration strings (set at build time)
//
CONST CHAR8  *gAegisAllowedUuid = AEGIS_ALLOWED_UUID;
CONST CHAR8  *gAegisExpiryDate  = AEGIS_EXPIRY_DATE;

/**
  Entry point for the DXE Inject driver.

  @param[in]  ImageHandle  Handle for the image of this driver.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS      Driver initialized successfully.
  @retval EFI_ABORTED      Kill-switch triggered, driver aborted.
  @retval Other            Error occurred during initialization.

**/
EFI_STATUS
EFIAPI
DxeInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS          Status;
  KILL_SWITCH_RESULT  KillSwitchResult;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "Aegis-Boot DXE Injection Module\n"));
  DEBUG ((DEBUG_INFO, "Version: %08x\n", AEGIS_BOOT_VERSION));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));

  //
  // CRITICAL: Validate kill-switches FIRST
  // This prevents execution on unauthorized hardware
  //
  DEBUG ((DEBUG_INFO, "[Aegis] Validating security constraints...\n"));
  KillSwitchResult = ValidateKillSwitches ();

  switch (KillSwitchResult) {
    case KillSwitchSuccess:
      DEBUG ((DEBUG_INFO, "[Aegis] Security validation PASSED\n"));
      break;

    case KillSwitchUuidMismatch:
      DEBUG ((DEBUG_ERROR, "[Aegis] KILL-SWITCH TRIGGERED: UUID Mismatch\n"));
      DEBUG ((DEBUG_ERROR, "[Aegis] This system is not authorized for Aegis-Boot execution\n"));
      LogTelemetry (L"Kill-switch triggered: UUID mismatch");
      return EFI_ABORTED;

    case KillSwitchTpmMismatch:
      DEBUG ((DEBUG_ERROR, "[Aegis] KILL-SWITCH TRIGGERED: TPM EK Mismatch\n"));
      DEBUG ((DEBUG_ERROR, "[Aegis] This system is not authorized for Aegis-Boot execution\n"));
      LogTelemetry (L"Kill-switch triggered: TPM EK mismatch");
      return EFI_ABORTED;

    case KillSwitchExpired:
      DEBUG ((DEBUG_ERROR, "[Aegis] KILL-SWITCH TRIGGERED: Project Expired\n"));
      DEBUG ((DEBUG_ERROR, "[Aegis] The project expiry date has passed\n"));
      LogTelemetry (L"Kill-switch triggered: Project expired");
      return EFI_ABORTED;

    default:
      DEBUG ((DEBUG_ERROR, "[Aegis] KILL-SWITCH TRIGGERED: Validation Error\n"));
      LogTelemetry (L"Kill-switch triggered: Validation error");
      return EFI_ABORTED;
  }

  //
  // Log successful initialization
  //
  LogTelemetry (L"DXE Inject module initialized successfully");

  //
  // Install Boot Services hooks
  //
  DEBUG ((DEBUG_INFO, "[Aegis] Installing Boot Services hooks...\n"));
  Status = InstallBootServicesHooks (&mHookContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Failed to install hooks: %r\n", Status));
    LogTelemetry (L"Failed to install Boot Services hooks");
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[Aegis] Hooks installed successfully\n"));
  LogTelemetry (L"Boot Services hooks installed");

  //
  // Record installation time
  //
  mHookContext.InstallTime = GetPerformanceCounter ();

  DEBUG ((DEBUG_INFO, "[Aegis] DXE Inject module loaded successfully\n"));
  DEBUG ((DEBUG_INFO, "[Aegis] Monitoring Boot Services activity...\n"));

  return EFI_SUCCESS;
}

/**
  Install hooks on Boot Services table functions.

  @param[in]  Context  Pointer to hook context structure.

  @retval EFI_SUCCESS      Hooks installed successfully.
  @retval EFI_UNSUPPORTED  Hooking not supported.
  @retval Other            Error occurred during hook installation.

**/
EFI_STATUS
InstallBootServicesHooks (
  IN OUT AEGIS_HOOK_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Context->HooksInstalled) {
    DEBUG ((DEBUG_WARN, "[Aegis] Hooks already installed\n"));
    return EFI_ALREADY_STARTED;
  }

  //
  // Save original function pointers
  //
  Context->OriginalAllocatePool = gBS->AllocatePool;
  Context->OriginalFreePool     = gBS->FreePool;
  Context->OriginalCreateEvent  = gBS->CreateEvent;

  //
  // Install hooks
  // NOTE: In a real implementation, we would need to handle
  // memory protection and ensure atomic updates
  //
  gBS->AllocatePool = HookedAllocatePool;
  gBS->FreePool     = HookedFreePool;
  gBS->CreateEvent  = HookedCreateEvent;

  //
  // Update CRC32 of Boot Services table
  // This is required for UEFI compliance
  //
  gBS->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 (gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  Context->HooksInstalled = TRUE;
  Context->HookCount      = 3;

  DEBUG ((DEBUG_INFO, "[Aegis] Installed %d hooks\n", Context->HookCount));

  return EFI_SUCCESS;
}

/**
  Remove hooks from Boot Services table functions.

  @param[in]  Context  Pointer to hook context structure.

  @retval EFI_SUCCESS  Hooks removed successfully.
  @retval Other        Error occurred during hook removal.

**/
EFI_STATUS
RemoveBootServicesHooks (
  IN AEGIS_HOOK_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Context->HooksInstalled) {
    return EFI_NOT_STARTED;
  }

  //
  // Restore original function pointers
  //
  gBS->AllocatePool = Context->OriginalAllocatePool;
  gBS->FreePool     = Context->OriginalFreePool;
  gBS->CreateEvent  = Context->OriginalCreateEvent;

  //
  // Update CRC32
  //
  gBS->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 (gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  Context->HooksInstalled = FALSE;

  DEBUG ((DEBUG_INFO, "[Aegis] Hooks removed\n"));

  return EFI_SUCCESS;
}

/**
  Hooked AllocatePool function.

  @param[in]   PoolType         Type of pool to allocate.
  @param[in]   Size             Size of allocation.
  @param[out]  Buffer           Pointer to allocated buffer.

  @retval EFI_SUCCESS           Allocation successful.
  @retval EFI_OUT_OF_RESOURCES  Not enough memory.

**/
EFI_STATUS
EFIAPI
HookedAllocatePool (
  IN  EFI_MEMORY_TYPE  PoolType,
  IN  UINTN            Size,
  OUT VOID             **Buffer
  )
{
  EFI_STATUS  Status;

  //
  // Log the allocation for research purposes
  //
  DEBUG ((
    DEBUG_VERBOSE,
    "[Aegis Hook] AllocatePool: Type=%d, Size=%lu\n",
    PoolType,
    (UINT64)Size
    ));

  //
  // Call original function
  //
  Status = mHookContext.OriginalAllocatePool (PoolType, Size, Buffer);

  if (!EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_VERBOSE,
      "[Aegis Hook] AllocatePool: Buffer=0x%p\n",
      *Buffer
      ));
  }

  return Status;
}

/**
  Hooked FreePool function.

  @param[in]  Buffer  Pointer to buffer to free.

  @retval EFI_SUCCESS  Buffer freed successfully.

**/
EFI_STATUS
EFIAPI
HookedFreePool (
  IN VOID  *Buffer
  )
{
  EFI_STATUS  Status;

  //
  // Log the deallocation
  //
  DEBUG ((
    DEBUG_VERBOSE,
    "[Aegis Hook] FreePool: Buffer=0x%p\n",
    Buffer
    ));

  //
  // Call original function
  //
  Status = mHookContext.OriginalFreePool (Buffer);

  return Status;
}

/**
  Hooked CreateEvent function.

  @param[in]   Type             Event type.
  @param[in]   NotifyTpl        Notification TPL.
  @param[in]   NotifyFunction   Notification function.
  @param[in]   NotifyContext    Notification context.
  @param[out]  Event            Pointer to created event.

  @retval EFI_SUCCESS  Event created successfully.

**/
EFI_STATUS
EFIAPI
HookedCreateEvent (
  IN  UINT32            Type,
  IN  EFI_TPL           NotifyTpl,
  IN  EFI_EVENT_NOTIFY  NotifyFunction OPTIONAL,
  IN  VOID              *NotifyContext OPTIONAL,
  OUT EFI_EVENT         *Event
  )
{
  EFI_STATUS  Status;

  //
  // Log event creation
  //
  DEBUG ((
    DEBUG_VERBOSE,
    "[Aegis Hook] CreateEvent: Type=0x%x, TPL=%lu\n",
    Type,
    (UINT64)NotifyTpl
    ));

  //
  // Call original function
  //
  Status = mHookContext.OriginalCreateEvent (
                          Type,
                          NotifyTpl,
                          NotifyFunction,
                          NotifyContext,
                          Event
                          );

  if (!EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_VERBOSE,
      "[Aegis Hook] CreateEvent: Event=0x%p\n",
      *Event
      ));
  }

  return Status;
}

/**
  Log telemetry data for research purposes.

  @param[in]  Message  Telemetry message to log.

**/
VOID
LogTelemetry (
  IN CONST CHAR16  *Message
  )
{
  EFI_TIME  CurrentTime;
  EFI_STATUS Status;

  //
  // Get current time
  //
  Status = gRT->GetTime (&CurrentTime, NULL);
  if (!EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_INFO,
      "[Aegis Telemetry] %04d-%02d-%02d %02d:%02d:%02d - %s\n",
      CurrentTime.Year,
      CurrentTime.Month,
      CurrentTime.Day,
      CurrentTime.Hour,
      CurrentTime.Minute,
      CurrentTime.Second,
      Message
      ));
  } else {
    DEBUG ((DEBUG_INFO, "[Aegis Telemetry] %s\n", Message));
  }

  //
  // In a real implementation, we would:
  // 1. Write to a dedicated logging partition
  // 2. Send to AttestationPkg for PCR extension
  // 3. Include in TCG Event Log
  //
}

// Made with Bob

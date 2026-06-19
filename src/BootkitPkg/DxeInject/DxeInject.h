/** @file
  DXE Injection Module Header

  Defines structures and functions for DXE phase implantation and
  Boot Services table hooking for academic research.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __DXE_INJECT_H__
#define __DXE_INJECT_H__

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
#define BARZAKH_SIGNATURE  SIGNATURE_32('A','E','G','S')
#define BARZAKH_VERSION    0x00010000

//
// Configuration (set at build time)
//
#ifndef AEGIS_ALLOWED_UUID
#define AEGIS_ALLOWED_UUID  "00000000-0000-0000-0000-000000000000"
#endif

#ifndef AEGIS_EXPIRY_DATE
#define AEGIS_EXPIRY_DATE   "2027-05-11"  // YYYY-MM-DD format
#endif

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
  UINTN                     HookCount;
  UINT64                    InstallTime;
} AEGIS_HOOK_CONTEXT;

//
// Function prototypes
//

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
  );

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
  );

/**
  Remove hooks from Boot Services table functions.

  @param[in]  Context  Pointer to hook context structure.

  @retval EFI_SUCCESS  Hooks removed successfully.
  @retval Other        Error occurred during hook removal.

**/
EFI_STATUS
RemoveBootServicesHooks (
  IN AEGIS_HOOK_CONTEXT  *Context
  );

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
  );

/**
  Hooked FreePool function.

  @param[in]  Buffer  Pointer to buffer to free.

  @retval EFI_SUCCESS  Buffer freed successfully.

**/
EFI_STATUS
EFIAPI
HookedFreePool (
  IN VOID  *Buffer
  );

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
  );

/**
  Log telemetry data for research purposes.

  @param[in]  Message  Telemetry message to log.

**/
VOID
LogTelemetry (
  IN CONST CHAR16  *Message
  );

#endif // __DXE_INJECT_H__


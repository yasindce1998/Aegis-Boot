/** @file
  ExitBootServices Hook Module Header

  Defines structures and functions for intercepting ExitBootServices
  to maintain memory residency during OS transition.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EXIT_BOOT_HOOK_H__
#define __EXIT_BOOT_HOOK_H__

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
#include <Protocol/LoadedImage.h>

//
// Module identification
//
#define EXIT_BOOT_HOOK_SIGNATURE  SIGNATURE_32('E','X','B','T')
#define EXIT_BOOT_HOOK_VERSION    0x00010000

//
// Runtime memory allocation size (for payload persistence)
//
#define RUNTIME_MEMORY_SIZE  SIZE_4KB

//
// Hook context structure
//
typedef struct {
  UINT32                    Signature;
  UINT32                    Version;
  BOOLEAN                   HookInstalled;
  EFI_EXIT_BOOT_SERVICES    OriginalExitBootServices;
  VOID                      *RuntimeMemory;
  UINTN                     RuntimeMemorySize;
  UINT64                    HookTime;
  UINT64                    ExitBootTime;
} EXIT_BOOT_HOOK_CONTEXT;

/**
  Entry point for the ExitBootServices Hook driver.

  @param[in]  ImageHandle  Handle for the image of this driver.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS      Driver initialized successfully.
  @retval Other            Error occurred during initialization.

**/
EFI_STATUS
EFIAPI
ExitBootHookEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

/**
  Install hook on ExitBootServices function.

  @param[in]  Context  Pointer to hook context structure.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred during hook installation.

**/
EFI_STATUS
InstallExitBootServicesHook (
  IN OUT EXIT_BOOT_HOOK_CONTEXT  *Context
  );

/**
  Hooked ExitBootServices function.

  @param[in]  ImageHandle  Handle that identifies the exiting image.
  @param[in]  MapKey       Key to the latest memory map.

  @retval EFI_SUCCESS      Boot services terminated successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
EFIAPI
HookedExitBootServices (
  IN EFI_HANDLE  ImageHandle,
  IN UINTN       MapKey
  );

/**
  Allocate runtime memory for payload persistence.

  @param[in]   Size    Size of memory to allocate.
  @param[out]  Memory  Pointer to allocated memory.

  @retval EFI_SUCCESS           Memory allocated successfully.
  @retval EFI_OUT_OF_RESOURCES  Not enough memory.

**/
EFI_STATUS
AllocateRuntimeMemory (
  IN  UINTN  Size,
  OUT VOID   **Memory
  );

/**
  Prepare payload for OS transition.

  This function is called just before ExitBootServices completes.
  It ensures the payload survives into the OS runtime.

  @param[in]  Context  Pointer to hook context.

  @retval EFI_SUCCESS  Payload prepared successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
PreparePayloadForRuntime (
  IN EXIT_BOOT_HOOK_CONTEXT  *Context
  );

/**
  Log ExitBootServices telemetry.

  @param[in]  Message  Telemetry message to log.

**/
VOID
LogExitBootTelemetry (
  IN CONST CHAR16  *Message
  );

#endif // __EXIT_BOOT_HOOK_H__


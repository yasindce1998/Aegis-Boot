/** @file
  Self-Erasure Module - Models Runtime Payload Self-Destruction

  Emulates the technique where a bootkit copies itself to a runtime
  allocation then zeroes its original loaded image, making forensic
  detection of the initial DXE driver impossible after boot.

  Seen in: BlackLotus (2023), CosmicStrand variants

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __SELF_ERASURE_H__
#define __SELF_ERASURE_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>

//
// Self-Erasure Context
//
typedef struct {
  BOOLEAN                 Initialized;
  //
  // Original loaded image location (will be erased)
  //
  EFI_PHYSICAL_ADDRESS    OriginalImageBase;
  UINT64                  OriginalImageSize;
  //
  // Runtime copy (survives ExitBootServices)
  //
  EFI_PHYSICAL_ADDRESS    RuntimeCopyBase;
  UINT64                  RuntimeCopySize;
  EFI_MEMORY_TYPE         RuntimeMemoryType;
  //
  // Status tracking
  //
  BOOLEAN                 CopyComplete;
  BOOLEAN                 ErasureComplete;
  UINT32                  ErasedByteCount;
} SELF_ERASURE_CONTEXT;

/**
  Initialize Self-Erasure context.

  @param[in,out]  Context    Pointer to self-erasure context.
  @param[in]      ImageBase  Base address of the loaded DXE driver image.
  @param[in]      ImageSize  Size of the loaded image.

  @retval EFI_SUCCESS           Context initialized.
  @retval EFI_INVALID_PARAMETER Context or ImageBase is NULL.
**/
EFI_STATUS
EFIAPI
InitializeSelfErasure (
  IN OUT SELF_ERASURE_CONTEXT  *Context,
  IN     EFI_PHYSICAL_ADDRESS  ImageBase,
  IN     UINT64                ImageSize
  );

/**
  Prepare self-erasure by copying payload to runtime memory.

  Allocates EfiRuntimeServicesCode memory and copies the active
  payload there. The runtime copy survives ExitBootServices.

  @param[in]  Context  Pointer to self-erasure context.

  @retval EFI_SUCCESS           Copy complete.
  @retval EFI_OUT_OF_RESOURCES  Failed to allocate runtime memory.
  @retval EFI_NOT_READY         Context not initialized.
**/
EFI_STATUS
EFIAPI
PrepareSelfErasure (
  IN SELF_ERASURE_CONTEXT  *Context
  );

/**
  Execute self-erasure of the original loaded image.

  Zeroes the original DXE driver image pages so that memory
  forensics cannot find the original PE/COFF image.

  @param[in]  Context  Pointer to self-erasure context.

  @retval EFI_SUCCESS     Erasure complete (or simulated).
  @retval EFI_NOT_READY   PrepareSelfErasure not called.
**/
EFI_STATUS
EFIAPI
ExecuteSelfErasure (
  IN SELF_ERASURE_CONTEXT  *Context
  );

/**
  Check if self-erasure has been completed.

  @param[in]  Context  Pointer to self-erasure context.

  @retval TRUE   Self-erasure was executed.
  @retval FALSE  Not yet erased or context invalid.
**/
BOOLEAN
EFIAPI
IsSelfErasureComplete (
  IN SELF_ERASURE_CONTEXT  *Context
  );

/**
  Log self-erasure status for debugging/detection testing.

  @param[in]  Context  Pointer to self-erasure context.
**/
VOID
EFIAPI
LogSelfErasureStatus (
  IN SELF_ERASURE_CONTEXT  *Context
  );

#endif // __SELF_ERASURE_H__

/** @file
  StartImage Hook Header

  Provides StartImage interception for image execution manipulation.
  For academic research purposes only.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __START_IMAGE_HOOK_H__
#define __START_IMAGE_HOOK_H__

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/LoadedImage.h>

//
// Original StartImage function pointer
//
extern EFI_IMAGE_START mOriginalStartImage;

/**
  Hooked StartImage function.

  Intercepts image execution to log and analyze before execution.
  In real bootkits, this would patch images before they run.

  @param[in]   ImageHandle    Handle of image to start.
  @param[out]  ExitDataSize   Size of exit data.
  @param[out]  ExitData       Exit data from image.

  @retval EFI_SUCCESS      Image started successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
EFIAPI
HookedStartImage (
  IN  EFI_HANDLE  ImageHandle,
  OUT UINTN       *ExitDataSize,
  OUT CHAR16      **ExitData OPTIONAL
  );

/**
  Install StartImage hook.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
InstallStartImageHook (
  VOID
  );

#endif // __START_IMAGE_HOOK_H__


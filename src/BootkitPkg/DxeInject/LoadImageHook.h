/** @file
  LoadImage Hook Header

  Provides LoadImage interception for bootloader manipulation research.
  For academic research purposes only.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __LOAD_IMAGE_HOOK_H__
#define __LOAD_IMAGE_HOOK_H__

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Protocol/LoadedImage.h>

//
// Original LoadImage function pointer
//
extern EFI_IMAGE_LOAD mOriginalLoadImage;

/**
  Hooked LoadImage function.

  Intercepts image loading to log and analyze bootloader/driver loading.
  In real bootkits, this would be used to inject malicious code or
  modify legitimate images before execution.

  @param[in]   BootPolicy          Boot policy for image loading.
  @param[in]   ParentImageHandle   Handle of parent image.
  @param[in]   DevicePath          Device path of image to load.
  @param[in]   SourceBuffer        Optional source buffer.
  @param[in]   SourceSize          Size of source buffer.
  @param[out]  ImageHandle         Handle of loaded image.

  @retval EFI_SUCCESS      Image loaded successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
EFIAPI
HookedLoadImage (
  IN  BOOLEAN                   BootPolicy,
  IN  EFI_HANDLE                ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  IN  VOID                      *SourceBuffer OPTIONAL,
  IN  UINTN                     SourceSize,
  OUT EFI_HANDLE                *ImageHandle
  );

/**
  Install LoadImage hook.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
InstallLoadImageHook (
  VOID
  );

#endif // __LOAD_IMAGE_HOOK_H__


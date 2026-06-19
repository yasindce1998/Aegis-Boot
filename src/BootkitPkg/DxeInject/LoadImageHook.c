/** @file
  LoadImage Hook Implementation

  Implements LoadImage interception for bootloader manipulation research.
  Models BlackLotus TTP for bootloader modification.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "LoadImageHook.h"
#include "DxeInject.h"

//
// Original LoadImage function pointer
//
EFI_IMAGE_LOAD mOriginalLoadImage = NULL;

/**
  Hooked LoadImage function.

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
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage Hook] INTERCEPTED\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage] BootPolicy: %d\n", BootPolicy));
  DEBUG ((DEBUG_INFO, "[LoadImage] ParentImageHandle: 0x%p\n", ParentImageHandle));
  DEBUG ((DEBUG_INFO, "[LoadImage] DevicePath: 0x%p\n", DevicePath));
  DEBUG ((DEBUG_INFO, "[LoadImage] SourceBuffer: 0x%p\n", SourceBuffer));
  DEBUG ((DEBUG_INFO, "[LoadImage] SourceSize: %lu bytes\n", (UINT64)SourceSize));

  //
  // Log telemetry for detection research
  //
  LogTelemetry (L"LoadImage hook triggered");

  //
  // In a real bootkit (e.g., BlackLotus), this would:
  // 1. Inspect the image being loaded
  // 2. Check if it's a bootloader (e.g., GRUB, Windows Boot Manager)
  // 3. Modify the image to inject malicious code
  // 4. Patch Secure Boot checks
  // 5. Install additional hooks in the bootloader
  //
  DEBUG ((DEBUG_INFO, "[LoadImage] In production bootkit, would:\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage]   1. Parse PE/ELF headers of loaded image\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage]   2. Identify if bootloader (GRUB/bootmgfw.efi)\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage]   3. Inject shellcode into .text section\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage]   4. Patch Secure Boot validation routines\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage]   5. Modify entry point to execute payload\n"));

  //
  // Call original LoadImage
  //
  DEBUG ((DEBUG_INFO, "[LoadImage] Calling original LoadImage...\n"));
  Status = mOriginalLoadImage (
             BootPolicy,
             ParentImageHandle,
             DevicePath,
             SourceBuffer,
             SourceSize,
             ImageHandle
             );

  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[LoadImage] ✓ Image loaded successfully\n"));
    DEBUG ((DEBUG_INFO, "[LoadImage]   ImageHandle: 0x%p\n", *ImageHandle));

    //
    // Get loaded image information
    //
    EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
    Status = gBS->HandleProtocol (
                    *ImageHandle,
                    &gEfiLoadedImageProtocolGuid,
                    (VOID **)&LoadedImage
                    );

    if (!EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "[LoadImage]   ImageBase: 0x%p\n", LoadedImage->ImageBase));
      DEBUG ((DEBUG_INFO, "[LoadImage]   ImageSize: 0x%lx bytes\n", (UINT64)LoadedImage->ImageSize));
      DEBUG ((DEBUG_INFO, "[LoadImage]   ImageCodeType: %d\n", LoadedImage->ImageCodeType));
      DEBUG ((DEBUG_INFO, "[LoadImage]   ImageDataType: %d\n", LoadedImage->ImageDataType));

      //
      // In real bootkit: analyze and potentially modify the loaded image
      //
      DEBUG ((DEBUG_INFO, "[LoadImage] Image analysis complete (research mode)\n"));
    }
  } else {
    DEBUG ((DEBUG_ERROR, "[LoadImage] ✗ Image load failed: %r\n", Status));
  }

  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));

  return Status;
}

/**
  Install LoadImage hook.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
InstallLoadImageHook (
  VOID
  )
{
  if (mOriginalLoadImage != NULL) {
    DEBUG ((DEBUG_WARN, "[LoadImage] Hook already installed\n"));
    return EFI_ALREADY_STARTED;
  }

  //
  // Save original LoadImage pointer
  //
  mOriginalLoadImage = gBS->LoadImage;

  //
  // Install hook
  //
  gBS->LoadImage = HookedLoadImage;

  DEBUG ((DEBUG_INFO, "[LoadImage] Hook installed successfully\n"));
  DEBUG ((DEBUG_INFO, "[LoadImage]   Original: 0x%p\n", mOriginalLoadImage));
  DEBUG ((DEBUG_INFO, "[LoadImage]   Hooked: 0x%p\n", HookedLoadImage));

  LogTelemetry (L"LoadImage hook installed");

  return EFI_SUCCESS;
}


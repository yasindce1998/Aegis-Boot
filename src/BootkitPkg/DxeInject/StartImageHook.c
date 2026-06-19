/** @file
  StartImage Hook Implementation

  Implements StartImage interception for image execution manipulation.
  Models CosmicStrand TTP for DXE driver injection.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "StartImageHook.h"
#include "DxeInject.h"

//
// Original StartImage function pointer
//
EFI_IMAGE_START mOriginalStartImage = NULL;

/**
  Hooked StartImage function.

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
  )
{
  EFI_STATUS                 Status;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[StartImage Hook] INTERCEPTED\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[StartImage] ImageHandle: 0x%p\n", ImageHandle));

  //
  // Log telemetry
  //
  LogTelemetry (L"StartImage hook triggered");

  //
  // Get loaded image information
  //
  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage
                  );

  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[StartImage] Image Information:\n"));
    DEBUG ((DEBUG_INFO, "[StartImage]   ImageBase: 0x%p\n", LoadedImage->ImageBase));
    DEBUG ((DEBUG_INFO, "[StartImage]   ImageSize: 0x%lx bytes\n", (UINT64)LoadedImage->ImageSize));
    DEBUG ((DEBUG_INFO, "[StartImage]   ImageCodeType: %d\n", LoadedImage->ImageCodeType));

    //
    // In a real bootkit (e.g., CosmicStrand), this would:
    // 1. Parse the image headers (PE/ELF)
    // 2. Locate the entry point
    // 3. Install inline hooks before execution
    // 4. Patch security checks
    // 5. Inject malicious code into .text section
    //
    DEBUG ((DEBUG_INFO, "[StartImage] In production bootkit, would:\n"));
    DEBUG ((DEBUG_INFO, "[StartImage]   1. Parse image at 0x%p\n", LoadedImage->ImageBase));
    DEBUG ((DEBUG_INFO, "[StartImage]   2. Locate entry point and key functions\n"));
    DEBUG ((DEBUG_INFO, "[StartImage]   3. Install inline hooks (MOV RAX, addr; JMP RAX)\n"));
    DEBUG ((DEBUG_INFO, "[StartImage]   4. Patch Secure Boot validation if present\n"));
    DEBUG ((DEBUG_INFO, "[StartImage]   5. Inject shellcode into executable sections\n"));
    DEBUG ((DEBUG_INFO, "[StartImage]   6. Modify import table for API hooking\n"));

    //
    // Check if this is a bootloader or critical system component
    //
    if (LoadedImage->ImageSize > 0x100000) {  // > 1MB suggests bootloader
      DEBUG ((DEBUG_WARN, "[StartImage] ⚠ Large image detected - likely bootloader!\n"));
      DEBUG ((DEBUG_WARN, "[StartImage]   This would be a HIGH-VALUE target for injection\n"));
    }
  }

  //
  // Call original StartImage
  //
  DEBUG ((DEBUG_INFO, "[StartImage] Calling original StartImage...\n"));
  Status = mOriginalStartImage (
             ImageHandle,
             ExitDataSize,
             ExitData
             );

  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[StartImage] ✓ Image executed successfully\n"));
  } else {
    DEBUG ((DEBUG_ERROR, "[StartImage] ✗ Image execution failed: %r\n", Status));
  }

  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));

  return Status;
}

/**
  Install StartImage hook.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
InstallStartImageHook (
  VOID
  )
{
  if (mOriginalStartImage != NULL) {
    DEBUG ((DEBUG_WARN, "[StartImage] Hook already installed\n"));
    return EFI_ALREADY_STARTED;
  }

  //
  // Save original StartImage pointer
  //
  mOriginalStartImage = gBS->StartImage;

  //
  // Install hook
  //
  gBS->StartImage = HookedStartImage;

  DEBUG ((DEBUG_INFO, "[StartImage] Hook installed successfully\n"));
  DEBUG ((DEBUG_INFO, "[StartImage]   Original: 0x%p\n", mOriginalStartImage));
  DEBUG ((DEBUG_INFO, "[StartImage]   Hooked: 0x%p\n", HookedStartImage));

  LogTelemetry (L"StartImage hook installed");

  return EFI_SUCCESS;
}


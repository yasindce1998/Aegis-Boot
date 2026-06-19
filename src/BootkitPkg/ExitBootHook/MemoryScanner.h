/** @file
  Memory Scanner Header

  Provides functions to locate OS kernel in memory during ExitBootServices.
  For academic research purposes only.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __MEMORY_SCANNER_H__
#define __MEMORY_SCANNER_H__

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <IndustryStandard/PeImage.h>

//
// PE/ELF Magic Numbers (guard against redefinition from PeImage.h)
//
#ifndef EFI_IMAGE_DOS_SIGNATURE
#define EFI_IMAGE_DOS_SIGNATURE     0x5A4D      // MZ
#endif
#ifndef EFI_IMAGE_NT_SIGNATURE
#define EFI_IMAGE_NT_SIGNATURE      0x00004550  // PE00
#endif
#define ELF_MAGIC_0                 0x7F        // 0x7F
#define ELF_MAGIC_1                 'E'
#define ELF_MAGIC_2                 'L'
#define ELF_MAGIC_3                 'F'

/**
  Locate OS kernel in memory by scanning for PE/ELF headers.

  @param[out]  KernelBase  Pointer to receive kernel base address.
  @param[out]  KernelSize  Pointer to receive kernel size in bytes.

  @retval EFI_SUCCESS      Kernel located successfully.
  @retval EFI_NOT_FOUND    Kernel not found in memory.
  @retval Other            Error occurred.

**/
EFI_STATUS
LocateOsKernel (
  OUT VOID   **KernelBase,
  OUT UINTN  *KernelSize
  );

/**
  Check if memory address contains a valid PE header.

  @param[in]  Address  Memory address to check.

  @retval TRUE   Valid PE header found.
  @retval FALSE  Not a valid PE header.

**/
BOOLEAN
IsPeHeader (
  IN VOID  *Address
  );

/**
  Check if memory address contains a valid ELF header.

  @param[in]  Address  Memory address to check.

  @retval TRUE   Valid ELF header found.
  @retval FALSE  Not a valid ELF header.

**/
BOOLEAN
IsElfHeader (
  IN VOID  *Address
  );

/**
  Parse PE header to get image size.

  @param[in]  ImageBase  Base address of PE image.

  @retval Image size in bytes, or 0 if invalid.

**/
UINTN
GetPeImageSize (
  IN VOID  *ImageBase
  );

/**
  Parse ELF header to get image size.

  @param[in]  ImageBase  Base address of ELF image.

  @retval Image size in bytes, or 0 if invalid.

**/
UINTN
GetElfImageSize (
  IN VOID  *ImageBase
  );

/**
  Scan memory region for specific pattern.

  @param[in]  StartAddress  Start of memory region.
  @param[in]  Size          Size of region to scan.
  @param[in]  Pattern       Pattern to search for.
  @param[in]  PatternSize   Size of pattern.

  @retval Pointer to pattern location, or NULL if not found.

**/
VOID *
ScanMemoryForPattern (
  IN VOID   *StartAddress,
  IN UINTN  Size,
  IN VOID   *Pattern,
  IN UINTN  PatternSize
  );

#endif // __MEMORY_SCANNER_H__


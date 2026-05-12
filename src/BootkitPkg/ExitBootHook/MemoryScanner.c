/** @file
  Memory Scanner Implementation

  Implements OS kernel detection in memory during ExitBootServices.
  For academic research purposes only - does not actually modify kernel.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "MemoryScanner.h"

/**
  Check if memory address contains a valid PE header.

  @param[in]  Address  Memory address to check.

  @retval TRUE   Valid PE header found.
  @retval FALSE  Not a valid PE header.

**/
BOOLEAN
IsPeHeader (
  IN VOID  *Address
  )
{
  EFI_IMAGE_DOS_HEADER     *DosHeader;
  EFI_IMAGE_NT_HEADERS64   *NtHeaders;
  UINT32                   e_lfanew;

  if (Address == NULL) {
    return FALSE;
  }

  //
  // Check DOS header signature
  //
  DosHeader = (EFI_IMAGE_DOS_HEADER *)Address;
  if (DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
    return FALSE;
  }

  //
  // Validate e_lfanew offset is reasonable
  //
  e_lfanew = DosHeader->e_lfanew;
  if (e_lfanew > 0x1000 || e_lfanew < sizeof(EFI_IMAGE_DOS_HEADER)) {
    return FALSE;
  }

  //
  // Check NT headers signature
  //
  NtHeaders = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)Address + e_lfanew);
  if (NtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE) {
    return FALSE;
  }

  //
  // Verify it's a valid machine type
  //
  if (NtHeaders->FileHeader.Machine != EFI_IMAGE_MACHINE_X64 &&
      NtHeaders->FileHeader.Machine != EFI_IMAGE_MACHINE_IA32) {
    return FALSE;
  }

  return TRUE;
}

/**
  Check if memory address contains a valid ELF header.

  @param[in]  Address  Memory address to check.

  @retval TRUE   Valid ELF header found.
  @retval FALSE  Not a valid ELF header.

**/
BOOLEAN
IsElfHeader (
  IN VOID  *Address
  )
{
  UINT8  *Magic;

  if (Address == NULL) {
    return FALSE;
  }

  Magic = (UINT8 *)Address;

  //
  // Check ELF magic: 0x7F 'E' 'L' 'F'
  //
  if (Magic[0] != ELF_MAGIC_0 ||
      Magic[1] != ELF_MAGIC_1 ||
      Magic[2] != ELF_MAGIC_2 ||
      Magic[3] != ELF_MAGIC_3) {
    return FALSE;
  }

  //
  // Check ELF class (32-bit or 64-bit)
  //
  if (Magic[4] != 1 && Magic[4] != 2) {  // 1=32-bit, 2=64-bit
    return FALSE;
  }

  return TRUE;
}

/**
  Parse PE header to get image size.

  @param[in]  ImageBase  Base address of PE image.

  @retval Image size in bytes, or 0 if invalid.

**/
UINTN
GetPeImageSize (
  IN VOID  *ImageBase
  )
{
  EFI_IMAGE_DOS_HEADER     *DosHeader;
  EFI_IMAGE_NT_HEADERS64   *NtHeaders;

  if (!IsPeHeader(ImageBase)) {
    return 0;
  }

  DosHeader = (EFI_IMAGE_DOS_HEADER *)ImageBase;
  NtHeaders = (EFI_IMAGE_NT_HEADERS64 *)((UINT8 *)ImageBase + DosHeader->e_lfanew);

  return (UINTN)NtHeaders->OptionalHeader.SizeOfImage;
}

/**
  Parse ELF header to get image size.

  @param[in]  ImageBase  Base address of ELF image.

  @retval Image size in bytes, or 0 if invalid.

**/
UINTN
GetElfImageSize (
  IN VOID  *ImageBase
  )
{
  UINT8   *Header;
  UINT64  *ProgramHeaderOffset;
  UINT16  *ProgramHeaderEntrySize;
  UINT16  *ProgramHeaderCount;
  UINTN   MaxAddress;
  UINTN   i;

  if (!IsElfHeader(ImageBase)) {
    return 0;
  }

  Header = (UINT8 *)ImageBase;

  //
  // For 64-bit ELF
  //
  if (Header[4] == 2) {
    ProgramHeaderOffset = (UINT64 *)(Header + 32);
    ProgramHeaderEntrySize = (UINT16 *)(Header + 54);
    ProgramHeaderCount = (UINT16 *)(Header + 56);

    MaxAddress = 0;

    //
    // Scan program headers to find highest address
    //
    for (i = 0; i < *ProgramHeaderCount; i++) {
      UINT8  *PhEntry = Header + *ProgramHeaderOffset + (i * *ProgramHeaderEntrySize);
      UINT64 *VAddr = (UINT64 *)(PhEntry + 16);
      UINT64 *MemSize = (UINT64 *)(PhEntry + 40);
      UINTN  EndAddr = (UINTN)(*VAddr + *MemSize);

      if (EndAddr > MaxAddress) {
        MaxAddress = EndAddr;
      }
    }

    return MaxAddress;
  }

  //
  // For 32-bit ELF (simplified)
  //
  return 0x100000;  // Default 1MB for 32-bit
}

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
  )
{
  UINT8  *Current;
  UINT8  *End;
  UINT8  *PatternBytes;

  if (StartAddress == NULL || Pattern == NULL || PatternSize == 0) {
    return NULL;
  }

  //
  // Guard against integer underflow when Size < PatternSize
  //
  if (Size < PatternSize) {
    DEBUG ((DEBUG_WARN, "[MemScan] Size (%d) < PatternSize (%d), cannot scan\n", Size, PatternSize));
    return NULL;
  }

  Current = (UINT8 *)StartAddress;
  End = Current + Size - PatternSize;
  PatternBytes = (UINT8 *)Pattern;

  //
  // Scan memory for pattern
  //
  while (Current <= End) {
    if (CompareMem(Current, PatternBytes, PatternSize) == 0) {
      return (VOID *)Current;
    }
    Current++;
  }

  return NULL;
}

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
  )
{
  EFI_STATUS             Status;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                  MemoryMapSize;
  UINTN                  MapKey;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;
  UINTN                  Index;
  VOID                   *TestAddress;

  if (KernelBase == NULL || KernelSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get memory map
  //
  MemoryMapSize = 0;
  MemoryMap = NULL;

  Status = gBS->GetMemoryMap(
                  &MemoryMapSize,
                  MemoryMap,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );

  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }

  //
  // Allocate buffer for memory map
  //
  MemoryMapSize += EFI_PAGE_SIZE;
  Status = gBS->AllocatePool(
                  EfiBootServicesData,
                  MemoryMapSize,
                  (VOID **)&MemoryMap
                  );

  if (EFI_ERROR(Status)) {
    return Status;
  }

  //
  // Get actual memory map
  //
  Status = gBS->GetMemoryMap(
                  &MemoryMapSize,
                  MemoryMap,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );

  if (EFI_ERROR(Status)) {
    gBS->FreePool(MemoryMap);
    return Status;
  }

  DEBUG((DEBUG_INFO, "[MemScan] Scanning memory map for OS kernel...\n"));
  DEBUG((DEBUG_INFO, "[MemScan] Memory map entries: %lu\n", MemoryMapSize / DescriptorSize));

  //
  // Scan memory map for kernel
  //
  Descriptor = MemoryMap;
  for (Index = 0; Index < MemoryMapSize / DescriptorSize; Index++) {
    //
    // Look in loader code/data regions
    //
    if (Descriptor->Type == EfiLoaderCode ||
        Descriptor->Type == EfiLoaderData ||
        Descriptor->Type == EfiBootServicesCode) {

      TestAddress = (VOID *)(UINTN)Descriptor->PhysicalStart;

      //
      // Check for PE header (Windows)
      //
      if (IsPeHeader(TestAddress)) {
        *KernelBase = TestAddress;
        *KernelSize = GetPeImageSize(TestAddress);

        DEBUG((DEBUG_INFO, "[MemScan] Windows PE kernel found!\n"));
        DEBUG((DEBUG_INFO, "[MemScan]   Base: 0x%p\n", *KernelBase));
        DEBUG((DEBUG_INFO, "[MemScan]   Size: 0x%lx bytes\n", *KernelSize));

        gBS->FreePool(MemoryMap);
        return EFI_SUCCESS;
      }

      //
      // Check for ELF header (Linux)
      //
      if (IsElfHeader(TestAddress)) {
        *KernelBase = TestAddress;
        *KernelSize = GetElfImageSize(TestAddress);

        DEBUG((DEBUG_INFO, "[MemScan] Linux ELF kernel found!\n"));
        DEBUG((DEBUG_INFO, "[MemScan]   Base: 0x%p\n", *KernelBase));
        DEBUG((DEBUG_INFO, "[MemScan]   Size: 0x%lx bytes\n", *KernelSize));

        gBS->FreePool(MemoryMap);
        return EFI_SUCCESS;
      }
    }

    //
    // Move to next descriptor
    //
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Descriptor + DescriptorSize);
  }

  DEBUG((DEBUG_WARN, "[MemScan] OS kernel not found in memory\n"));

  gBS->FreePool(MemoryMap);
  return EFI_NOT_FOUND;
}

// Made with Bob
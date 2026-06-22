/** @file
  SPI Chipset Register Emulation - Implementation

  Emulates chipset register-level SPI flash manipulation. Models the LoJax
  technique of directly toggling BIOS_CNTL.BiosWe to enable flash writes,
  bypassing FLOCKDN via TOCTOU race conditions, and using hardware sequencing
  registers (HSFS/HSFC) for direct flash operations.

  All operations are SIMULATED - no actual chipset registers are modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SpiChipsetEmulator.h"

STATIC SPI_CHIPSET_CONTEXT  mSpiContext;

EFI_STATUS
EFIAPI
InitializeSpiChipset (
  OUT SPI_CHIPSET_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (SPI_CHIPSET_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = SpiStateUninitialized;

  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ReadChipsetRegisters (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  )
{
  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  if (SIMULATION_MODE) {
    Context->BiosCntl = BIOS_CNTL_BLE | BIOS_CNTL_SMM_BWP;
    Context->BiosWeSet = FALSE;
    Context->BleSet = TRUE;
    Context->SmmBwpSet = TRUE;

    Context->SpiBar = 0xFE010000;
    Context->SpiBarValid = TRUE;

    Context->Hsfs = SPI_HSFS_FDV | SPI_HSFS_FLOCKDN;
    Context->Hsfc = 0;
    Context->FlockdnSet = TRUE;
    Context->FlashDescriptorValid = TRUE;

    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "BIOS_CNTL (PCI B%d:D%d:F%d+0x%02x): 0x%02x\n",
            LPC_PCI_BUS, LPC_PCI_DEV, LPC_PCI_FUNC, BIOS_CNTL_OFFSET, Context->BiosCntl));
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  BIOSWE=%d  BLE=%d  SMM_BWP=%d\n",
            Context->BiosWeSet, Context->BleSet, Context->SmmBwpSet));
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "SPIBAR: 0x%016lx\n", Context->SpiBar));
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "HSFS: 0x%04x (FDV=%d FLOCKDN=%d)\n",
            Context->Hsfs, Context->FlashDescriptorValid, Context->FlockdnSet));
  } else {
    Context->BiosCntl = PciRead8 (PCI_LIB_ADDRESS (
                          LPC_PCI_BUS, LPC_PCI_DEV, LPC_PCI_FUNC, BIOS_CNTL_OFFSET));
    Context->BiosWeSet = (Context->BiosCntl & BIOS_CNTL_BIOSWE) != 0;
    Context->BleSet = (Context->BiosCntl & BIOS_CNTL_BLE) != 0;
    Context->SmmBwpSet = (Context->BiosCntl & BIOS_CNTL_SMM_BWP) != 0;
  }

  Context->State = SpiStateRegistersRead;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
AnalyzeWriteProtection (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  )
{
  UINT32  Index;
  UINT32  PrValue;

  if (Context->State < SpiStateRegistersRead) {
    return EFI_NOT_READY;
  }

  if (SIMULATION_MODE) {
    Context->ProtectedRanges[0].BaseAddress = 0x00000000;
    Context->ProtectedRanges[0].LimitAddress = 0x00000FFF;
    Context->ProtectedRanges[0].WriteProtected = TRUE;
    Context->ProtectedRanges[0].ReadProtected = FALSE;

    Context->ProtectedRanges[1].BaseAddress = 0x00FF0000;
    Context->ProtectedRanges[1].LimitAddress = 0x00FFFFFF;
    Context->ProtectedRanges[1].WriteProtected = TRUE;
    Context->ProtectedRanges[1].ReadProtected = FALSE;

    Context->ProtectedRangeCount = 2;
  } else {
    Context->ProtectedRangeCount = 0;
    for (Index = 0; Index < SPI_PR_COUNT; Index++) {
      PrValue = MmioRead32 ((UINTN)(Context->SpiBar + SPI_PR0_OFFSET + (Index * 4)));
      if ((PrValue & SPI_PR_WPE) || (PrValue & SPI_PR_RPE)) {
        Context->ProtectedRanges[Context->ProtectedRangeCount].WriteProtected =
          (PrValue & SPI_PR_WPE) != 0;
        Context->ProtectedRanges[Context->ProtectedRangeCount].ReadProtected =
          (PrValue & SPI_PR_RPE) != 0;
        Context->ProtectedRanges[Context->ProtectedRangeCount].BaseAddress =
          (PrValue & 0x1FFF) << 12;
        Context->ProtectedRanges[Context->ProtectedRangeCount].LimitAddress =
          ((PrValue >> 16) & 0x1FFF) << 12;
        Context->ProtectedRangeCount++;
      }
    }
  }

  for (Index = 0; Index < Context->ProtectedRangeCount; Index++) {
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "PR%d: Base=0x%08x Limit=0x%08x WP=%d RP=%d\n",
            Index,
            Context->ProtectedRanges[Index].BaseAddress,
            Context->ProtectedRanges[Index].LimitAddress,
            Context->ProtectedRanges[Index].WriteProtected,
            Context->ProtectedRanges[Index].ReadProtected));
  }

  Context->State = SpiStateProtectionAnalyzed;
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "Write protection analysis complete: %d ranges active\n",
          Context->ProtectedRangeCount));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateBiosWeToggle (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  )
{
  if (Context->State < SpiStateProtectionAnalyzed) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "Attempting BIOS_CNTL.BIOSWE toggle (LoJax technique)...\n"));

  if (Context->BleSet) {
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  BLE is set - setting BIOSWE will generate SMI\n"));
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  SMI handler will clear BIOSWE (normal platform behavior)\n"));

    if (Context->SmmBwpSet) {
      DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  SMM_BWP is set - writes blocked even from SMM\n"));
      DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  → Standard BIOSWE toggle BLOCKED\n"));
      DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  → Need TOCTOU or SMM vulnerability to proceed\n"));
    } else {
      DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  SMM_BWP is clear - SMM can write flash\n"));
      DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  → BIOSWE toggle viable via SMM code execution\n"));
    }
  } else {
    if (SIMULATION_MODE) {
      Context->BiosWeSet = TRUE;
      Context->BiosCntl |= BIOS_CNTL_BIOSWE;
      DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  BLE clear - BIOSWE set directly [SIMULATED]\n"));
      Context->State = SpiStateWriteEnabled;
      return EFI_SUCCESS;
    }
  }

  Context->State = SpiStateBypassAttempted;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateToctouBypass (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  )
{
  if (Context->State < SpiStateBypassAttempted) {
    return EFI_NOT_READY;
  }

  Context->ToctouAttempted = TRUE;

  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "Emulating TOCTOU race condition bypass...\n"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  Technique: Race between BIOSWE check and SMI handler\n"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  Step 1: Set BIOSWE (triggers SMI via BLE)\n"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  Step 2: Immediately issue SPI write cycle\n"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  Step 3: Write completes before SMI handler clears BIOSWE\n"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  Window: ~100ns between BIOSWE set and SMI delivery\n"));

  if (SIMULATION_MODE) {
    Context->ToctouSucceeded = TRUE;
    Context->BiosWeSet = TRUE;
    Context->State = SpiStateWriteEnabled;
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  → TOCTOU bypass SUCCEEDED [SIMULATED]\n"));
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateHardwareSequencing (
  IN OUT SPI_CHIPSET_CONTEXT  *Context,
  IN     UINT8               CycleType,
  IN     UINT32              Address,
  IN     UINT32              DataSize
  )
{
  CHAR8  *CycleStr;

  if (Context->State < SpiStateWriteEnabled) {
    DEBUG ((DEBUG_WARN, SPI_DEBUG_PREFIX "Flash not write-enabled, cannot sequence\n"));
    return EFI_ACCESS_DENIED;
  }

  switch (CycleType) {
    case SPI_HSFC_FCYCLE_READ:  CycleStr = "READ";  break;
    case SPI_HSFC_FCYCLE_WRITE: CycleStr = "WRITE"; break;
    case SPI_HSFC_FCYCLE_ERASE: CycleStr = "ERASE"; break;
    default:                    CycleStr = "UNKNOWN"; break;
  }

  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "Hardware Sequencing: %a cycle\n", CycleStr));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  FADDR = 0x%08x\n", Address));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  FDBC  = %d bytes\n", DataSize));

  if (SIMULATION_MODE) {
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  HSFC.FGO = 1 [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  Polling HSFS.FDONE...\n"));
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  HSFS.FDONE = 1, HSFS.FCERR = 0 [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  → %a cycle completed successfully\n", CycleStr));
  }

  return EFI_SUCCESS;
}

VOID
EFIAPI
LogSpiChipsetStatus (
  IN     SPI_CHIPSET_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case SpiStateUninitialized:      StateStr = "Uninitialized"; break;
    case SpiStateRegistersRead:      StateStr = "Registers Read"; break;
    case SpiStateProtectionAnalyzed: StateStr = "Protection Analyzed"; break;
    case SpiStateBypassAttempted:    StateStr = "Bypass Attempted"; break;
    case SpiStateWriteEnabled:       StateStr = "Write Enabled"; break;
    default:                         StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "=== SPI Chipset Register Status ===\n"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  State:       %a\n", StateStr));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  BIOS_CNTL:   0x%02x (BIOSWE=%d BLE=%d SMM_BWP=%d)\n",
          Context->BiosCntl, Context->BiosWeSet, Context->BleSet, Context->SmmBwpSet));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  SPIBAR:      0x%016lx (Valid=%a)\n",
          Context->SpiBar, Context->SpiBarValid ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  FLOCKDN:     %a\n", Context->FlockdnSet ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  PRx Ranges:  %d active\n", Context->ProtectedRangeCount));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "  TOCTOU:      Attempted=%a Succeeded=%a\n",
          Context->ToctouAttempted ? "Yes" : "No",
          Context->ToctouSucceeded ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "===================================\n\n"));
}

EFI_STATUS
EFIAPI
SpiChipsetEmulatorEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "Module loaded - Chipset Register Manipulation Emulation\n"));

  Status = InitializeSpiChipset (&mSpiContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ReadChipsetRegisters (&mSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SPI_DEBUG_PREFIX "Failed to read chipset registers: %r\n", Status));
    return Status;
  }

  Status = AnalyzeWriteProtection (&mSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SPI_DEBUG_PREFIX "Protection analysis failed: %r\n", Status));
    return Status;
  }

  Status = EmulateBiosWeToggle (&mSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, SPI_DEBUG_PREFIX "BIOSWE toggle: %r\n", Status));
  }

  if (mSpiContext.State < SpiStateWriteEnabled) {
    Status = EmulateToctouBypass (&mSpiContext);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, SPI_DEBUG_PREFIX "TOCTOU bypass: %r\n", Status));
    }
  }

  if (mSpiContext.State == SpiStateWriteEnabled) {
    EmulateHardwareSequencing (&mSpiContext, SPI_HSFC_FCYCLE_WRITE, 0x00FF0000, 64);
  }

  LogSpiChipsetStatus (&mSpiContext);

  DEBUG ((DEBUG_INFO, SPI_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}

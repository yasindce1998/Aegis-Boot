/** @file
  Boot Guard Emulator - Models Intel Boot Guard / AMD PSB Protections

  Emulates the hardware-rooted Verified/Measured Boot mechanisms
  that protect firmware integrity on 2024+ platforms. This models
  how Boot Guard ACM measures the Initial Boot Block (IBB) and
  extends TPM PCRs, and identifies persistence slots outside
  the measured region.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __BOOT_GUARD_EMULATOR_H__
#define __BOOT_GUARD_EMULATOR_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

//
// Boot Guard Profile Types (Intel Boot Guard configuration modes)
//
typedef enum {
  BootGuardDisabled          = 0,
  BootGuardMeasuredBoot      = 1,
  BootGuardVerifiedBoot      = 2,
  BootGuardMeasuredVerified  = 3
} BOOT_GUARD_PROFILE;

//
// ACM (Authenticated Code Module) Status Flags
//
#define ACM_STATUS_VALID           BIT0
#define ACM_STATUS_IBB_MEASURED    BIT1
#define ACM_STATUS_IBB_VERIFIED    BIT2
#define ACM_STATUS_STARTUP_ERROR   BIT3
#define ACM_STATUS_KM_REVOKED      BIT4

//
// Boot Guard PCR indices
//
#define BOOT_GUARD_PCR_IBB       0
#define BOOT_GUARD_PCR_AUTHORITY 7

//
// IBB (Initial Boot Block) segment descriptor
//
#define IBB_MAX_SEGMENTS  8

typedef struct {
  UINT32    Base;
  UINT32    Size;
  UINT8     Hash[32];    // SHA-256 of segment
} IBB_SEGMENT;

//
// Boot Guard Emulator Context
//
typedef struct {
  BOOLEAN             Initialized;
  BOOT_GUARD_PROFILE  Profile;
  UINT32              AcmStatus;
  //
  // IBB measurement state
  //
  IBB_SEGMENT         IbbSegments[IBB_MAX_SEGMENTS];
  UINT32              IbbSegmentCount;
  UINT8               IbbDigest[32];             // Combined IBB hash
  BOOLEAN             IbbMeasurementComplete;
  //
  // Key Manifest / Boot Policy
  //
  UINT8               KeyManifestHash[32];       // KM signing key hash (fused)
  UINT32              KeyManifestRevision;
  BOOLEAN             EnforcementOnFailure;      // Shutdown vs continue on verify fail
  //
  // Non-measured region tracking (attack surface)
  //
  UINT32              NonMeasuredBase;
  UINT32              NonMeasuredSize;
  BOOLEAN             NonMeasuredRegionFound;
} BOOT_GUARD_EMULATOR;

/**
  Initialize Boot Guard Emulator.

  @param[in,out]  Emulator  Pointer to emulator context.
  @param[in]      Profile   Boot Guard profile to emulate.

  @retval EFI_SUCCESS           Emulator initialized.
  @retval EFI_INVALID_PARAMETER Emulator is NULL or invalid profile.
**/
EFI_STATUS
EFIAPI
InitializeBootGuardEmulator (
  IN OUT BOOT_GUARD_EMULATOR  *Emulator,
  IN     BOOT_GUARD_PROFILE   Profile
  );

/**
  Add an IBB segment to the measurement set.

  @param[in]  Emulator  Pointer to emulator context.
  @param[in]  Base      Segment base address in flash.
  @param[in]  Size      Segment size in bytes.

  @retval EFI_SUCCESS           Segment added.
  @retval EFI_OUT_OF_RESOURCES  Max segments reached.
**/
EFI_STATUS
EFIAPI
BootGuardAddIbbSegment (
  IN BOOT_GUARD_EMULATOR  *Emulator,
  IN UINT32               Base,
  IN UINT32               Size
  );

/**
  Emulate IBB measurement (what Boot Guard ACM does at reset).

  Hashes all IBB segments, extends PCR[0] and PCR[7].

  @param[in]  Emulator   Pointer to emulator context.
  @param[in]  FlashData  Flash memory buffer to hash from.
  @param[in]  FlashSize  Total flash buffer size.

  @retval EFI_SUCCESS           Measurement complete.
  @retval EFI_NOT_READY         No IBB segments configured.
**/
EFI_STATUS
EFIAPI
EmulateIbbMeasurement (
  IN BOOT_GUARD_EMULATOR  *Emulator,
  IN UINT8                *FlashData,
  IN UINT32               FlashSize
  );

/**
  Find persistence slots outside the measured IBB region.

  Scans DXE FV for space that Boot Guard does NOT cover, which
  is the real attack surface for MosaicRegressor/CosmicStrand.

  @param[in]   Emulator        Pointer to emulator context.
  @param[in]   FvBase          Firmware Volume base in flash.
  @param[in]   FvSize          Firmware Volume size.
  @param[out]  SlotBase        Base of non-measured free space.
  @param[out]  SlotSize        Size of non-measured free space.

  @retval EFI_SUCCESS           Slot found.
  @retval EFI_NOT_FOUND         No non-measured space available.
**/
EFI_STATUS
EFIAPI
FindNonMeasuredPersistenceSlot (
  IN  BOOT_GUARD_EMULATOR  *Emulator,
  IN  UINT32               FvBase,
  IN  UINT32               FvSize,
  OUT UINT32               *SlotBase,
  OUT UINT32               *SlotSize
  );

/**
  Log Boot Guard emulator status.

  @param[in]  Emulator  Pointer to emulator context.
**/
VOID
EFIAPI
LogBootGuardStatus (
  IN BOOT_GUARD_EMULATOR  *Emulator
  );

#endif // __BOOT_GUARD_EMULATOR_H__

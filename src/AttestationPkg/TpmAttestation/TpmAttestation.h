/** @file
  TPM Attestation Module Header

  Defines structures and functions for TPM PCR querying and
  Measured Boot validation.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __TPM_ATTESTATION_H__
#define __TPM_ATTESTATION_H__

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/Tpm20.h>

//
// Module identification
//
#define TPM_ATTESTATION_SIGNATURE  SIGNATURE_32('T','P','M','A')
#define TPM_ATTESTATION_VERSION    0x00010000

//
// PCR indices to monitor
//
#define PCR_0   0  // Core System Firmware
#define PCR_1   1  // Platform Configuration
#define PCR_2   2  // Option ROM Code
#define PCR_3   3  // Option ROM Configuration
#define PCR_4   4  // Boot Manager Code
#define PCR_5   5  // Boot Manager Configuration
#define PCR_6   6  // Platform Manufacturer Specific
#define PCR_7   7  // Secure Boot Policy

//
// Number of PCRs to monitor
//
#define MONITORED_PCR_COUNT  8

//
// SHA-256 digest size
//
#define SHA256_DIGEST_SIZE  32

//
// PCR measurement structure
//
typedef struct {
  UINT32  PcrIndex;
  UINT8   Digest[SHA256_DIGEST_SIZE];
  CHAR16  Description[64];
} PCR_MEASUREMENT;

//
// Attestation context
//
typedef struct {
  UINT32                Signature;
  UINT32                Version;
  EFI_TCG2_PROTOCOL     *Tcg2Protocol;
  PCR_MEASUREMENT       Baseline[MONITORED_PCR_COUNT];
  PCR_MEASUREMENT       Current[MONITORED_PCR_COUNT];
  BOOLEAN               BaselineEstablished;
  BOOLEAN               TamperingDetected;
  UINT32                TamperedPcrCount;
} TPM_ATTESTATION_CONTEXT;

/**
  Entry point for the TPM Attestation driver.

  @param[in]  ImageHandle  Handle for the image of this driver.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS      Driver initialized successfully.
  @retval Other            Error occurred during initialization.

**/
EFI_STATUS
EFIAPI
TpmAttestationEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

/**
  Read PCR values from TPM.

  @param[in]   Context       Pointer to attestation context.
  @param[out]  Measurements  Array to store PCR measurements.

  @retval EFI_SUCCESS      PCRs read successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
ReadPcrValues (
  IN  TPM_ATTESTATION_CONTEXT  *Context,
  OUT PCR_MEASUREMENT          *Measurements
  );

/**
  Establish baseline PCR measurements.

  @param[in]  Context  Pointer to attestation context.

  @retval EFI_SUCCESS  Baseline established successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
EstablishBaseline (
  IN OUT TPM_ATTESTATION_CONTEXT  *Context
  );

/**
  Compare current PCR values against baseline.

  @param[in]  Context  Pointer to attestation context.

  @retval EFI_SUCCESS      No tampering detected.
  @retval EFI_COMPROMISED  Tampering detected.
  @retval Other            Error occurred.

**/
EFI_STATUS
ValidatePcrIntegrity (
  IN OUT TPM_ATTESTATION_CONTEXT  *Context
  );

/**
  Log PCR measurements for research purposes.

  @param[in]  Measurements  Array of PCR measurements.
  @param[in]  Count         Number of measurements.
  @param[in]  Label         Label for the measurements.

**/
VOID
LogPcrMeasurements (
  IN CONST PCR_MEASUREMENT  *Measurements,
  IN UINTN                  Count,
  IN CONST CHAR16           *Label
  );

/**
  Calculate SHA-256 hash.

  @param[in]   Data       Data to hash.
  @param[in]   DataSize   Size of data.
  @param[out]  Digest     Buffer to receive digest.

  @retval EFI_SUCCESS  Hash calculated successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
CalculateSha256 (
  IN  CONST VOID  *Data,
  IN  UINTN       DataSize,
  OUT UINT8       *Digest
  );

/**
  Export attestation data for analysis.

  @param[in]  Context  Pointer to attestation context.

  @retval EFI_SUCCESS  Data exported successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
ExportAttestationData (
  IN TPM_ATTESTATION_CONTEXT  *Context
  );

#endif // __TPM_ATTESTATION_H__

// Made with Bob

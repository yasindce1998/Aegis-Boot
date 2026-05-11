/** @file
  TPM Attestation Module Implementation

  Implements TPM PCR querying and Measured Boot validation for
  defensive security research.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "TpmAttestation.h"
#include <Library/Tpm2CommandLib.h>

//
// Global attestation context
//
STATIC TPM_ATTESTATION_CONTEXT  mAttestationContext = {
  .Signature            = TPM_ATTESTATION_SIGNATURE,
  .Version              = TPM_ATTESTATION_VERSION,
  .Tcg2Protocol         = NULL,
  .BaselineEstablished  = FALSE,
  .TamperingDetected    = FALSE,
  .TamperedPcrCount     = 0
};

//
// PCR descriptions
//
STATIC CONST CHAR16  *mPcrDescriptions[MONITORED_PCR_COUNT] = {
  L"PCR 0: Core System Firmware",
  L"PCR 1: Platform Configuration",
  L"PCR 2: Option ROM Code",
  L"PCR 3: Option ROM Configuration",
  L"PCR 4: Boot Manager Code",
  L"PCR 5: Boot Manager Configuration",
  L"PCR 6: Platform Manufacturer",
  L"PCR 7: Secure Boot Policy"
};

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
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "Aegis-Boot TPM Attestation Module\n"));
  DEBUG ((DEBUG_INFO, "Version: %08x\n", TPM_ATTESTATION_VERSION));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));

  //
  // Locate TCG2 Protocol
  //
  DEBUG ((DEBUG_INFO, "[Attestation] Locating TCG2 Protocol...\n"));
  Status = gBS->LocateProtocol (
                  &gEfiTcg2ProtocolGuid,
                  NULL,
                  (VOID **)&mAttestationContext.Tcg2Protocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Attestation] TCG2 Protocol not found: %r\n", Status));
    DEBUG ((DEBUG_WARN, "[Attestation] TPM may not be available\n"));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[Attestation] TCG2 Protocol located successfully\n"));

  //
  // Establish baseline PCR measurements
  //
  DEBUG ((DEBUG_INFO, "[Attestation] Establishing baseline measurements...\n"));
  Status = EstablishBaseline (&mAttestationContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Attestation] Failed to establish baseline: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[Attestation] Baseline established successfully\n"));

  //
  // Log baseline measurements
  //
  LogPcrMeasurements (
    mAttestationContext.Baseline,
    MONITORED_PCR_COUNT,
    L"Baseline"
    );

  //
  // Validate PCR integrity (compare against baseline)
  //
  DEBUG ((DEBUG_INFO, "[Attestation] Validating PCR integrity...\n"));
  Status = ValidatePcrIntegrity (&mAttestationContext);
  if (Status == EFI_COMPROMISED_DATA) {
    DEBUG ((DEBUG_ERROR, "[Attestation] PCR TAMPERING DETECTED!\n"));
    DEBUG ((DEBUG_ERROR, "[Attestation] %d PCR(s) have been modified\n", mAttestationContext.TamperedPcrCount));
  } else if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[Attestation] PCR integrity validated - no tampering detected\n"));
  }

  //
  // Export attestation data for analysis
  //
  DEBUG ((DEBUG_INFO, "[Attestation] Exporting attestation data...\n"));
  Status = ExportAttestationData (&mAttestationContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "[Attestation] Failed to export data: %r\n", Status));
  }

  DEBUG ((DEBUG_INFO, "[Attestation] TPM Attestation module initialized\n"));

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS  Status;
  UINT32      PcrIndex;
  TPML_PCR_SELECTION  PcrSelectionIn;
  UINT32              PcrUpdateCounter;
  TPML_PCR_SELECTION  PcrSelectionOut;
  TPML_DIGEST         PcrValues;

  if (Context == NULL || Measurements == NULL || Context->Tcg2Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Read each PCR
  //
  for (PcrIndex = 0; PcrIndex < MONITORED_PCR_COUNT; PcrIndex++) {
    //
    // Setup PCR selection
    //
    ZeroMem (&PcrSelectionIn, sizeof (PcrSelectionIn));
    PcrSelectionIn.count = 1;
    PcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA256;
    PcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
    PcrSelectionIn.pcrSelections[0].pcrSelect[PcrIndex / 8] = (1 << (PcrIndex % 8));

    //
    // Read PCR
    //
    Status = Tpm2PcrRead (
               &PcrSelectionIn,
               &PcrUpdateCounter,
               &PcrSelectionOut,
               &PcrValues
               );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[Attestation] Failed to read PCR %d: %r\n", PcrIndex, Status));
      return Status;
    }

    //
    // Store measurement
    //
    Measurements[PcrIndex].PcrIndex = PcrIndex;
    CopyMem (
      Measurements[PcrIndex].Digest,
      PcrValues.digests[0].buffer,
      MIN (SHA256_DIGEST_SIZE, PcrValues.digests[0].size)
      );
    StrnCpyS (
      Measurements[PcrIndex].Description,
      sizeof (Measurements[PcrIndex].Description) / sizeof (CHAR16),
      mPcrDescriptions[PcrIndex],
      StrLen (mPcrDescriptions[PcrIndex])
      );
  }

  return EFI_SUCCESS;
}

/**
  Establish baseline PCR measurements.

  @param[in]  Context  Pointer to attestation context.

  @retval EFI_SUCCESS  Baseline established successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
EstablishBaseline (
  IN OUT TPM_ATTESTATION_CONTEXT  *Context
  )
{
  EFI_STATUS  Status;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Read current PCR values as baseline
  //
  Status = ReadPcrValues (Context, Context->Baseline);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Attestation] Failed to read baseline PCRs: %r\n", Status));
    return Status;
  }

  Context->BaselineEstablished = TRUE;

  DEBUG ((DEBUG_INFO, "[Attestation] Baseline established for %d PCRs\n", MONITORED_PCR_COUNT));

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS  Status;
  UINT32      PcrIndex;
  BOOLEAN     TamperingDetected;

  if (Context == NULL || !Context->BaselineEstablished) {
    return EFI_NOT_READY;
  }

  //
  // Read current PCR values
  //
  Status = ReadPcrValues (Context, Context->Current);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Attestation] Failed to read current PCRs: %r\n", Status));
    return Status;
  }

  //
  // Compare against baseline
  //
  TamperingDetected = FALSE;
  Context->TamperedPcrCount = 0;

  for (PcrIndex = 0; PcrIndex < MONITORED_PCR_COUNT; PcrIndex++) {
    if (CompareMem (
          Context->Baseline[PcrIndex].Digest,
          Context->Current[PcrIndex].Digest,
          SHA256_DIGEST_SIZE
          ) != 0)
    {
      TamperingDetected = TRUE;
      Context->TamperedPcrCount++;

      DEBUG ((DEBUG_ERROR, "[Attestation] PCR %d MODIFIED!\n", PcrIndex));
      DEBUG ((DEBUG_ERROR, "[Attestation]   %s\n", mPcrDescriptions[PcrIndex]));
    }
  }

  Context->TamperingDetected = TamperingDetected;

  if (TamperingDetected) {
    //
    // Log current measurements for comparison
    //
    LogPcrMeasurements (
      Context->Current,
      MONITORED_PCR_COUNT,
      L"Current (TAMPERED)"
      );

    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

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
  )
{
  UINTN   Index;
  UINTN   DigestIndex;
  CHAR16  DigestString[SHA256_DIGEST_SIZE * 2 + 1];

  if (Measurements == NULL || Label == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "=== PCR Measurements: %s ===\n", Label));

  for (Index = 0; Index < Count; Index++) {
    //
    // Convert digest to hex string
    //
    for (DigestIndex = 0; DigestIndex < SHA256_DIGEST_SIZE; DigestIndex++) {
      UnicodeSPrint (
        &DigestString[DigestIndex * 2],
        3 * sizeof (CHAR16),
        L"%02x",
        Measurements[Index].Digest[DigestIndex]
        );
    }
    DigestString[SHA256_DIGEST_SIZE * 2] = L'\0';

    DEBUG ((
      DEBUG_INFO,
      "[Attestation] PCR %d: %s\n",
      Measurements[Index].PcrIndex,
      Measurements[Index].Description
      ));
    DEBUG ((DEBUG_INFO, "[Attestation]   SHA256: %s\n", DigestString));
  }

  DEBUG ((DEBUG_INFO, "=== End PCR Measurements ===\n"));
  DEBUG ((DEBUG_INFO, "\n"));
}

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
  )
{
  BOOLEAN  Result;

  if (Data == NULL || Digest == NULL || DataSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Calculate SHA-256 hash
  //
  Result = Sha256HashAll (Data, DataSize, Digest);
  if (!Result) {
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Export attestation data for analysis.

  @param[in]  Context  Pointer to attestation context.

  @retval EFI_SUCCESS  Data exported successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
ExportAttestationData (
  IN TPM_ATTESTATION_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // In a real implementation, we would:
  // 1. Write to a dedicated logging partition
  // 2. Export to serial port for capture
  // 3. Store in NVRAM for post-boot analysis
  // 4. Send to AegisScanner for detection rule generation
  //

  DEBUG ((DEBUG_INFO, "[Attestation] === Attestation Data Export ===\n"));
  DEBUG ((DEBUG_INFO, "[Attestation] Baseline Established: %a\n", Context->BaselineEstablished ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, "[Attestation] Tampering Detected: %a\n", Context->TamperingDetected ? "YES" : "No"));
  DEBUG ((DEBUG_INFO, "[Attestation] Tampered PCR Count: %d\n", Context->TamperedPcrCount));
  DEBUG ((DEBUG_INFO, "[Attestation] === End Export ===\n"));

  return EFI_SUCCESS;
}

// Made with Bob

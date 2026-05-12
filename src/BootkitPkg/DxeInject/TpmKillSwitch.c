/** @file
  TPM-Based Kill-Switch Implementation

  Provides enhanced security through TPM-based validation mechanisms.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "TpmKillSwitch.h"
#include <Library/BaseCryptLib.h>
#include <Library/UefiBootServicesTableLib.h>

//
// Global expected EK (configured at build time)
//
STATIC TPM_EXPECTED_EK  mExpectedEk = {
  .PublicKey   = { 0 },  // Set to actual EK in production
  .KeySize     = 0,
  .Initialized = FALSE
};

//
// TCG2 Protocol for TPM access
//
STATIC EFI_TCG2_PROTOCOL  *mTcg2Protocol = NULL;

/**
  Initialize TPM kill-switch subsystem.

  @retval EFI_SUCCESS  Initialization successful.
  @retval Other        Error occurred.
**/
EFI_STATUS
EFIAPI
InitializeTpmKillSwitch (
  VOID
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "[TPM-KS] Initializing TPM kill-switch...\n"));

  //
  // Locate TCG2 Protocol
  //
  Status = gBS->LocateProtocol (
                  &gEfiTcg2ProtocolGuid,
                  NULL,
                  (VOID **)&mTcg2Protocol
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "[TPM-KS] TCG2 Protocol not found: %r\n", Status));
    DEBUG ((DEBUG_WARN, "[TPM-KS] TPM-based kill-switches disabled\n"));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] TCG2 Protocol located\n"));

  //
  // Initialize expected EK (in production, load from secure storage)
  //
  if (!mExpectedEk.Initialized) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] No expected EK configured\n"));
    DEBUG ((DEBUG_ERROR, "[TPM-KS] TPM kill-switch cannot be enforced without EK\n"));
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

/**
  Validate TPM Endorsement Key against expected value.

  @param[in]  ExpectedEk  Expected EK structure.

  @retval TPM_KILL_SWITCH_RESULT  Validation result.
**/
TPM_KILL_SWITCH_RESULT
EFIAPI
ValidateTpmEndorsementKey (
  IN TPM_EXPECTED_EK  *ExpectedEk
  )
{
  EFI_STATUS  Status;
  UINT8       ActualEk[TPM_EK_SIZE];
  UINT32      ActualEkSize;

  if (mTcg2Protocol == NULL) {
    DEBUG ((DEBUG_WARN, "[TPM-KS] No TPM available\n"));
    return TpmKillSwitchNoTpm;
  }

  if (ExpectedEk == NULL || !ExpectedEk->Initialized) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] No expected EK configured - validation FAILED\n"));
    return TpmKillSwitchError;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] Validating TPM Endorsement Key...\n"));

  //
  // Read TPM EK (simplified - actual implementation would use TPM2_ReadPublic)
  //
  ActualEkSize = sizeof (ActualEk);
  Status       = Tpm2ReadPublic (
                   TPM_RH_ENDORSEMENT,
                   ActualEk,
                   &ActualEkSize
                   );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] Failed to read TPM EK: %r\n", Status));
    return TpmKillSwitchError;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] Read %d bytes of EK data\n", ActualEkSize));

  //
  // Compare EK
  //
  if (ActualEkSize != ExpectedEk->KeySize) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] EK size mismatch: %d != %d\n", ActualEkSize, ExpectedEk->KeySize));
    return TpmKillSwitchEkMismatch;
  }

  if (CompareMem (ActualEk, ExpectedEk->PublicKey, ActualEkSize) != 0) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] EK content mismatch\n"));
    DEBUG ((DEBUG_ERROR, "[TPM-KS] This system is not authorized\n"));
    return TpmKillSwitchEkMismatch;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] EK validation PASSED\n"));
  return TpmKillSwitchSuccess;
}

/**
  Check TPM monotonic counter for expiry.

  @param[in]  ExpiryValue  Counter value that triggers expiry.

  @retval TPM_KILL_SWITCH_RESULT  Check result.
**/
TPM_KILL_SWITCH_RESULT
EFIAPI
CheckTpmMonotonicCounter (
  IN UINT64  ExpiryValue
  )
{
  EFI_STATUS  Status;
  UINT64      CurrentCounter;

  if (mTcg2Protocol == NULL) {
    DEBUG ((DEBUG_WARN, "[TPM-KS] No TPM available\n"));
    return TpmKillSwitchNoTpm;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] Checking TPM monotonic counter...\n"));

  //
  // Read monotonic counter (simplified - actual implementation would use TPM2_NV_Read)
  //
  Status = Tpm2NvReadCounter (&CurrentCounter);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] Failed to read counter: %r\n", Status));
    return TpmKillSwitchError;
  }

  DEBUG ((
    DEBUG_INFO,
    "[TPM-KS] Counter: %ld / %ld\n",
    CurrentCounter,
    ExpiryValue
    ));

  //
  // Check expiry
  //
  if (CurrentCounter >= ExpiryValue) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] Counter expired: %ld >= %ld\n", CurrentCounter, ExpiryValue));
    return TpmKillSwitchCounterExpired;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] Counter check PASSED\n"));
  return TpmKillSwitchSuccess;
}

/**
  Validate signed timestamp from remote server.

  @param[in]  Timestamp  Unix timestamp to validate.
  @param[in]  Signature  Signature over timestamp.
  @param[in]  SigSize    Signature size.

  @retval TPM_KILL_SWITCH_RESULT  Validation result.
**/
TPM_KILL_SWITCH_RESULT
EFIAPI
ValidateSignedTimestamp (
  IN UINT64  Timestamp,
  IN UINT8   *Signature,
  IN UINT32  SigSize
  )
{
  BOOLEAN  Valid;
  UINT64   CurrentTime;
  UINT8    PublicKey[256];  // Server's public key
  UINT32   PublicKeySize;

  if (Signature == NULL || SigSize == 0) {
    DEBUG ((DEBUG_WARN, "[TPM-KS] No signature provided, skipping validation\n"));
    return TpmKillSwitchSuccess;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] Validating signed timestamp...\n"));

  //
  // Get current time (simplified - would use EFI_TIME in production)
  //
  CurrentTime = 1704067200;  // 2024-01-01 00:00:00 UTC (example)

  //
  // Check if timestamp is in the future (replay attack)
  //
  if (Timestamp > CurrentTime + 300) {  // 5 minute tolerance
    DEBUG ((DEBUG_ERROR, "[TPM-KS] Timestamp is in the future\n"));
    return TpmKillSwitchError;
  }

  //
  // Check if timestamp is expired
  //
  if (Timestamp < CurrentTime - 86400) {  // 24 hour expiry
    DEBUG ((DEBUG_ERROR, "[TPM-KS] Timestamp expired\n"));
    return TpmKillSwitchCounterExpired;
  }

  //
  // Load server's public key (in production, from secure storage)
  //
  PublicKeySize = sizeof (PublicKey);
  CopyMem (PublicKey, AEGIS_SERVER_PUBLIC_KEY, AEGIS_SERVER_PUBLIC_KEY_SIZE);

  //
  // Verify signature using RSA-SHA256
  //
  Valid = RsaVerify (
            PublicKey,
            PublicKeySize,
            (UINT8 *)&Timestamp,
            sizeof (Timestamp),
            Signature,
            SigSize
            );

  if (!Valid) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] Signature verification failed\n"));
    return TpmKillSwitchError;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] Timestamp validation PASSED\n"));
  return TpmKillSwitchSuccess;
}

/**
  Log TPM kill-switch status.

  @param[in]  Result  Kill-switch validation result.
**/
VOID
EFIAPI
LogTpmKillSwitchStatus (
  IN TPM_KILL_SWITCH_RESULT  Result
  )
{
  CHAR8  *ResultString;

  switch (Result) {
    case TpmKillSwitchSuccess:
      ResultString = "SUCCESS";
      break;
    case TpmKillSwitchNoTpm:
      ResultString = "NO_TPM";
      break;
    case TpmKillSwitchEkMismatch:
      ResultString = "EK_MISMATCH";
      break;
    case TpmKillSwitchCounterExpired:
      ResultString = "COUNTER_EXPIRED";
      break;
    case TpmKillSwitchError:
      ResultString = "ERROR";
      break;
    default:
      ResultString = "UNKNOWN";
      break;
  }

  DEBUG ((DEBUG_INFO, "[TPM-KS] Status: %a\n", ResultString));

  //
  // Log to telemetry
  //
  if (Result != TpmKillSwitchSuccess) {
    DEBUG ((DEBUG_ERROR, "[TPM-KS] KILL-SWITCH TRIGGERED: %a\n", ResultString));
  }
}

/**
  Stub implementation of Tpm2ReadPublic for compilation.
  In production, this would use the actual TPM2 command.
**/
EFI_STATUS
EFIAPI
Tpm2ReadPublic (
  IN  UINT32  Handle,
  OUT UINT8   *PublicArea,
  OUT UINT32  *PublicAreaSize
  )
{
  //
  // Stub implementation - return simulated EK
  //
  if (PublicArea == NULL || PublicAreaSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *PublicAreaSize = 32;  // Simulated size
  SetMem (PublicArea, *PublicAreaSize, 0xBB);  // Simulated data

  return EFI_SUCCESS;
}

/**
  Stub implementation of Tpm2NvReadCounter for compilation.
  In production, this would use the actual TPM2 NV read command.
**/
EFI_STATUS
EFIAPI
Tpm2NvReadCounter (
  OUT UINT64  *Counter
  )
{
  if (Counter == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Stub implementation - return simulated counter
  //
  *Counter = 12345;  // Simulated value

  return EFI_SUCCESS;
}

/**
  Stub implementation of RsaVerify for compilation.
  In production, this would use BaseCryptLib's actual RSA verification.
**/
BOOLEAN
EFIAPI
RsaVerify (
  IN UINT8   *PublicKey,
  IN UINT32  PublicKeySize,
  IN UINT8   *Message,
  IN UINT32  MessageSize,
  IN UINT8   *Signature,
  IN UINT32  SignatureSize
  )
{
#ifdef AEGIS_STUB_CRYPTO
  //
  // CRITICAL SECURITY WARNING: Stub implementation for testing only
  // This MUST be replaced with actual cryptographic verification in production
  //
  DEBUG ((DEBUG_ERROR, "[TPM-KS] WARNING: Using stub RSA verification - NOT SECURE!\n"));
  DEBUG ((DEBUG_ERROR, "[TPM-KS] This build is for testing only and MUST NOT be deployed\n"));
  return TRUE;
#else
  //
  // Fail-closed: Without proper crypto implementation, reject all signatures
  //
  DEBUG ((DEBUG_ERROR, "[TPM-KS] RSA verification not implemented - signature rejected\n"));
  return FALSE;
#endif
}

// Made with Bob
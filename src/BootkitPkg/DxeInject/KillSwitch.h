/** @file
  Kill-Switch Implementation Header

  Defines hardware-rooted security mechanisms that prevent unauthorized
  execution of the bootkit emulation outside controlled research environments.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __KILL_SWITCH_H__
#define __KILL_SWITCH_H__

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Protocol/Smbios.h>
#include <Protocol/Tcg2Protocol.h>

//
// Kill-switch validation results
//
typedef enum {
  KillSwitchSuccess = 0,
  KillSwitchUuidMismatch,
  KillSwitchTpmMismatch,
  KillSwitchExpired,
  KillSwitchError
} KILL_SWITCH_RESULT;

/**
  Validate all kill-switch mechanisms.

  This function checks:
  1. SMBIOS UUID matches allowed value
  2. TPM Endorsement Key matches allowed value
  3. Current date is before expiry date

  @retval KillSwitchSuccess      All validations passed.
  @retval KillSwitchUuidMismatch UUID does not match allowed value.
  @retval KillSwitchTpmMismatch  TPM EK does not match allowed value.
  @retval KillSwitchExpired      Current date is past expiry date.
  @retval KillSwitchError        Error occurred during validation.

**/
KILL_SWITCH_RESULT
ValidateKillSwitches (
  VOID
  );

/**
  Validate SMBIOS UUID against allowed value.

  @retval TRUE   UUID matches allowed value.
  @retval FALSE  UUID does not match or error occurred.

**/
BOOLEAN
ValidateUuid (
  VOID
  );

/**
  Validate TPM Endorsement Key against allowed value.

  @retval TRUE   TPM EK matches allowed value.
  @retval FALSE  TPM EK does not match or error occurred.

**/
BOOLEAN
ValidateTpmEk (
  VOID
  );

/**
  Validate that current date is before expiry date.

  @retval TRUE   Current date is before expiry.
  @retval FALSE  Current date is past expiry or error occurred.

**/
BOOLEAN
ValidateExpiry (
  VOID
  );

/**
  Get SMBIOS UUID string.

  @param[out]  UuidString  Buffer to receive UUID string.
  @param[in]   BufferSize  Size of buffer in bytes.

  @retval EFI_SUCCESS      UUID retrieved successfully.
  @retval EFI_NOT_FOUND    SMBIOS table not found.
  @retval Other            Error occurred.

**/
EFI_STATUS
GetSmbiosUuid (
  OUT CHAR8   *UuidString,
  IN  UINTN   BufferSize
  );

/**
  Get TPM Endorsement Key hash.

  @param[out]  EkHash      Buffer to receive EK hash.
  @param[in]   HashSize    Size of hash buffer.

  @retval EFI_SUCCESS      EK hash retrieved successfully.
  @retval EFI_NOT_FOUND    TPM not found or EK not available.
  @retval Other            Error occurred.

**/
EFI_STATUS
GetTpmEkHash (
  OUT UINT8   *EkHash,
  IN  UINTN   HashSize
  );

/**
  Parse date string in YYYY-MM-DD format.

  @param[in]   DateString  Date string to parse.
  @param[out]  Year        Parsed year.
  @param[out]  Month       Parsed month.
  @param[out]  Day         Parsed day.

  @retval TRUE   Date parsed successfully.
  @retval FALSE  Invalid date format.

**/
BOOLEAN
ParseDateString (
  IN  CONST CHAR8  *DateString,
  OUT UINT16       *Year,
  OUT UINT8        *Month,
  OUT UINT8        *Day
  );

/**
  Compare two dates.

  @param[in]  Year1   First date year.
  @param[in]  Month1  First date month.
  @param[in]  Day1    First date day.
  @param[in]  Year2   Second date year.
  @param[in]  Month2  Second date month.
  @param[in]  Day2    Second date day.

  @retval  < 0  First date is before second date.
  @retval  = 0  Dates are equal.
  @retval  > 0  First date is after second date.

**/
INTN
CompareDates (
  IN UINT16  Year1,
  IN UINT8   Month1,
  IN UINT8   Day1,
  IN UINT16  Year2,
  IN UINT8   Month2,
  IN UINT8   Day2
  );

#endif // __KILL_SWITCH_H__

// Made with Bob

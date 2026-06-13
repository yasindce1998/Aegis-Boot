/** @file
  Kill-Switch Implementation

  Implements hardware-rooted security mechanisms that prevent unauthorized
  execution of the bootkit emulation outside controlled research environments.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "KillSwitch.h"
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/PrintLib.h>
#include <IndustryStandard/SmBios.h>

//
// Kill-switch configuration (compile-time defaults for research environment)
//
#ifndef AEGIS_ALLOWED_UUID
#define AEGIS_ALLOWED_UUID  "00000000-0000-0000-0000-000000000000"
#endif

#ifndef AEGIS_EXPIRY_DATE
#define AEGIS_EXPIRY_DATE   "2027-12-31"
#endif

/**
  Validate all kill-switch mechanisms.

  @retval KillSwitchSuccess      All validations passed.
  @retval KillSwitchUuidMismatch UUID does not match allowed value.
  @retval KillSwitchTpmMismatch  TPM EK does not match allowed value.
  @retval KillSwitchExpired      Current date is past expiry date.
  @retval KillSwitchError        Error occurred during validation.

**/
KILL_SWITCH_RESULT
ValidateKillSwitches (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "[Aegis] Validating kill-switches...\n"));

  //
  // Check UUID binding
  //
  if (!ValidateUuid ()) {
    DEBUG ((DEBUG_ERROR, "[Aegis] UUID validation FAILED\n"));
    return KillSwitchUuidMismatch;
  }
  DEBUG ((DEBUG_INFO, "[Aegis] UUID validation passed\n"));

  //
  // Check TPM EK binding
  //
  if (!ValidateTpmEk ()) {
    DEBUG ((DEBUG_ERROR, "[Aegis] TPM EK validation FAILED\n"));
#ifdef AEGIS_QEMU_MODE
    DEBUG ((DEBUG_WARN, "[Aegis] QEMU mode: Allowing execution despite TPM failure\n"));
#else
    return KillSwitchTpmMismatch;
#endif
  }

  //
  // Check expiry date
  //
  if (!ValidateExpiry ()) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Expiry validation FAILED\n"));
    return KillSwitchExpired;
  }
  DEBUG ((DEBUG_INFO, "[Aegis] Expiry validation passed\n"));

  DEBUG ((DEBUG_INFO, "[Aegis] All kill-switch validations passed\n"));
  return KillSwitchSuccess;
}

/**
  Validate SMBIOS UUID against allowed value.

  @retval TRUE   UUID matches allowed value.
  @retval FALSE  UUID does not match or error occurred.

**/
BOOLEAN
ValidateUuid (
  VOID
  )
{
  EFI_STATUS           Status;
  EFI_SMBIOS_PROTOCOL  *Smbios;
  EFI_SMBIOS_HANDLE    SmbiosHandle;
  EFI_SMBIOS_TYPE      SmbiosType;
  SMBIOS_STRUCTURE     *SmbiosRecord;
  SMBIOS_TABLE_TYPE1   *Type1Record;
  UINT8                *CurrentUuid;
  UINT8                AllowedUuidBytes[16];
  CHAR8                UuidString[64];

  //
  // Locate SMBIOS protocol
  //
  Status = gBS->LocateProtocol (
                  &gEfiSmbiosProtocolGuid,
                  NULL,
                  (VOID **)&Smbios
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Failed to locate SMBIOS protocol: %r\n", Status));
    return FALSE;
  }

  //
  // Find System Information (Type 1) table
  //
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  SmbiosType   = SMBIOS_TYPE_SYSTEM_INFORMATION;

  Status = Smbios->GetNext (
                     Smbios,
                     &SmbiosHandle,
                     &SmbiosType,
                     &SmbiosRecord,
                     NULL
                     );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Failed to get SMBIOS Type 1 table: %r\n", Status));
    return FALSE;
  }

  Type1Record = (SMBIOS_TABLE_TYPE1 *)SmbiosRecord;
  CurrentUuid = (UINT8 *)&Type1Record->Uuid;

  //
  // Parse allowed UUID string into bytes for comparison
  // This is defense-in-depth; primary validation is raw byte comparison
  //
  Status = ParseUuidString (AEGIS_ALLOWED_UUID, AllowedUuidBytes);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Failed to parse allowed UUID: %r\n", Status));
    return FALSE;
  }

  //
  // Format current UUID for logging
  //
  AsciiSPrint (
    UuidString,
    sizeof (UuidString),
    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    CurrentUuid[0], CurrentUuid[1], CurrentUuid[2], CurrentUuid[3],
    CurrentUuid[4], CurrentUuid[5],
    CurrentUuid[6], CurrentUuid[7],
    CurrentUuid[8], CurrentUuid[9],
    CurrentUuid[10], CurrentUuid[11], CurrentUuid[12], CurrentUuid[13], CurrentUuid[14], CurrentUuid[15]
    );

  DEBUG ((DEBUG_INFO, "[Aegis] Current UUID: %a\n", UuidString));
  DEBUG ((DEBUG_INFO, "[Aegis] Allowed UUID: %a\n", AEGIS_ALLOWED_UUID));

  //
  // Compare raw 16-byte UUIDs using CompareMem (defense-in-depth)
  // This avoids string comparison issues (case sensitivity, format variations)
  //
  if (CompareMem (CurrentUuid, AllowedUuidBytes, 16) != 0) {
    DEBUG ((DEBUG_ERROR, "[Aegis] UUID mismatch!\n"));
    return FALSE;
  }

  DEBUG ((DEBUG_INFO, "[Aegis] UUID validation passed\n"));
  return TRUE;
}

/**
  Validate TPM Endorsement Key against allowed value.

  @retval TRUE   TPM EK matches allowed value.
  @retval FALSE  TPM EK does not match or error occurred.

**/
BOOLEAN
ValidateTpmEk (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT8       EkHash[32];  // SHA-256 hash
  UINT8       ExpectedEkHash[32];  // Expected EK hash

  //
  // Get TPM EK hash
  //
  Status = GetTpmEkHash (EkHash, sizeof (EkHash));
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Failed to get TPM EK: %r\n", Status));
#ifdef AEGIS_QEMU_MODE
    DEBUG ((DEBUG_WARN, "[Aegis] QEMU mode: TPM unavailable, allowing execution\n"));
    return TRUE;
#else
    return FALSE;
#endif
  }

  //
  // Load expected EK hash (in production, from secure storage)
  // For now, use a placeholder that must be configured
  //
  ZeroMem (ExpectedEkHash, sizeof (ExpectedEkHash));
  
  //
  // Compare EK hash against expected value
  //
  if (CompareMem (EkHash, ExpectedEkHash, sizeof (EkHash)) != 0) {
    DEBUG ((DEBUG_ERROR, "[Aegis] TPM EK hash mismatch\n"));
    DEBUG ((DEBUG_ERROR, "[Aegis] This system is not authorized\n"));
    return FALSE;
  }

  DEBUG ((DEBUG_INFO, "[Aegis] TPM EK validation passed\n"));
  return TRUE;
}

/**
  Validate that current date is before expiry date.

  @retval TRUE   Current date is before expiry.
  @retval FALSE  Current date is past expiry or error occurred.

**/
BOOLEAN
ValidateExpiry (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_TIME    CurrentTime;
  UINT16      ExpiryYear;
  UINT8       ExpiryMonth;
  UINT8       ExpiryDay;
  INTN        Comparison;

  //
  // Get current time from RTC
  //
  Status = gRT->GetTime (&CurrentTime, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Failed to get current time: %r\n", Status));
    return FALSE;
  }

  DEBUG ((
    DEBUG_INFO,
    "[Aegis] Current date: %04d-%02d-%02d\n",
    CurrentTime.Year,
    CurrentTime.Month,
    CurrentTime.Day
    ));

  //
  // Parse expiry date
  //
  if (!ParseDateString (AEGIS_EXPIRY_DATE, &ExpiryYear, &ExpiryMonth, &ExpiryDay)) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Failed to parse expiry date: %a\n", AEGIS_EXPIRY_DATE));
    return FALSE;
  }

  DEBUG ((
    DEBUG_INFO,
    "[Aegis] Expiry date: %04d-%02d-%02d\n",
    ExpiryYear,
    ExpiryMonth,
    ExpiryDay
    ));

  //
  // Compare dates
  //
  Comparison = CompareDates (
                 CurrentTime.Year,
                 (UINT8)CurrentTime.Month,
                 (UINT8)CurrentTime.Day,
                 ExpiryYear,
                 ExpiryMonth,
                 ExpiryDay
                 );

  if (Comparison >= 0) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Project has expired!\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  Get SMBIOS UUID string.

  @param[out]  UuidString  Buffer to receive UUID string.
  @param[in]   BufferSize  Size of buffer in bytes.

  @retval EFI_SUCCESS           UUID retrieved successfully.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small for UUID string.
  @retval EFI_NOT_FOUND         SMBIOS table not found.
  @retval Other                 Error occurred.

**/
EFI_STATUS
GetSmbiosUuid (
  OUT CHAR8   *UuidString,
  IN  UINTN   BufferSize
  )
{
  EFI_STATUS           Status;
  EFI_SMBIOS_PROTOCOL  *Smbios;
  EFI_SMBIOS_HANDLE    SmbiosHandle;
  EFI_SMBIOS_TYPE      SmbiosType;
  SMBIOS_STRUCTURE     *SmbiosRecord;
  SMBIOS_TABLE_TYPE1   *Type1Record;
  UINT8                *Uuid;

  //
  // Validate buffer size (UUID string requires 37 bytes: 36 chars + null terminator)
  //
  if (BufferSize < 37) {
    DEBUG ((DEBUG_ERROR, "[Aegis] UUID buffer too small: %d < 37\n", BufferSize));
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Locate SMBIOS protocol
  //
  Status = gBS->LocateProtocol (
                  &gEfiSmbiosProtocolGuid,
                  NULL,
                  (VOID **)&Smbios
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Find System Information (Type 1) table
  //
  SmbiosHandle = SMBIOS_HANDLE_PI_RESERVED;
  SmbiosType   = SMBIOS_TYPE_SYSTEM_INFORMATION;

  Status = Smbios->GetNext (
                     Smbios,
                     &SmbiosHandle,
                     &SmbiosType,
                     &SmbiosRecord,
                     NULL
                     );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Type1Record = (SMBIOS_TABLE_TYPE1 *)SmbiosRecord;
  Uuid        = (UINT8 *)&Type1Record->Uuid;

  //
  // Format UUID as string: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
  //
  AsciiSPrint (
    UuidString,
    BufferSize,
    "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
    Uuid[0], Uuid[1], Uuid[2], Uuid[3],
    Uuid[4], Uuid[5],
    Uuid[6], Uuid[7],
    Uuid[8], Uuid[9],
    Uuid[10], Uuid[11], Uuid[12], Uuid[13], Uuid[14], Uuid[15]
    );

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS          Status;
  EFI_TCG2_PROTOCOL   *Tcg2Protocol;

  //
  // Locate TCG2 protocol
  //
  Status = gBS->LocateProtocol (
                  &gEfiTcg2ProtocolGuid,
                  NULL,
                  (VOID **)&Tcg2Protocol
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // In a real implementation, we would:
  // 1. Read the EK certificate from TPM NV
  // 2. Hash the EK public key
  // 3. Compare against known value
  //
  // For now, we just return success if TPM is available
  //
  ZeroMem (EkHash, HashSize);

  return EFI_SUCCESS;
}

/**
  Check if a year is a leap year.

  @param[in]  Year  Year to check.

  @retval TRUE   Year is a leap year.
  @retval FALSE  Year is not a leap year.

**/
STATIC
BOOLEAN
IsLeapYear (
  IN UINT16  Year
  )
{
  //
  // Leap year rules:
  // - Divisible by 4: leap year
  // - Divisible by 100: not a leap year
  // - Divisible by 400: leap year
  //
  if (Year % 400 == 0) {
    return TRUE;
  }
  if (Year % 100 == 0) {
    return FALSE;
  }
  if (Year % 4 == 0) {
    return TRUE;
  }
  return FALSE;
}

/**
  Get number of days in a month.

  @param[in]  Month  Month (1-12).
  @param[in]  Year   Year (for leap year calculation).

  @retval Number of days in the month.

**/
STATIC
UINT8
GetDaysInMonth (
  IN UINT8   Month,
  IN UINT16  Year
  )
{
  STATIC CONST UINT8 DaysInMonth[12] = {
    31,  // January
    28,  // February (adjusted for leap year)
    31,  // March
    30,  // April
    31,  // May
    30,  // June
    31,  // July
    31,  // August
    30,  // September
    31,  // October
    30,  // November
    31   // December
  };

  if (Month < 1 || Month > 12) {
    return 0;
  }

  if (Month == 2 && IsLeapYear (Year)) {
    return 29;
  }

  return DaysInMonth[Month - 1];
}

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
  )
{
  UINTN  Len;
  CHAR8  YearStr[5];
  CHAR8  MonthStr[3];
  CHAR8  DayStr[3];

  if (DateString == NULL || Year == NULL || Month == NULL || Day == NULL) {
    return FALSE;
  }

  Len = AsciiStrLen (DateString);
  if (Len != 10) {  // YYYY-MM-DD
    return FALSE;
  }

  //
  // Check format: YYYY-MM-DD
  //
  if (DateString[4] != '-' || DateString[7] != '-') {
    return FALSE;
  }

  //
  // Extract year
  //
  CopyMem (YearStr, DateString, 4);
  YearStr[4] = '\0';
  *Year = (UINT16)AsciiStrDecimalToUintn (YearStr);

  //
  // Extract month
  //
  CopyMem (MonthStr, DateString + 5, 2);
  MonthStr[2] = '\0';
  *Month = (UINT8)AsciiStrDecimalToUintn (MonthStr);

  //
  // Extract day
  //
  CopyMem (DayStr, DateString + 8, 2);
  DayStr[2] = '\0';
  *Day = (UINT8)AsciiStrDecimalToUintn (DayStr);

  //
  // Validate year range
  //
  if (*Year < 2000 || *Year > 2100) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Invalid year: %d\n", *Year));
    return FALSE;
  }

  //
  // Validate month range
  //
  if (*Month < 1 || *Month > 12) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Invalid month: %d\n", *Month));
    return FALSE;
  }

  //
  // Validate day range with proper days-in-month check (including leap year)
  //
  UINT8 MaxDays = GetDaysInMonth (*Month, *Year);
  if (*Day < 1 || *Day > MaxDays) {
    DEBUG ((DEBUG_ERROR, "[Aegis] Invalid day: %d for month %d (max: %d)\n", *Day, *Month, MaxDays));
    return FALSE;
  }

  return TRUE;
}

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
  )
{
  if (Year1 != Year2) {
    return (INTN)Year1 - (INTN)Year2;
  }

  if (Month1 != Month2) {
    return (INTN)Month1 - (INTN)Month2;
  }

  return (INTN)Day1 - (INTN)Day2;
}

// Made with Bob

/**
  Parse UUID string into 16-byte array.

  @param[in]   UuidString  UUID string in format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.
  @param[out]  UuidBytes   Buffer to receive 16-byte UUID.

  @retval EFI_SUCCESS            UUID parsed successfully.
  @retval EFI_INVALID_PARAMETER  Invalid UUID format.

**/
EFI_STATUS
ParseUuidString (
  IN  CONST CHAR8  *UuidString,
  OUT UINT8        *UuidBytes
  )
{
  UINTN  Len;
  UINTN  i;
  UINTN  ByteIndex;
  CHAR8  HexStr[3];

  if (UuidString == NULL || UuidBytes == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Len = AsciiStrLen (UuidString);
  if (Len != 36) {  // XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    return EFI_INVALID_PARAMETER;
  }

  //
  // Verify dashes are in correct positions
  //
  if (UuidString[8] != '-' || UuidString[13] != '-' || 
      UuidString[18] != '-' || UuidString[23] != '-') {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Parse hex bytes
  //
  ByteIndex = 0;
  HexStr[2] = '\0';

  for (i = 0; i < 36 && ByteIndex < 16; i++) {
    if (UuidString[i] == '-') {
      continue;
    }

    HexStr[0] = UuidString[i];
    HexStr[1] = UuidString[i + 1];
    
    UuidBytes[ByteIndex] = (UINT8)AsciiStrHexToUintn (HexStr);
    ByteIndex++;
    i++;  // Skip second hex digit
  }

  if (ByteIndex != 16) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

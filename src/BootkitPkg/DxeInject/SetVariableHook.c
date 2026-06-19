/** @file
  SetVariable Hook Implementation

  Implements SetVariable interception for Secure Boot tampering detection.
  Models BlackLotus TTP for Secure Boot bypass (CVE-2023-24932).

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SetVariableHook.h"
#include "DxeInject.h"

//
// Original SetVariable function pointer
//
EFI_SET_VARIABLE mOriginalSetVariable = NULL;

/**
  Check if variable is Secure Boot related.

  @param[in]  VariableName  Variable name.
  @param[in]  VendorGuid    Vendor GUID.

  @retval TRUE   Variable is Secure Boot related.
  @retval FALSE  Variable is not Secure Boot related.

**/
STATIC
BOOLEAN
IsSecureBootVariable (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid
  )
{
  //
  // Check for Secure Boot variables
  //
  if (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid)) {
    if (StrCmp (VariableName, L"SecureBoot") == 0 ||
        StrCmp (VariableName, L"SetupMode") == 0 ||
        StrCmp (VariableName, L"PK") == 0 ||
        StrCmp (VariableName, L"KEK") == 0) {
      return TRUE;
    }
  }

  if (CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid)) {
    if (StrCmp (VariableName, L"db") == 0 ||
        StrCmp (VariableName, L"dbx") == 0 ||
        StrCmp (VariableName, L"dbt") == 0 ||
        StrCmp (VariableName, L"dbr") == 0) {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Hooked SetVariable function.

  @param[in]  VariableName  Name of variable.
  @param[in]  VendorGuid    GUID of variable.
  @param[in]  Attributes    Variable attributes.
  @param[in]  DataSize      Size of data.
  @param[in]  Data          Variable data.

  @retval EFI_SUCCESS      Variable set successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
EFIAPI
HookedSetVariable (
  IN  CHAR16    *VariableName,
  IN  EFI_GUID  *VendorGuid,
  IN  UINT32    Attributes,
  IN  UINTN     DataSize,
  IN  VOID      *Data
  )
{
  EFI_STATUS  Status;
  BOOLEAN     IsSecureBoot;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[SetVariable Hook] INTERCEPTED\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[SetVariable] Variable: %s\n", VariableName));
  DEBUG ((DEBUG_INFO, "[SetVariable] DataSize: %lu bytes\n", (UINT64)DataSize));
  DEBUG ((DEBUG_INFO, "[SetVariable] Attributes: 0x%08x\n", Attributes));

  //
  // Check if this is a Secure Boot variable
  //
  IsSecureBoot = IsSecureBootVariable (VariableName, VendorGuid);

  if (IsSecureBoot) {
    DEBUG ((DEBUG_WARN, "[SetVariable] ⚠ SECURE BOOT VARIABLE MODIFICATION DETECTED!\n"));
    DEBUG ((DEBUG_WARN, "[SetVariable]   Variable: %s\n", VariableName));
    DEBUG ((DEBUG_WARN, "[SetVariable]   This is a HIGH-SEVERITY security event\n"));

    //
    // Log telemetry for detection research
    //
    LogTelemetry (L"SetVariable: Secure Boot tampering attempt detected");

    //
    // In a real bootkit (e.g., BlackLotus CVE-2023-24932), this would:
    // 1. Disable Secure Boot by setting SecureBoot=0
    // 2. Modify PK (Platform Key) to gain control
    // 3. Add malicious certificates to db (authorized database)
    // 4. Remove security signatures from dbx (forbidden database)
    // 5. Enter Setup Mode to bypass protections
    //
    DEBUG ((DEBUG_WARN, "[SetVariable] In production bootkit, would:\n"));
    DEBUG ((DEBUG_WARN, "[SetVariable]   1. Disable Secure Boot enforcement\n"));
    DEBUG ((DEBUG_WARN, "[SetVariable]   2. Modify Platform Key (PK) ownership\n"));
    DEBUG ((DEBUG_WARN, "[SetVariable]   3. Add malicious cert to authorized db\n"));
    DEBUG ((DEBUG_WARN, "[SetVariable]   4. Remove revocations from dbx\n"));
    DEBUG ((DEBUG_WARN, "[SetVariable]   5. Force system into Setup Mode\n"));

    //
    // Analyze the modification
    //
    if (StrCmp (VariableName, L"SecureBoot") == 0) {
      if (DataSize == sizeof(UINT8) && Data != NULL) {
        UINT8 Value = *(UINT8 *)Data;
        DEBUG ((DEBUG_WARN, "[SetVariable]   SecureBoot value: %d (0=Disabled, 1=Enabled)\n", Value));
        if (Value == 0) {
          DEBUG ((DEBUG_ERROR, "[SetVariable]   ⚠⚠⚠ ATTEMPTING TO DISABLE SECURE BOOT!\n"));
        }
      }
    }

    if (StrCmp (VariableName, L"PK") == 0) {
      DEBUG ((DEBUG_WARN, "[SetVariable]   Platform Key modification detected\n"));
      if (DataSize == 0) {
        DEBUG ((DEBUG_ERROR, "[SetVariable]   ⚠⚠⚠ ATTEMPTING TO DELETE PLATFORM KEY!\n"));
        DEBUG ((DEBUG_ERROR, "[SetVariable]   This would enter Setup Mode and disable Secure Boot\n"));
      }
    }

    if (StrCmp (VariableName, L"db") == 0 || StrCmp (VariableName, L"dbx") == 0) {
      DEBUG ((DEBUG_WARN, "[SetVariable]   Signature database modification detected\n"));
      DEBUG ((DEBUG_WARN, "[SetVariable]   Database: %s\n", VariableName));
      DEBUG ((DEBUG_WARN, "[SetVariable]   Size: %lu bytes\n", (UINT64)DataSize));
    }
  }

  //
  // Log all variable modifications for research
  //
  LogTelemetry (L"SetVariable hook triggered");

  //
  // Call original SetVariable
  //
  DEBUG ((DEBUG_INFO, "[SetVariable] Calling original SetVariable...\n"));
  Status = mOriginalSetVariable (
             VariableName,
             VendorGuid,
             Attributes,
             DataSize,
             Data
             );

  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[SetVariable] ✓ Variable set successfully\n"));
    if (IsSecureBoot) {
      DEBUG ((DEBUG_WARN, "[SetVariable] ⚠ Secure Boot variable was modified!\n"));
    }
  } else {
    DEBUG ((DEBUG_ERROR, "[SetVariable] ✗ Variable set failed: %r\n", Status));
  }

  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));

  return Status;
}

/**
  Install SetVariable hook.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
InstallSetVariableHook (
  VOID
  )
{
  if (mOriginalSetVariable != NULL) {
    DEBUG ((DEBUG_WARN, "[SetVariable] Hook already installed\n"));
    return EFI_ALREADY_STARTED;
  }

  //
  // Save original SetVariable pointer
  //
  mOriginalSetVariable = gRT->SetVariable;

  //
  // Install hook
  //
  gRT->SetVariable = HookedSetVariable;

  DEBUG ((DEBUG_INFO, "[SetVariable] Hook installed successfully\n"));
  DEBUG ((DEBUG_INFO, "[SetVariable]   Original: 0x%p\n", mOriginalSetVariable));
  DEBUG ((DEBUG_INFO, "[SetVariable]   Hooked: 0x%p\n", HookedSetVariable));

  LogTelemetry (L"SetVariable hook installed");

  return EFI_SUCCESS;
}


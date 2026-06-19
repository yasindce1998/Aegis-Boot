/** @file
  SetVariable Hook Header

  Provides SetVariable interception for Secure Boot tampering detection.
  For academic research purposes only.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SET_VARIABLE_HOOK_H__
#define __SET_VARIABLE_HOOK_H__

#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>

//
// Original SetVariable function pointer
//
extern EFI_SET_VARIABLE mOriginalSetVariable;

/**
  Hooked SetVariable function.

  Intercepts UEFI variable modifications to detect Secure Boot tampering.
  In real bootkits (e.g., BlackLotus), this would disable Secure Boot
  or modify key databases.

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
  );

/**
  Install SetVariable hook.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
InstallSetVariableHook (
  VOID
  );

#endif // __SET_VARIABLE_HOOK_H__


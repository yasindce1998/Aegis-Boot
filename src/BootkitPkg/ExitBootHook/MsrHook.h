/** @file
  MSR Hooking Module - Model Specific Register Manipulation

  Implements MSR hooking to redirect kernel syscall entry points,
  replicating CosmicStrand bootkit techniques for research purposes.

  Target MSRs:
  - IA32_LSTAR (0xC0000082): Syscall entry point (x86_64)
  - IA32_CSTAR (0xC0000083): Compatibility mode syscall
  - IA32_SYSENTER_EIP (0x176): Legacy sysenter entry

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MSR_HOOK_H__
#define __MSR_HOOK_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>

//
// MSR Definitions
//
#define IA32_LSTAR           0xC0000082  // Syscall entry (64-bit)
#define IA32_CSTAR           0xC0000083  // Syscall entry (compat)
#define IA32_STAR            0xC0000081  // Syscall target address
#define IA32_FMASK           0xC0000084  // Syscall flag mask
#define IA32_SYSENTER_CS     0x174       // Sysenter CS
#define IA32_SYSENTER_ESP    0x175       // Sysenter ESP
#define IA32_SYSENTER_EIP    0x176       // Sysenter EIP

//
// Hook context structure
//
typedef struct {
  UINT64    OriginalLstar;
  UINT64    OriginalCstar;
  UINT64    OriginalSysenterEip;
  UINT64    HookAddress;
  BOOLEAN   HooksInstalled;
  UINT32    HookCount;
} MSR_HOOK_CONTEXT;

/**
  Read a Model Specific Register.

  @param[in]  Msr  MSR index to read.

  @retval Value of the MSR.
**/
UINT64
EFIAPI
ReadMsr (
  IN UINT32  Msr
  );

/**
  Write a Model Specific Register.

  @param[in]  Msr    MSR index to write.
  @param[in]  Value  Value to write.

  @retval EFI_SUCCESS  MSR written successfully.
**/
EFI_STATUS
EFIAPI
WriteMsr (
  IN UINT32  Msr,
  IN UINT64  Value
  );

/**
  Install MSR hooks to redirect kernel syscall entry points.

  @param[in,out]  Context  Pointer to MSR hook context.

  @retval EFI_SUCCESS           Hooks installed successfully.
  @retval EFI_INVALID_PARAMETER Context is NULL.
  @retval EFI_ALREADY_STARTED   Hooks already installed.
**/
EFI_STATUS
EFIAPI
InstallMsrHooks (
  IN OUT MSR_HOOK_CONTEXT  *Context
  );

/**
  Remove MSR hooks and restore original values.

  @param[in,out]  Context  Pointer to MSR hook context.

  @retval EFI_SUCCESS           Hooks removed successfully.
  @retval EFI_INVALID_PARAMETER Context is NULL.
  @retval EFI_NOT_STARTED       Hooks not installed.
**/
EFI_STATUS
EFIAPI
RemoveMsrHooks (
  IN OUT MSR_HOOK_CONTEXT  *Context
  );

/**
  Log current MSR values for analysis.

  @param[in]  Context  Pointer to MSR hook context.
**/
VOID
EFIAPI
LogMsrValues (
  IN MSR_HOOK_CONTEXT  *Context
  );

#endif // __MSR_HOOK_H__


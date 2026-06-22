/** @file
  Virtual Address Map Hook Emulation - Implementation

  Emulates CosmicStrand-style kernel patching via the SetVirtualAddressMap
  callback. Registers for EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, scans for the
  Windows kernel PE header in memory, identifies DSE patch targets, and
  simulates kernel memory patching during OS handoff.

  All operations are SIMULATED - no actual kernel modifications are performed.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "VirtualAddressMapHook.h"

STATIC VAM_HOOK_CONTEXT  mVamContext;

STATIC
VOID
EFIAPI
VamNotifyCallback (
  IN EFI_EVENT  Event,
  IN VOID       *CallbackContext
  )
{
  VAM_HOOK_CONTEXT  *Context;

  Context = (VAM_HOOK_CONTEXT *)CallbackContext;
  if (Context == NULL) {
    return;
  }

  Context->CallbackFired = TRUE;
  Context->State = VamStateCallbackFired;

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "*** SetVirtualAddressMap callback fired ***\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  OS is transitioning to virtual addressing\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Runtime services being relocated\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Window for kernel patching: NOW\n"));
}

EFI_STATUS
EFIAPI
InitializeVamHook (
  OUT VAM_HOOK_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (VAM_HOOK_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = VamStateUninitialized;

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RegisterVamCallback (
  IN OUT VAM_HOOK_CONTEXT  *Context
  )
{
  EFI_STATUS  Status;

  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Registering SetVirtualAddressMap callback...\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Event type: EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  TPL:        TPL_NOTIFY\n"));

  if (SIMULATION_MODE) {
    Context->EventRegistered = TRUE;
    Context->VamEvent = NULL;
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → Event registered [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → Callback will fire during ExitBootServices→SetVirtualAddressMap\n"));
  } else {
    Status = gBS->CreateEvent (
                    EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,
                    TPL_NOTIFY,
                    VamNotifyCallback,
                    Context,
                    &Context->VamEvent
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, VAM_DEBUG_PREFIX "  CreateEvent failed: %r\n", Status));
      return Status;
    }

    Context->EventRegistered = TRUE;
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → Event registered (live)\n"));
  }

  Context->State = VamStateEventRegistered;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateCallbackFire (
  IN OUT VAM_HOOK_CONTEXT  *Context
  )
{
  if (Context->State < VamStateEventRegistered) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Emulating callback trigger...\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Scenario: OS loader calls RT->SetVirtualAddressMap()\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Firmware signals EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE\n"));

  if (SIMULATION_MODE) {
    VamNotifyCallback (NULL, Context);
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → Callback invoked [SIMULATED]\n"));
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ScanForKernelImage (
  IN OUT VAM_HOOK_CONTEXT  *Context
  )
{
  if (Context->State < VamStateCallbackFired) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Scanning for kernel PE image...\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Search range: 0x%016lx - 0x%016lx\n",
          KERNEL_SEARCH_BASE, KERNEL_SEARCH_LIMIT));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Step size:    0x%x (page-aligned)\n", KERNEL_SEARCH_STEP));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Looking for:  MZ header → PE signature → AMD64 machine\n"));

  if (SIMULATION_MODE) {
    Context->KernelBase = 0xFFFFF8000C000000ULL;
    Context->KernelSize = 0x00C00000;
    Context->KernelFound = TRUE;
    Context->Machine = PE_MACHINE_AMD64;
    Context->TimeDateStamp = 0x614A4B5C;

    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → Kernel found [SIMULATED]:\n"));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "      Base:          0x%016lx\n", Context->KernelBase));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "      Size:          0x%x (%d MB)\n",
            Context->KernelSize, Context->KernelSize / (1024 * 1024)));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "      Machine:       0x%04x (AMD64)\n", Context->Machine));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "      TimeDateStamp: 0x%08x\n", Context->TimeDateStamp));
  }

  Context->State = VamStateKernelFound;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
PrepareKernelPatches (
  IN OUT VAM_HOOK_CONTEXT  *Context
  )
{
  if (Context->State < VamStateKernelFound) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Preparing kernel patch sites...\n"));

  // DSE bypass patch (ci!g_CiOptions)
  Context->PatchSites[0].Type = PatchTargetDse;
  Context->PatchSites[0].Address = Context->KernelBase + 0x003B1234ULL;
  Context->PatchSites[0].OriginalBytes[0] = 0x06;
  Context->PatchSites[0].OriginalSize = 1;
  Context->PatchSites[0].PatchBytes[0] = 0x00;
  Context->PatchSites[0].PatchSize = 1;
  Context->PatchSites[0].Applied = FALSE;

  // PatchGuard initialization skip
  Context->PatchSites[1].Type = PatchTargetPatchGuard;
  Context->PatchSites[1].Address = Context->KernelBase + 0x005A5678ULL;
  Context->PatchSites[1].OriginalBytes[0] = 0xE8;  // CALL
  Context->PatchSites[1].OriginalBytes[1] = 0x12;
  Context->PatchSites[1].OriginalBytes[2] = 0x34;
  Context->PatchSites[1].OriginalBytes[3] = 0x56;
  Context->PatchSites[1].OriginalBytes[4] = 0x78;
  Context->PatchSites[1].OriginalSize = 5;
  Context->PatchSites[1].PatchBytes[0] = 0x90;  // NOP sled
  Context->PatchSites[1].PatchBytes[1] = 0x90;
  Context->PatchSites[1].PatchBytes[2] = 0x90;
  Context->PatchSites[1].PatchBytes[3] = 0x90;
  Context->PatchSites[1].PatchBytes[4] = 0x90;
  Context->PatchSites[1].PatchSize = 5;
  Context->PatchSites[1].Applied = FALSE;

  Context->PatchCount = 2;

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Patch site 0: DSE bypass (ci!g_CiOptions)\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "    Address:  0x%016lx\n", Context->PatchSites[0].Address));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "    Original: 0x%02x (enforcement enabled)\n",
          Context->PatchSites[0].OriginalBytes[0]));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "    Patch:    0x%02x (enforcement disabled)\n",
          Context->PatchSites[0].PatchBytes[0]));

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Patch site 1: PatchGuard init skip\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "    Address:  0x%016lx\n", Context->PatchSites[1].Address));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "    Original: CALL rel32 (KiInitializePatchGuard)\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "    Patch:    5-byte NOP (skip initialization)\n"));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateKernelPatch (
  IN OUT VAM_HOOK_CONTEXT  *Context
  )
{
  UINT32  Index;

  if (Context->State < VamStateKernelFound) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Emulating kernel memory patching...\n"));

  if (SIMULATION_MODE) {
    for (Index = 0; Index < Context->PatchCount; Index++) {
      CHAR8  *TypeStr;

      switch (Context->PatchSites[Index].Type) {
        case PatchTargetDse:        TypeStr = "DSE"; break;
        case PatchTargetPatchGuard: TypeStr = "PatchGuard"; break;
        default:                    TypeStr = "Custom"; break;
      }

      DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Applying patch %d (%a)...\n", Index, TypeStr));
      DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "    memcpy(0x%016lx, patch, %d) [SIMULATED]\n",
              Context->PatchSites[Index].Address, Context->PatchSites[Index].PatchSize));

      Context->PatchSites[Index].Applied = TRUE;
      Context->PatchesApplied++;
    }

    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → %d/%d patches applied [SIMULATED]\n",
            Context->PatchesApplied, Context->PatchCount));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → DSE disabled: unsigned drivers can load\n"));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  → PatchGuard disabled: kernel modifications undetected\n"));
  }

  Context->State = VamStatePatchApplied;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogVamHookStatus (
  IN     VAM_HOOK_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case VamStateUninitialized:   StateStr = "Uninitialized"; break;
    case VamStateEventRegistered: StateStr = "Event Registered"; break;
    case VamStateCallbackFired:   StateStr = "Callback Fired"; break;
    case VamStateKernelFound:     StateStr = "Kernel Found"; break;
    case VamStatePatchApplied:    StateStr = "Patch Applied"; break;
    default:                      StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "=== VirtualAddressMap Hook Status ===\n"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  State:           %a\n", StateStr));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Event:           %a\n",
          Context->EventRegistered ? "Registered" : "Not registered"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Callback Fired:  %a\n",
          Context->CallbackFired ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Kernel Found:    %a\n",
          Context->KernelFound ? "Yes" : "No"));
  if (Context->KernelFound) {
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Kernel Base:     0x%016lx\n", Context->KernelBase));
    DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Kernel Size:     0x%x\n", Context->KernelSize));
  }
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "  Patches:         %d/%d applied\n",
          Context->PatchesApplied, Context->PatchCount));
  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "=====================================\n\n"));
}

EFI_STATUS
EFIAPI
VirtualAddressMapHookEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Module loaded - CosmicStrand-style Kernel Patch Emulation\n"));

  Status = InitializeVamHook (&mVamContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = RegisterVamCallback (&mVamContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VAM_DEBUG_PREFIX "Callback registration failed: %r\n", Status));
    return Status;
  }

  Status = EmulateCallbackFire (&mVamContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VAM_DEBUG_PREFIX "Callback emulation failed: %r\n", Status));
    return Status;
  }

  Status = ScanForKernelImage (&mVamContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VAM_DEBUG_PREFIX "Kernel scan failed: %r\n", Status));
    return Status;
  }

  Status = PrepareKernelPatches (&mVamContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VAM_DEBUG_PREFIX "Patch preparation failed: %r\n", Status));
    return Status;
  }

  Status = EmulateKernelPatch (&mVamContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, VAM_DEBUG_PREFIX "Kernel patching: %r\n", Status));
  }

  LogVamHookStatus (&mVamContext);

  DEBUG ((DEBUG_INFO, VAM_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}

/** @file
  Capsule Update Hijack Emulation - Implementation

  Emulates firmware update protocol abuse via EFI_FIRMWARE_MANAGEMENT_PROTOCOL.
  Models FMP enumeration, GetImageInfo queries, malicious capsule header
  construction, SetImage injection, and UpdateCapsule runtime calls.

  All operations are SIMULATED - no actual firmware updates are performed.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "CapsuleHijack.h"

STATIC CAPSULE_HIJACK_CONTEXT  mCapsuleContext;

EFI_STATUS
EFIAPI
InitializeCapsuleHijack (
  OUT CAPSULE_HIJACK_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (CAPSULE_HIJACK_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = CapsuleStateUninitialized;

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EnumerateFmpInstances (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  )
{
  EFI_STATUS  Status;
  UINTN       HandleCount;
  EFI_HANDLE  *HandleBuffer;
  UINT32      Index;

  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Enumerating FMP instances...\n"));

  if (SIMULATION_MODE) {
    Context->FmpCount = 3;

    Context->ImageInfo[0].ImageIndex = 1;
    Context->ImageInfo[0].ImageSize = SIMULATED_IMAGE_SIZE;
    Context->ImageInfo[0].Version = 0x00010005;
    Context->ImageInfo[0].Updatable = TRUE;

    Context->ImageInfo[1].ImageIndex = 2;
    Context->ImageInfo[1].ImageSize = SIMULATED_IMAGE_SIZE * 2;
    Context->ImageInfo[1].Version = 0x00020001;
    Context->ImageInfo[1].Updatable = TRUE;

    Context->ImageInfo[2].ImageIndex = 3;
    Context->ImageInfo[2].ImageSize = SIMULATED_IMAGE_SIZE / 2;
    Context->ImageInfo[2].Version = 0x00010000;
    Context->ImageInfo[2].Updatable = FALSE;

    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Found %d FMP instances [SIMULATED]\n",
            Context->FmpCount));
    for (Index = 0; Index < Context->FmpCount; Index++) {
      DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  FMP[%d]: Index=%d Size=0x%lx Ver=0x%08x Updatable=%a\n",
              Index,
              Context->ImageInfo[Index].ImageIndex,
              Context->ImageInfo[Index].ImageSize,
              Context->ImageInfo[Index].Version,
              Context->ImageInfo[Index].Updatable ? "Yes" : "No"));
    }
  } else {
    HandleCount = 0;
    HandleBuffer = NULL;
    Status = gBS->LocateHandleBuffer (
                    ByProtocol,
                    &gEfiFirmwareManagementProtocolGuid,
                    NULL,
                    &HandleCount,
                    &HandleBuffer
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, CAPSULE_DEBUG_PREFIX "No FMP instances found: %r\n", Status));
      Context->FmpCount = 0;
      Context->State = CapsuleStateFmpEnumerated;
      return EFI_SUCCESS;
    }

    Context->FmpCount = (UINT32)(HandleCount > MAX_FMP_INSTANCES ?
                          MAX_FMP_INSTANCES : HandleCount);
    for (Index = 0; Index < Context->FmpCount; Index++) {
      Context->FmpHandles[Index] = HandleBuffer[Index];
    }

    if (HandleBuffer != NULL) {
      FreePool (HandleBuffer);
    }

    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Found %d FMP instances (live)\n",
            Context->FmpCount));
  }

  Context->State = CapsuleStateFmpEnumerated;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
GatherImageInfo (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  )
{
  if (Context->State < CapsuleStateFmpEnumerated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Gathering image info via GetImageInfo...\n"));

  if (SIMULATION_MODE) {
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Querying FMP[0].GetImageInfo()...\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    ImageDescriptorVersion: 3\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    ImageDescriptorCount:   1\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    ImageDescriptorSize:    104\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    AttributesSupported:    IMAGE_UPDATABLE | RESET_REQUIRED\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    AttributesSetting:      IMAGE_UPDATABLE\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    LowestSupportedVersion: 0x00010000\n"));

    Context->ImageInfo[0].AttributesSupported = 0x07;
    Context->ImageInfo[0].AttributesSetting = 0x03;
  } else {
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Live GetImageInfo not implemented (read-only)\n"));
  }

  Context->State = CapsuleStateImageInfoGathered;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ConstructMaliciousCapsule (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  )
{
  EFI_CAPSULE_HEADER  *CapsuleHeader;
  UINT32              PayloadSize;
  UINT32              TotalSize;
  UINT8               *Payload;

  if (Context->State < CapsuleStateImageInfoGathered) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Constructing malicious capsule...\n"));

  PayloadSize = 4096;
  TotalSize = (UINT32)(CAPSULE_HEADER_SIZE + PayloadSize);

  if (SIMULATION_MODE) {
    Context->CapsuleBuffer = AllocateZeroPool (TotalSize);
    if (Context->CapsuleBuffer == NULL) {
      DEBUG ((DEBUG_ERROR, CAPSULE_DEBUG_PREFIX "  Failed to allocate capsule buffer\n"));
      return EFI_OUT_OF_RESOURCES;
    }

    CapsuleHeader = (EFI_CAPSULE_HEADER *)Context->CapsuleBuffer;

    CapsuleHeader->CapsuleGuid = gEfiFirmwareManagementProtocolGuid;
    CapsuleHeader->HeaderSize = (UINT32)CAPSULE_HEADER_SIZE;
    CapsuleHeader->Flags = CAPSULE_FLAGS_PERSIST_ACROSS_RESET |
                           CAPSULE_FLAGS_INITIATE_RESET;
    CapsuleHeader->CapsuleImageSize = TotalSize;

    Payload = Context->CapsuleBuffer + CAPSULE_HEADER_SIZE;
    *(UINT32 *)Payload = IMPLANT_MARKER;

    Context->CapsuleSize = TotalSize;
    Context->CapsuleReady = TRUE;

    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Capsule Header:\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    GUID:       FMP capsule GUID\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    HeaderSize: 0x%x\n", CapsuleHeader->HeaderSize));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    Flags:      0x%08x (PERSIST | RESET)\n",
            CapsuleHeader->Flags));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "    ImageSize:  0x%x (%d bytes)\n",
            TotalSize, TotalSize));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Payload:      Implant marker 0x%08x at offset 0\n",
            IMPLANT_MARKER));
  }

  Context->State = CapsuleStateCapsuleConstructed;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateSetImageInjection (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  )
{
  if (Context->State < CapsuleStateCapsuleConstructed) {
    return EFI_NOT_READY;
  }

  if (!Context->CapsuleReady) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Emulating FMP.SetImage() injection...\n"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Target: FMP[0], ImageIndex=1\n"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Image size: 0x%x bytes\n", Context->CapsuleSize));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  VendorCode: NULL (no vendor-specific auth)\n"));

  if (SIMULATION_MODE) {
    Context->SetImageAttempted = TRUE;
    Context->InjectionResult = EFI_SUCCESS;
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  → FMP.SetImage() returned %r [SIMULATED]\n",
            Context->InjectionResult));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  → Firmware image replaced with implanted payload\n"));
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateUpdateCapsuleCall (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  )
{
  if (Context->State < CapsuleStateCapsuleConstructed) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Emulating RT->UpdateCapsule() call...\n"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  CapsuleHeaderArray: 1 capsule\n"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  CapsuleCount:       1\n"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  ScatterGatherList:  0 (contiguous)\n"));

  if (SIMULATION_MODE) {
    Context->UpdateCapsuleAttempted = TRUE;
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  → RT->UpdateCapsule() accepted [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  → Capsule queued for processing on next reset\n"));
    DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  → On reboot: firmware processes capsule → implant persists\n"));
  }

  Context->State = CapsuleStateInjectionSimulated;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogCapsuleHijackStatus (
  IN     CAPSULE_HIJACK_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case CapsuleStateUninitialized:       StateStr = "Uninitialized"; break;
    case CapsuleStateFmpEnumerated:       StateStr = "FMP Enumerated"; break;
    case CapsuleStateImageInfoGathered:   StateStr = "Image Info Gathered"; break;
    case CapsuleStateCapsuleConstructed:  StateStr = "Capsule Constructed"; break;
    case CapsuleStateInjectionSimulated:  StateStr = "Injection Simulated"; break;
    default:                              StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "=== Capsule Hijack Status ===\n"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  State:            %a\n", StateStr));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  FMP Instances:    %d\n", Context->FmpCount));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Capsule Ready:    %a\n",
          Context->CapsuleReady ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  Capsule Size:     0x%x bytes\n", Context->CapsuleSize));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  SetImage:         %a\n",
          Context->SetImageAttempted ? "Attempted" : "Not attempted"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "  UpdateCapsule:    %a\n",
          Context->UpdateCapsuleAttempted ? "Attempted" : "Not attempted"));
  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "=============================\n\n"));
}

EFI_STATUS
EFIAPI
CapsuleHijackEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Module loaded - Capsule Update Hijack Emulation\n"));

  Status = InitializeCapsuleHijack (&mCapsuleContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = EnumerateFmpInstances (&mCapsuleContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAPSULE_DEBUG_PREFIX "FMP enumeration failed: %r\n", Status));
    return Status;
  }

  Status = GatherImageInfo (&mCapsuleContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAPSULE_DEBUG_PREFIX "GetImageInfo failed: %r\n", Status));
    return Status;
  }

  Status = ConstructMaliciousCapsule (&mCapsuleContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAPSULE_DEBUG_PREFIX "Capsule construction failed: %r\n", Status));
    return Status;
  }

  Status = EmulateSetImageInjection (&mCapsuleContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, CAPSULE_DEBUG_PREFIX "SetImage injection: %r\n", Status));
  }

  Status = EmulateUpdateCapsuleCall (&mCapsuleContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, CAPSULE_DEBUG_PREFIX "UpdateCapsule call: %r\n", Status));
  }

  LogCapsuleHijackStatus (&mCapsuleContext);

  if (mCapsuleContext.CapsuleBuffer != NULL) {
    FreePool (mCapsuleContext.CapsuleBuffer);
    mCapsuleContext.CapsuleBuffer = NULL;
  }

  DEBUG ((DEBUG_INFO, CAPSULE_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}

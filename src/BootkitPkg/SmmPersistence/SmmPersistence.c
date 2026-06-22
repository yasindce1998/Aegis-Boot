/** @file
  SMM Persistence Emulation - Implementation

  Emulates Ring -2 persistence via System Management Mode. Models techniques
  from ThinkPwn and Hacking Team UEFI rootkits:
  - SMRAM layout discovery via SMRR MSRs
  - D_LCK bit bypass for SMRAM unlock
  - SMI handler injection into TSEG
  - SMI trigger via APMC port 0xB2

  All operations are SIMULATED - no actual SMM manipulation occurs.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SmmPersistence.h"

STATIC SMM_PERSISTENCE_CONTEXT  mSmmContext;

STATIC UINT8  mDummyHandler[] = {
  0xFB,                   // STI
  0x48, 0x89, 0xE5,      // MOV RBP, RSP
  0x48, 0x83, 0xEC, 0x20,// SUB RSP, 0x20
  0x90,                   // NOP (payload placeholder)
  0x90, 0x90, 0x90,
  0x48, 0x83, 0xC4, 0x20,// ADD RSP, 0x20
  0x5D,                   // POP RBP
  0x0F, 0xAA             // RSM (return from SMM)
};

EFI_STATUS
EFIAPI
InitializeSmmPersistence (
  OUT SMM_PERSISTENCE_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (SMM_PERSISTENCE_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = SmmStateUninitialized;
  Context->HandlerCount = 0;

  Context->SimulatedSmramSize = TSEG_DEFAULT_SIZE;
  Context->SimulatedSmram = AllocateZeroPool (Context->SimulatedSmramSize);
  if (Context->SimulatedSmram == NULL) {
    DEBUG ((DEBUG_ERROR, SMM_DEBUG_PREFIX "Failed to allocate simulated SMRAM\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
DiscoverSmramLayout (
  IN OUT SMM_PERSISTENCE_CONTEXT  *Context
  )
{
  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  if (SIMULATION_MODE) {
    Context->SmrrPhysBase = TSEG_DEFAULT_BASE | 0x06;  // WB cacheable
    Context->SmrrPhysMask = 0xFFFFFFFF00800000ULL | BIT11;  // Valid + 8MB mask
    Context->TsegBase = TSEG_DEFAULT_BASE;
    Context->TsegSize = TSEG_DEFAULT_SIZE;
    Context->SmrrValid = TRUE;

    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "SMRR PhysBase: 0x%016lx\n", Context->SmrrPhysBase));
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "SMRR PhysMask: 0x%016lx\n", Context->SmrrPhysMask));
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "TSEG Base: 0x%08lx, Size: 0x%08x\n",
            Context->TsegBase, (UINT32)Context->TsegSize));
  } else {
    Context->SmrrPhysBase = AsmReadMsr64 (MSR_IA32_SMRR_PHYSBASE);
    Context->SmrrPhysMask = AsmReadMsr64 (MSR_IA32_SMRR_PHYSMASK);
    Context->SmrrValid = (Context->SmrrPhysMask & BIT11) != 0;

    if (Context->SmrrValid) {
      Context->TsegBase = Context->SmrrPhysBase & 0xFFFFF000;
      Context->TsegSize = ~(Context->SmrrPhysMask & 0xFFFFF000) + 1;
    }
  }

  Context->State = SmmStateDiscovered;
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "SMRAM layout discovered\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateSmramLockBypass (
  IN OUT SMM_PERSISTENCE_CONTEXT  *Context
  )
{
  if (Context->State < SmmStateDiscovered) {
    return EFI_NOT_READY;
  }

  if (SIMULATION_MODE) {
    Context->DLockSet = TRUE;
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "D_LCK bit currently SET (PCI B%d:D%d:F%d offset 0x%02x)\n",
            SMM_DLOCK_PCI_BUS, SMM_DLOCK_PCI_DEV, SMM_DLOCK_PCI_FUNC, SMM_DLOCK_OFFSET));

    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "Simulating D_LCK bypass via race condition...\n"));
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  Step 1: Trigger SMI to enter SMM context\n"));
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  Step 2: Within SMM, clear D_LCK (privileged in Ring -2)\n"));
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  Step 3: SMRAM now writable from Ring 0\n"));

    Context->DLockBypassed = TRUE;
  } else {
    DEBUG ((DEBUG_WARN, SMM_DEBUG_PREFIX "LIVE MODE: D_LCK bypass NOT performed (research only)\n"));
    return EFI_ACCESS_DENIED;
  }

  Context->State = SmmStateLockBypassed;
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "SMRAM lock bypass emulated successfully\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
InjectSmiHandler (
  IN OUT SMM_PERSISTENCE_CONTEXT  *Context,
  IN     UINT8                    CommandCode,
  IN     VOID                     *HandlerCode,
  IN     UINT32                   HandlerSize
  )
{
  UINT64  TargetAddress;
  UINT32  Offset;

  if (Context->State < SmmStateLockBypassed) {
    return EFI_NOT_READY;
  }

  if (Context->HandlerCount >= MAX_SMI_HANDLERS) {
    DEBUG ((DEBUG_ERROR, SMM_DEBUG_PREFIX "Handler table full\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  if (HandlerSize > (Context->SimulatedSmramSize - SMRAM_HANDLER_OFFSET)) {
    return EFI_BUFFER_TOO_SMALL;
  }

  Offset = SMRAM_HANDLER_OFFSET + (Context->HandlerCount * 0x1000);
  TargetAddress = Context->TsegBase + Offset;

  if (SIMULATION_MODE) {
    CopyMem (Context->SimulatedSmram + Offset, HandlerCode, HandlerSize);
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "Injected handler at SMRAM+0x%x (simulated addr: 0x%016lx)\n",
            Offset, TargetAddress));
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  Command code: 0x%02x, Size: %d bytes\n",
            CommandCode, HandlerSize));
  }

  Context->Handlers[Context->HandlerCount].CommandCode = CommandCode;
  Context->Handlers[Context->HandlerCount].HandlerAddress = TargetAddress;
  Context->Handlers[Context->HandlerCount].HandlerSize = HandlerSize;
  Context->Handlers[Context->HandlerCount].IsActive = TRUE;
  Context->HandlerCount++;

  Context->State = SmmStateHandlerInjected;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TriggerSmi (
  IN     SMM_PERSISTENCE_CONTEXT  *Context,
  IN     UINT8                    CommandCode
  )
{
  UINT32  Index;

  if (Context->State < SmmStateHandlerInjected) {
    return EFI_NOT_READY;
  }

  for (Index = 0; Index < Context->HandlerCount; Index++) {
    if (Context->Handlers[Index].CommandCode == CommandCode &&
        Context->Handlers[Index].IsActive) {
      if (SIMULATION_MODE) {
        DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "SMI triggered: cmd=0x%02x → handler at 0x%016lx\n",
                CommandCode, Context->Handlers[Index].HandlerAddress));
        DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  IoWrite8(0x%x, 0x%02x) [SIMULATED]\n",
                SMI_TRIGGER_PORT, CommandCode));
      } else {
        IoWrite8 (SMI_TRIGGER_PORT, CommandCode);
      }

      Context->State = SmmStateActive;
      return EFI_SUCCESS;
    }
  }

  DEBUG ((DEBUG_WARN, SMM_DEBUG_PREFIX "No handler for command 0x%02x\n", CommandCode));
  return EFI_NOT_FOUND;
}

VOID
EFIAPI
LogSmmPersistenceStatus (
  IN     SMM_PERSISTENCE_CONTEXT  *Context
  )
{
  UINT32  Index;
  CHAR8   *StateStr;

  switch (Context->State) {
    case SmmStateUninitialized:   StateStr = "Uninitialized"; break;
    case SmmStateDiscovered:      StateStr = "SMRAM Discovered"; break;
    case SmmStateLockBypassed:    StateStr = "Lock Bypassed"; break;
    case SmmStateHandlerInjected: StateStr = "Handler Injected"; break;
    case SmmStateActive:          StateStr = "Active"; break;
    default:                      StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "=== SMM Persistence Status ===\n"));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  State:         %a\n", StateStr));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  TSEG Base:     0x%016lx\n", Context->TsegBase));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  TSEG Size:     0x%08x (%d MB)\n",
          (UINT32)Context->TsegSize, (UINT32)(Context->TsegSize / (1024 * 1024))));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  SMRR Valid:    %a\n", Context->SmrrValid ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  D_LCK Set:     %a\n", Context->DLockSet ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  D_LCK Bypass:  %a\n", Context->DLockBypassed ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "  Handlers:      %d / %d\n",
          Context->HandlerCount, MAX_SMI_HANDLERS));

  for (Index = 0; Index < Context->HandlerCount; Index++) {
    DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "    [%d] Cmd=0x%02x Addr=0x%016lx Size=%d Active=%a\n",
            Index,
            Context->Handlers[Index].CommandCode,
            Context->Handlers[Index].HandlerAddress,
            Context->Handlers[Index].HandlerSize,
            Context->Handlers[Index].IsActive ? "Yes" : "No"));
  }

  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "==============================\n\n"));
}

EFI_STATUS
EFIAPI
SmmPersistenceEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "Module loaded - Ring -2 Persistence Emulation\n"));

  Status = InitializeSmmPersistence (&mSmmContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = DiscoverSmramLayout (&mSmmContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SMM_DEBUG_PREFIX "Failed to discover SMRAM layout: %r\n", Status));
    return Status;
  }

  Status = EmulateSmramLockBypass (&mSmmContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SMM_DEBUG_PREFIX "Lock bypass failed: %r\n", Status));
    return Status;
  }

  Status = InjectSmiHandler (
             &mSmmContext,
             SMI_CMD_IMPLANT_HANDLER,
             mDummyHandler,
             sizeof (mDummyHandler)
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, SMM_DEBUG_PREFIX "Handler injection failed: %r\n", Status));
    return Status;
  }

  Status = TriggerSmi (&mSmmContext, SMI_CMD_IMPLANT_HANDLER);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, SMM_DEBUG_PREFIX "SMI trigger failed: %r\n", Status));
  }

  LogSmmPersistenceStatus (&mSmmContext);

  DEBUG ((DEBUG_INFO, SMM_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}

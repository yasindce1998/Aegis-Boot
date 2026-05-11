/** @file
  Event Log Extractor Module Header

  Defines structures and functions for TCG Event Log extraction
  and analysis.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __EVENT_LOG_EXTRACTOR_H__
#define __EVENT_LOG_EXTRACTOR_H__

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <IndustryStandard/UefiTcgPlatform.h>

//
// Module identification
//
#define EVENT_LOG_SIGNATURE  SIGNATURE_32('E','V','L','G')
#define EVENT_LOG_VERSION    0x00010000

//
// Maximum events to process
//
#define MAX_EVENT_COUNT  256

//
// Event log entry structure
//
typedef struct {
  UINT32   PcrIndex;
  UINT32   EventType;
  UINT8    Digest[32];  // SHA-256
  UINT32   EventSize;
  CHAR16   Description[128];
} EVENT_LOG_ENTRY;

//
// Event log context
//
typedef struct {
  UINT32                Signature;
  UINT32                Version;
  EFI_TCG2_PROTOCOL     *Tcg2Protocol;
  EVENT_LOG_ENTRY       Events[MAX_EVENT_COUNT];
  UINT32                EventCount;
  BOOLEAN               LogExtracted;
} EVENT_LOG_CONTEXT;

/**
  Entry point for the Event Log Extractor driver.

  @param[in]  ImageHandle  Handle for the image of this driver.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS      Driver initialized successfully.
  @retval Other            Error occurred during initialization.

**/
EFI_STATUS
EFIAPI
EventLogExtractorEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

/**
  Extract TCG Event Log from firmware.

  @param[in]  Context  Pointer to event log context.

  @retval EFI_SUCCESS  Event log extracted successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
ExtractEventLog (
  IN OUT EVENT_LOG_CONTEXT  *Context
  );

/**
  Parse a single event log entry.

  @param[in]   EventData  Pointer to event data.
  @param[out]  Entry      Pointer to store parsed entry.

  @retval EFI_SUCCESS  Entry parsed successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
ParseEventEntry (
  IN  CONST VOID        *EventData,
  OUT EVENT_LOG_ENTRY   *Entry
  );

/**
  Log event log entries for research purposes.

  @param[in]  Context  Pointer to event log context.

**/
VOID
LogEventEntries (
  IN CONST EVENT_LOG_CONTEXT  *Context
  );

/**
  Export event log data for analysis.

  @param[in]  Context  Pointer to event log context.

  @retval EFI_SUCCESS  Data exported successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
ExportEventLogData (
  IN EVENT_LOG_CONTEXT  *Context
  );

/**
  Get event type description.

  @param[in]  EventType  Event type code.

  @return Event type description string.

**/
CONST CHAR16 *
GetEventTypeDescription (
  IN UINT32  EventType
  );

#endif // __EVENT_LOG_EXTRACTOR_H__

// Made with Bob

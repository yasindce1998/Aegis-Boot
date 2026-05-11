/** @file
  Event Log Extractor Module Implementation

  Implements TCG Event Log extraction and parsing for defensive
  security research and detection ground truth generation.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "EventLogExtractor.h"

//
// Global event log context
//
STATIC EVENT_LOG_CONTEXT  mEventLogContext = {
  .Signature      = EVENT_LOG_SIGNATURE,
  .Version        = EVENT_LOG_VERSION,
  .Tcg2Protocol   = NULL,
  .EventCount     = 0,
  .LogExtracted   = FALSE
};

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
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "Aegis-Boot Event Log Extractor\n"));
  DEBUG ((DEBUG_INFO, "Version: %08x\n", EVENT_LOG_VERSION));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));

  //
  // Locate TCG2 Protocol
  //
  DEBUG ((DEBUG_INFO, "[EventLog] Locating TCG2 Protocol...\n"));
  Status = gBS->LocateProtocol (
                  &gEfiTcg2ProtocolGuid,
                  NULL,
                  (VOID **)&mEventLogContext.Tcg2Protocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[EventLog] TCG2 Protocol not found: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[EventLog] TCG2 Protocol located successfully\n"));

  //
  // Extract event log
  //
  DEBUG ((DEBUG_INFO, "[EventLog] Extracting TCG Event Log...\n"));
  Status = ExtractEventLog (&mEventLogContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[EventLog] Failed to extract event log: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[EventLog] Extracted %d events\n", mEventLogContext.EventCount));

  //
  // Log event entries
  //
  LogEventEntries (&mEventLogContext);

  //
  // Export event log data
  //
  DEBUG ((DEBUG_INFO, "[EventLog] Exporting event log data...\n"));
  Status = ExportEventLogData (&mEventLogContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "[EventLog] Failed to export data: %r\n", Status));
  }

  DEBUG ((DEBUG_INFO, "[EventLog] Event Log Extractor initialized\n"));

  return EFI_SUCCESS;
}

/**
  Extract TCG Event Log from firmware.

  @param[in]  Context  Pointer to event log context.

  @retval EFI_SUCCESS  Event log extracted successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
ExtractEventLog (
  IN OUT EVENT_LOG_CONTEXT  *Context
  )
{
  EFI_STATUS                    Status;
  EFI_PHYSICAL_ADDRESS          EventLogLocation;
  EFI_PHYSICAL_ADDRESS          EventLogLastEntry;
  BOOLEAN                       EventLogTruncated;
  TCG_PCR_EVENT2                *Event;
  UINT8                         *EventPtr;
  UINT32                        EventIndex;

  if (Context == NULL || Context->Tcg2Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get event log location
  //
  Status = Context->Tcg2Protocol->GetEventLog (
                                     Context->Tcg2Protocol,
                                     EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
                                     &EventLogLocation,
                                     &EventLogLastEntry,
                                     &EventLogTruncated
                                     );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[EventLog] Failed to get event log location: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[EventLog] Event log location: 0x%lx\n", EventLogLocation));
  DEBUG ((DEBUG_INFO, "[EventLog] Event log last entry: 0x%lx\n", EventLogLastEntry));
  DEBUG ((DEBUG_INFO, "[EventLog] Event log truncated: %a\n", EventLogTruncated ? "Yes" : "No"));

  //
  // Parse event log entries
  //
  EventPtr = (UINT8 *)(UINTN)EventLogLocation;
  EventIndex = 0;

  while ((UINTN)EventPtr < (UINTN)EventLogLastEntry && EventIndex < MAX_EVENT_COUNT) {
    Event = (TCG_PCR_EVENT2 *)EventPtr;

    //
    // Parse this event
    //
    Status = ParseEventEntry (Event, &Context->Events[EventIndex]);
    if (!EFI_ERROR (Status)) {
      EventIndex++;
    }

    //
    // Move to next event
    // Event size = header + digest count + digests + event size + event data
    //
    EventPtr += sizeof (TCG_PCR_EVENT2_HDR);
    EventPtr += sizeof (UINT32);  // Digest count
    EventPtr += Event->Digests.count * (sizeof (UINT16) + 32);  // Assume SHA-256
    EventPtr += sizeof (UINT32);  // Event size
    EventPtr += Event->EventSize;

    //
    // Safety check
    //
    if ((UINTN)EventPtr >= (UINTN)EventLogLastEntry) {
      break;
    }
  }

  Context->EventCount = EventIndex;
  Context->LogExtracted = TRUE;

  return EFI_SUCCESS;
}

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
  )
{
  TCG_PCR_EVENT2  *Event;

  if (EventData == NULL || Entry == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Event = (TCG_PCR_EVENT2 *)EventData;

  //
  // Extract event information
  //
  Entry->PcrIndex = Event->PCRIndex;
  Entry->EventType = Event->EventType;
  Entry->EventSize = Event->EventSize;

  //
  // Copy first digest (assume SHA-256)
  //
  if (Event->Digests.count > 0) {
    CopyMem (
      Entry->Digest,
      Event->Digests.digests[0].digest.sha256,
      MIN (32, sizeof (Entry->Digest))
      );
  } else {
    ZeroMem (Entry->Digest, sizeof (Entry->Digest));
  }

  //
  // Get event type description
  //
  StrnCpyS (
    Entry->Description,
    sizeof (Entry->Description) / sizeof (CHAR16),
    GetEventTypeDescription (Entry->EventType),
    127
    );

  return EFI_SUCCESS;
}

/**
  Log event log entries for research purposes.

  @param[in]  Context  Pointer to event log context.

**/
VOID
LogEventEntries (
  IN CONST EVENT_LOG_CONTEXT  *Context
  )
{
  UINT32  Index;
  UINT32  DigestIndex;
  CHAR16  DigestString[65];

  if (Context == NULL || !Context->LogExtracted) {
    return;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "=== TCG Event Log (%d entries) ===\n", Context->EventCount));

  for (Index = 0; Index < Context->EventCount; Index++) {
    //
    // Convert digest to hex string
    //
    for (DigestIndex = 0; DigestIndex < 32; DigestIndex++) {
      UnicodeSPrint (
        &DigestString[DigestIndex * 2],
        3 * sizeof (CHAR16),
        L"%02x",
        Context->Events[Index].Digest[DigestIndex]
        );
    }
    DigestString[64] = L'\0';

    DEBUG ((
      DEBUG_INFO,
      "[EventLog] Event %d: PCR %d, Type 0x%08x\n",
      Index,
      Context->Events[Index].PcrIndex,
      Context->Events[Index].EventType
      ));
    DEBUG ((DEBUG_INFO, "[EventLog]   %s\n", Context->Events[Index].Description));
    DEBUG ((DEBUG_INFO, "[EventLog]   Digest: %s\n", DigestString));
    DEBUG ((DEBUG_INFO, "[EventLog]   Size: %d bytes\n", Context->Events[Index].EventSize));
  }

  DEBUG ((DEBUG_INFO, "=== End Event Log ===\n"));
  DEBUG ((DEBUG_INFO, "\n"));
}

/**
  Export event log data for analysis.

  @param[in]  Context  Pointer to event log context.

  @retval EFI_SUCCESS  Data exported successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
ExportEventLogData (
  IN EVENT_LOG_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->LogExtracted) {
    return EFI_NOT_READY;
  }

  //
  // In a real implementation, we would:
  // 1. Write to a dedicated logging partition
  // 2. Export to serial port for capture
  // 3. Store in NVRAM for post-boot analysis
  // 4. Send to AegisScanner for IoC generation
  //

  DEBUG ((DEBUG_INFO, "[EventLog] === Event Log Export ===\n"));
  DEBUG ((DEBUG_INFO, "[EventLog] Total Events: %d\n", Context->EventCount));
  DEBUG ((DEBUG_INFO, "[EventLog] Log Extracted: %a\n", Context->LogExtracted ? "Yes" : "No"));
  DEBUG ((DEBUG_INFO, "[EventLog] === End Export ===\n"));

  return EFI_SUCCESS;
}

/**
  Get event type description.

  @param[in]  EventType  Event type code.

  @return Event type description string.

**/
CONST CHAR16 *
GetEventTypeDescription (
  IN UINT32  EventType
  )
{
  switch (EventType) {
    case EV_PREBOOT_CERT:
      return L"Pre-Boot Certificate";
    case EV_POST_CODE:
      return L"POST Code";
    case EV_NO_ACTION:
      return L"No Action";
    case EV_SEPARATOR:
      return L"Separator";
    case EV_ACTION:
      return L"Action";
    case EV_EVENT_TAG:
      return L"Event Tag";
    case EV_S_CRTM_CONTENTS:
      return L"S-CRTM Contents";
    case EV_S_CRTM_VERSION:
      return L"S-CRTM Version";
    case EV_CPU_MICROCODE:
      return L"CPU Microcode";
    case EV_PLATFORM_CONFIG_FLAGS:
      return L"Platform Config Flags";
    case EV_TABLE_OF_DEVICES:
      return L"Table of Devices";
    case EV_COMPACT_HASH:
      return L"Compact Hash";
    case EV_IPL:
      return L"IPL (Initial Program Load)";
    case EV_IPL_PARTITION_DATA:
      return L"IPL Partition Data";
    case EV_NONHOST_CODE:
      return L"Non-Host Code";
    case EV_NONHOST_CONFIG:
      return L"Non-Host Config";
    case EV_NONHOST_INFO:
      return L"Non-Host Info";
    case EV_OMIT_BOOT_DEVICE_EVENTS:
      return L"Omit Boot Device Events";
    case EV_EFI_EVENT_BASE:
      return L"EFI Event Base";
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
      return L"EFI Variable Driver Config";
    case EV_EFI_VARIABLE_BOOT:
      return L"EFI Variable Boot";
    case EV_EFI_BOOT_SERVICES_APPLICATION:
      return L"EFI Boot Services Application";
    case EV_EFI_BOOT_SERVICES_DRIVER:
      return L"EFI Boot Services Driver";
    case EV_EFI_RUNTIME_SERVICES_DRIVER:
      return L"EFI Runtime Services Driver";
    case EV_EFI_GPT_EVENT:
      return L"EFI GPT Event";
    case EV_EFI_ACTION:
      return L"EFI Action";
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
      return L"EFI Platform Firmware Blob";
    case EV_EFI_HANDOFF_TABLES:
      return L"EFI Handoff Tables";
    case EV_EFI_HCRTM_EVENT:
      return L"EFI H-CRTM Event";
    case EV_EFI_VARIABLE_AUTHORITY:
      return L"EFI Variable Authority";
    default:
      return L"Unknown Event Type";
  }
}

// Made with Bob

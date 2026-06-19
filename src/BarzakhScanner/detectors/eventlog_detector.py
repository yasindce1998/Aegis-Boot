"""
Event Log Detector - TCG Event Log Analysis

Detects bootkit artifacts by analyzing TCG Event Log for anomalies,
missing measurements, and suspicious event sequences.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class EventLogDetector:
    """Detector for TCG Event Log anomalies."""

    # TCG Event Types
    EVENT_TYPES = {
        0x00000000: "EV_PREBOOT_CERT",
        0x00000001: "EV_POST_CODE",
        0x00000002: "EV_UNUSED",
        0x00000003: "EV_NO_ACTION",
        0x00000004: "EV_SEPARATOR",
        0x00000005: "EV_ACTION",
        0x00000006: "EV_EVENT_TAG",
        0x00000007: "EV_S_CRTM_CONTENTS",
        0x00000008: "EV_S_CRTM_VERSION",
        0x00000009: "EV_CPU_MICROCODE",
        0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
        0x0000000B: "EV_TABLE_OF_DEVICES",
        0x0000000C: "EV_COMPACT_HASH",
        0x0000000D: "EV_IPL",
        0x0000000E: "EV_IPL_PARTITION_DATA",
        0x0000000F: "EV_NONHOST_CODE",
        0x00000010: "EV_NONHOST_CONFIG",
        0x00000011: "EV_NONHOST_INFO",
        0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
        0x80000000: "EV_EFI_EVENT_BASE",
        0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
        0x80000002: "EV_EFI_VARIABLE_BOOT",
        0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
        0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
        0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
        0x80000006: "EV_EFI_GPT_EVENT",
        0x80000007: "EV_EFI_ACTION",
        0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        0x80000009: "EV_EFI_HANDOFF_TABLES",
        0x800000E0: "EV_EFI_VARIABLE_AUTHORITY"
    }

    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize event log detector.

        Args:
            baseline: Baseline event log for comparison
        """
        self.baseline = baseline
        self.findings = []

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze TCG Event Log for anomalies.

        Args:
            target_path: Path to event log dump

        Returns:
            List of findings
        """
        self.findings = []

        # Load event log
        events = self._load_event_log(target_path)
        
        if not events:
            self.findings.append({
                'detector': 'eventlog',
                'severity': 'medium',
                'title': 'Unable to load event log',
                'description': f'Could not read event log from {target_path}',
                'recommendation': 'Verify file format and TCG Event Log availability'
            })
            return self.findings

        # Check for missing critical events
        self._check_missing_events(events)

        # Check for suspicious event sequences
        self._check_event_sequences(events)

        # Check for measurement gaps
        self._check_measurement_gaps(events)

        # Check for duplicate events
        self._check_duplicate_events(events)

        # Compare with baseline
        if self.baseline:
            self._compare_with_baseline(events)

        return self.findings

    def _load_event_log(self, target_path: str) -> List[Dict]:
        """
        Load and parse TCG Event Log.

        Args:
            target_path: Path to event log

        Returns:
            List of parsed events
        """
        target = Path(target_path)
        
        if not target.exists():
            return []

        events = []

        try:
            with open(target, 'rb') as f:
                data = f.read()
                offset = 0

                # Parse TCG_PCR_EVENT2 structures
                while offset < len(data) - 32:
                    event = self._parse_event(data, offset)
                    if event:
                        events.append(event)
                        offset += event['size']
                    else:
                        break

        except Exception as e:
            print(f"[WARNING] Failed to load event log: {e}")

        return events

    def _parse_event(self, data: bytes, offset: int) -> Optional[Dict]:
        """
        Parse single TCG event.

        Args:
            data: Event log data
            offset: Current offset

        Returns:
            Parsed event or None
        """
        try:
            # TCG_PCR_EVENT2 structure:
            # PCRIndex (4) + EventType (4) + DigestCount (4) + Digests + EventSize (4) + Event
            
            pcr_index = struct.unpack('<I', data[offset:offset+4])[0]
            event_type = struct.unpack('<I', data[offset+4:offset+8])[0]
            digest_count = struct.unpack('<I', data[offset+8:offset+12])[0]

            current_offset = offset + 12

            # Parse digests
            digests = []
            for _ in range(digest_count):
                if current_offset + 34 > len(data):
                    return None
                
                alg_id = struct.unpack('<H', data[current_offset:current_offset+2])[0]
                digest = data[current_offset+2:current_offset+34]
                digests.append({'algorithm': alg_id, 'digest': digest.hex()})
                current_offset += 34

            # Parse event data
            if current_offset + 4 > len(data):
                return None
            
            event_size = struct.unpack('<I', data[current_offset:current_offset+4])[0]
            current_offset += 4

            if current_offset + event_size > len(data):
                return None

            event_data = data[current_offset:current_offset+event_size]
            current_offset += event_size

            return {
                'pcr_index': pcr_index,
                'event_type': event_type,
                'event_type_name': self.EVENT_TYPES.get(event_type, f'Unknown (0x{event_type:08x})'),
                'digests': digests,
                'event_data': event_data.hex(),
                'size': current_offset - offset
            }

        except Exception as e:
            print(f"[WARNING] Failed to parse event at offset {offset}: {e}")
            return None

    def _check_missing_events(self, events: List[Dict]):
        """
        Check for missing critical events.

        Args:
            events: List of parsed events
        """
        # Critical events that should be present
        critical_events = [
            (0x00000007, "EV_S_CRTM_CONTENTS"),  # BIOS measurement
            (0x00000004, "EV_SEPARATOR"),         # PCR separator
            (0x80000008, "EV_EFI_PLATFORM_FIRMWARE_BLOB")  # Firmware blob
        ]

        event_types_present = set(e['event_type'] for e in events)

        for event_type, event_name in critical_events:
            if event_type not in event_types_present:
                self.findings.append({
                    'detector': 'eventlog',
                    'severity': 'high',
                    'title': f'Missing critical event: {event_name}',
                    'description': f'Event log is missing {event_name} (0x{event_type:08x}), '
                                 'which should be present in a valid boot sequence.',
                    'details': {
                        'event_type': f'0x{event_type:08x}',
                        'event_name': event_name
                    },
                    'recommendation': 'Investigate why critical boot measurement is missing'
                })

    def _check_event_sequences(self, events: List[Dict]):
        """
        Check for suspicious event sequences.

        Args:
            events: List of parsed events
        """
        # Check for events in wrong PCRs
        for event in events:
            pcr = event['pcr_index']
            event_type = event['event_type']

            # EV_S_CRTM_CONTENTS should be in PCR 0
            if event_type == 0x00000007 and pcr != 0:
                self.findings.append({
                    'detector': 'eventlog',
                    'severity': 'high',
                    'title': 'CRTM measurement in wrong PCR',
                    'description': f'EV_S_CRTM_CONTENTS found in PCR {pcr} instead of PCR 0',
                    'details': {
                        'pcr_index': pcr,
                        'event_type': event['event_type_name']
                    },
                    'recommendation': 'Investigate event log manipulation'
                })

            # EV_SEPARATOR should be in PCRs 0-7
            if event_type == 0x00000004 and pcr > 7:
                self.findings.append({
                    'detector': 'eventlog',
                    'severity': 'medium',
                    'title': 'Separator in unexpected PCR',
                    'description': f'EV_SEPARATOR found in PCR {pcr}, expected in PCRs 0-7',
                    'details': {
                        'pcr_index': pcr,
                        'event_type': event['event_type_name']
                    },
                    'recommendation': 'Verify event log integrity'
                })

    def _check_measurement_gaps(self, events: List[Dict]):
        """
        Check for gaps in measurement sequence.

        Args:
            events: List of parsed events
        """
        # Group events by PCR
        pcr_events = {}
        for event in events:
            pcr = event['pcr_index']
            if pcr not in pcr_events:
                pcr_events[pcr] = []
            pcr_events[pcr].append(event)

        # Check each PCR for gaps
        for pcr in range(8):
            if pcr not in pcr_events:
                self.findings.append({
                    'detector': 'eventlog',
                    'severity': 'high',
                    'title': f'No measurements in PCR {pcr}',
                    'description': f'PCR {pcr} has no recorded measurements in event log',
                    'details': {
                        'pcr_index': pcr
                    },
                    'recommendation': 'Investigate missing boot measurements'
                })
            elif len(pcr_events[pcr]) < 2:
                self.findings.append({
                    'detector': 'eventlog',
                    'severity': 'medium',
                    'title': f'Insufficient measurements in PCR {pcr}',
                    'description': f'PCR {pcr} has only {len(pcr_events[pcr])} measurement(s), '
                                 'which is unusually low',
                    'details': {
                        'pcr_index': pcr,
                        'measurement_count': len(pcr_events[pcr])
                    },
                    'recommendation': 'Verify complete boot measurement chain'
                })

    def _check_duplicate_events(self, events: List[Dict]):
        """
        Check for duplicate events (possible replay attack).

        Args:
            events: List of parsed events
        """
        seen_events = set()
        
        for event in events:
            # Create event signature
            signature = (
                event['pcr_index'],
                event['event_type'],
                event['digests'][0]['digest'] if event['digests'] else ''
            )

            if signature in seen_events:
                self.findings.append({
                    'detector': 'eventlog',
                    'severity': 'high',
                    'title': 'Duplicate event detected',
                    'description': f'Found duplicate event in PCR {event["pcr_index"]}: '
                                 f'{event["event_type_name"]}',
                    'details': {
                        'pcr_index': event['pcr_index'],
                        'event_type': event['event_type_name'],
                        'digest': event['digests'][0]['digest'] if event['digests'] else 'N/A'
                    },
                    'recommendation': 'Investigate potential event log replay attack'
                })
            
            seen_events.add(signature)

    def _compare_with_baseline(self, events: List[Dict]):
        """
        Compare event log with baseline.

        Args:
            events: List of parsed events
        """
        if not self.baseline or 'event_log' not in self.baseline:
            return

        baseline_events = self.baseline['event_log']

        # Compare event counts per PCR
        current_counts = {}
        for event in events:
            pcr = event['pcr_index']
            current_counts[pcr] = current_counts.get(pcr, 0) + 1

        baseline_counts = {}
        for event in baseline_events:
            pcr = event['pcr_index']
            baseline_counts[pcr] = baseline_counts.get(pcr, 0) + 1

        for pcr in range(8):
            current = current_counts.get(pcr, 0)
            baseline = baseline_counts.get(pcr, 0)

            if current != baseline:
                severity = 'high' if abs(current - baseline) > 2 else 'medium'
                self.findings.append({
                    'detector': 'eventlog',
                    'severity': severity,
                    'title': f'Event count mismatch in PCR {pcr}',
                    'description': f'PCR {pcr} has {current} events vs {baseline} in baseline',
                    'details': {
                        'pcr_index': pcr,
                        'current_count': current,
                        'baseline_count': baseline
                    },
                    'recommendation': 'Investigate additional or missing boot measurements'
                })



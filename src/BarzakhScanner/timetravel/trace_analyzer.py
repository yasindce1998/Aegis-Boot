"""
Trace Analyzer - Post-hoc analysis of recorded execution traces.

Answers questions like: "When was BST[LoadImage] first modified?"
"What instruction installed the hook?" "What memory was written
between events A and B?"

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .trace_format import (
    MemoryAccessType,
    TraceEvent,
    TraceEventType,
    TraceHeader,
    TraceReader,
)


@dataclass
class AnalysisResult:
    """Result of a trace analysis query."""
    query: str = ""
    found: bool = False
    event_index: int = -1
    event: Optional[TraceEvent] = None
    context_before: List[TraceEvent] = field(default_factory=list)
    context_after: List[TraceEvent] = field(default_factory=list)
    details: Dict = field(default_factory=dict)

    @property
    def pc(self) -> int:
        return self.event.pc if self.event else 0

    @property
    def timestamp_ns(self) -> int:
        return self.event.timestamp_ns if self.event else 0


@dataclass
class MemoryRegionStats:
    """Statistics about writes to a memory region."""
    base_address: int
    size: int
    write_count: int = 0
    unique_pcs: Set[int] = field(default_factory=set)
    first_write_index: int = -1
    last_write_index: int = -1
    values_written: List[Tuple[int, int, int]] = field(default_factory=list)


class TraceAnalyzer:
    """
    Post-hoc analysis engine for execution traces.

    Provides high-level queries against recorded traces to answer
    security-relevant questions about boot execution.
    """

    # Well-known BST entry offsets (x86_64, UEFI 2.x)
    BST_OFFSETS = {
        0x28: "RaiseTPL",
        0x30: "RestoreTPL",
        0x38: "AllocatePages",
        0x40: "FreePages",
        0x48: "GetMemoryMap",
        0x50: "AllocatePool",
        0x58: "FreePool",
        0x80: "HandleProtocol",
        0xC0: "LoadImage",
        0xC8: "StartImage",
        0xD0: "Exit",
        0xD8: "UnloadImage",
        0xE0: "ExitBootServices",
        0xE8: "GetNextMonotonicCount",
        0xF0: "Stall",
        0xF8: "SetWatchdogTimer",
        0x140: "SetVariable",
    }

    def __init__(self, trace_path: Path, bst_base: int = 0):
        self._trace_path = Path(trace_path)
        self._bst_base = bst_base
        self._header: Optional[TraceHeader] = None
        self._events_cache: Optional[List[TraceEvent]] = None

    @property
    def header(self) -> Optional[TraceHeader]:
        return self._header

    def load(self, cache_events: bool = True) -> TraceHeader:
        """Load trace file and optionally cache all events in memory."""
        reader = TraceReader(self._trace_path)
        self._header = reader.open()
        if self._bst_base == 0 and self._header.bst_address:
            self._bst_base = self._header.bst_address

        if cache_events:
            self._events_cache = list(reader.iter_events())

        reader.close()
        return self._header

    @property
    def event_count(self) -> int:
        if self._events_cache is not None:
            return len(self._events_cache)
        return self._header.event_count if self._header else 0

    def _iter_events(self):
        """Iterate events from cache or file."""
        if self._events_cache is not None:
            yield from self._events_cache
            return
        reader = TraceReader(self._trace_path)
        reader.open()
        yield from reader.iter_events()
        reader.close()

    def find_first_bst_modification(self, offset: Optional[int] = None
                                     ) -> AnalysisResult:
        """
        Find the first BST modification.

        If offset is given, find the first modification to that specific
        BST entry. Otherwise find any BST modification.
        """
        target_addr = (self._bst_base + offset) if offset is not None else None

        for idx, event in enumerate(self._iter_events()):
            if event.event_type != TraceEventType.BST_ACCESS:
                continue
            if target_addr is not None and event.address != target_addr:
                continue

            bst_offset = event.address - self._bst_base if self._bst_base else event.address
            service_name = self.BST_OFFSETS.get(bst_offset, f"offset_0x{bst_offset:x}")

            return AnalysisResult(
                query=f"first_bst_modification(offset={offset})",
                found=True,
                event_index=idx,
                event=event,
                context_before=self._get_context(idx, before=5),
                context_after=self._get_context(idx, after=5),
                details={
                    "bst_offset": bst_offset,
                    "service_name": service_name,
                    "old_value": event.aux_data,
                    "new_value": event.value,
                    "modifying_pc": event.pc,
                },
            )

        return AnalysisResult(
            query=f"first_bst_modification(offset={offset})",
            found=False,
        )

    def find_all_bst_modifications(self) -> List[AnalysisResult]:
        """Find all BST modifications in the trace."""
        results = []
        for idx, event in enumerate(self._iter_events()):
            if event.event_type != TraceEventType.BST_ACCESS:
                continue

            bst_offset = event.address - self._bst_base if self._bst_base else event.address
            service_name = self.BST_OFFSETS.get(bst_offset, f"offset_0x{bst_offset:x}")

            results.append(AnalysisResult(
                query="all_bst_modifications",
                found=True,
                event_index=idx,
                event=event,
                details={
                    "bst_offset": bst_offset,
                    "service_name": service_name,
                    "old_value": event.aux_data,
                    "new_value": event.value,
                    "modifying_pc": event.pc,
                },
            ))
        return results

    def find_writes_to_address(self, address: int) -> List[AnalysisResult]:
        """Find all writes to a specific memory address."""
        results = []
        for idx, event in enumerate(self._iter_events()):
            if (event.event_type in (TraceEventType.MEMORY_WRITE,
                                     TraceEventType.BST_ACCESS) and
                    event.address == address):
                results.append(AnalysisResult(
                    query=f"writes_to_address(0x{address:x})",
                    found=True,
                    event_index=idx,
                    event=event,
                    details={
                        "value": event.value,
                        "pc": event.pc,
                    },
                ))
        return results

    def find_writes_from_pc(self, pc: int) -> List[AnalysisResult]:
        """Find all memory writes originating from a specific PC."""
        results = []
        for idx, event in enumerate(self._iter_events()):
            if (event.event_type in (TraceEventType.MEMORY_WRITE,
                                     TraceEventType.BST_ACCESS) and
                    event.pc == pc):
                results.append(AnalysisResult(
                    query=f"writes_from_pc(0x{pc:x})",
                    found=True,
                    event_index=idx,
                    event=event,
                    details={
                        "address": event.address,
                        "value": event.value,
                    },
                ))
        return results

    def find_instruction_at(self, pc: int) -> Optional[AnalysisResult]:
        """Find the first execution of an instruction at a given PC."""
        for idx, event in enumerate(self._iter_events()):
            if event.event_type == TraceEventType.INSTRUCTION and event.pc == pc:
                return AnalysisResult(
                    query=f"instruction_at(0x{pc:x})",
                    found=True,
                    event_index=idx,
                    event=event,
                    context_before=self._get_context(idx, before=3),
                    context_after=self._get_context(idx, after=3),
                )
        return AnalysisResult(
            query=f"instruction_at(0x{pc:x})",
            found=False,
        )

    def analyze_memory_region(self, base: int, size: int) -> MemoryRegionStats:
        """Analyze all writes to a memory region."""
        stats = MemoryRegionStats(base_address=base, size=size)
        end = base + size

        for idx, event in enumerate(self._iter_events()):
            if event.event_type not in (TraceEventType.MEMORY_WRITE,
                                        TraceEventType.BST_ACCESS):
                continue
            if not (base <= event.address < end):
                continue

            stats.write_count += 1
            stats.unique_pcs.add(event.pc)
            if stats.first_write_index == -1:
                stats.first_write_index = idx
            stats.last_write_index = idx
            stats.values_written.append((idx, event.address, event.value))

        return stats

    def find_hook_installation_sequence(self, bst_offset: int
                                         ) -> Dict:
        """
        Reconstruct the full hook installation sequence for a BST entry.

        Returns the modification event plus surrounding memory writes
        that likely constitute the trampoline/payload setup.
        """
        target_addr = self._bst_base + bst_offset
        modification = self.find_first_bst_modification(bst_offset)

        if not modification.found:
            return {"found": False, "bst_offset": bst_offset}

        mod_idx = modification.event_index
        hook_value = modification.event.value

        payload_writes = []
        window_start = max(0, mod_idx - 100)
        window_end = min(self.event_count, mod_idx + 50)

        events = list(self._iter_events())
        for idx in range(window_start, min(window_end, len(events))):
            ev = events[idx]
            if ev.event_type == TraceEventType.MEMORY_WRITE:
                if (hook_value <= ev.address < hook_value + 256 or
                        ev.pc == modification.event.pc):
                    payload_writes.append({
                        "index": idx,
                        "pc": ev.pc,
                        "address": ev.address,
                        "value": ev.value,
                    })

        service_name = self.BST_OFFSETS.get(bst_offset, f"offset_0x{bst_offset:x}")

        return {
            "found": True,
            "bst_offset": bst_offset,
            "service_name": service_name,
            "modification_index": mod_idx,
            "modifying_pc": modification.event.pc,
            "old_handler": modification.event.aux_data,
            "new_handler": hook_value,
            "payload_writes": payload_writes,
            "payload_size_estimate": len(payload_writes) * 8,
        }

    def compute_execution_profile(self) -> Dict:
        """Compute basic execution statistics from the trace."""
        event_counts = {}
        unique_pcs = set()
        bst_mods = 0
        first_bst_mod_idx = -1

        for idx, event in enumerate(self._iter_events()):
            etype = event.event_type.name
            event_counts[etype] = event_counts.get(etype, 0) + 1
            unique_pcs.add(event.pc)
            if event.event_type == TraceEventType.BST_ACCESS:
                bst_mods += 1
                if first_bst_mod_idx == -1:
                    first_bst_mod_idx = idx

        return {
            "total_events": self.event_count,
            "event_type_counts": event_counts,
            "unique_pcs": len(unique_pcs),
            "bst_modifications": bst_mods,
            "first_bst_modification_index": first_bst_mod_idx,
        }

    def _get_context(self, index: int, before: int = 0,
                     after: int = 0) -> List[TraceEvent]:
        """Get events surrounding a given index."""
        if self._events_cache is None:
            return []

        start = max(0, index - before)
        end = min(len(self._events_cache), index + after + 1)
        events = self._events_cache[start:end]
        if index - before >= 0:
            return [e for i, e in enumerate(events) if start + i != index]
        return [e for i, e in enumerate(events) if start + i != index]

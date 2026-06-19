"""
Live Detector - Adapts existing detectors for streaming/incremental analysis.

Bridges the introspection engine with the existing scanner detection
framework, allowing real-time detection as memory changes occur.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .event_stream import EventStream, EventType, IntrospectionEvent, Severity
from .memory_watch import ChangeType, MemoryChange, MemoryWatcher


@dataclass
class LiveFinding:
    """A finding from live detection analysis."""
    title: str
    severity: str
    description: str
    evidence: Dict = field(default_factory=dict)
    timestamp: float = 0.0
    detector: str = ""
    mitre_id: str = ""

    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "detector": self.detector,
            "mitre_id": self.mitre_id,
        }


class LiveDetector:
    """
    Real-time detector that analyzes memory changes as they occur.

    Applies heuristics to determine if changes represent:
    - BST hooking (function pointer replacement)
    - Code injection (shellcode in data regions)
    - Persistence mechanisms (FV/NVRAM writes)
    - Evasion techniques (self-modifying code)
    """

    # Trampoline patterns: hook -> redirect
    TRAMPOLINE_PATTERNS = {
        "mov_rax_jmp": (b'\x48\xb8', 10),  # MOV RAX, imm64; JMP RAX
        "push_ret": (b'\x68', 6),  # PUSH imm32; RET (but 64-bit needs more)
        "jmp_rip_rel": (b'\xff\x25', 6),  # JMP [RIP+offset]
        "call_rip_rel": (b'\xff\x15', 6),  # CALL [RIP+offset]
    }

    # Known legitimate BST pointer ranges (OVMF DXE core)
    LEGITIMATE_RANGES = [
        (0x7000000, 0x8000000),  # Typical OVMF DXE core range
        (0x6000000, 0x7000000),  # Extended DXE range
    ]

    def __init__(self, event_stream: Optional[EventStream] = None):
        self._event_stream = event_stream or EventStream()
        self._findings: List[LiveFinding] = []
        self._baseline_pointers: Dict[str, int] = {}
        self._hook_history: List[Dict] = []
        self._suspicious_regions: List[tuple] = []

    @property
    def findings(self) -> List[LiveFinding]:
        return list(self._findings)

    def set_baseline(self, bst_pointers: Dict[str, int]) -> None:
        """Set the known-good BST pointer baseline."""
        self._baseline_pointers = dict(bst_pointers)

    def analyze_memory_change(self, change: MemoryChange) -> Optional[LiveFinding]:
        """Analyze a memory change and produce findings."""
        if change.change_type == ChangeType.POINTER_MODIFIED:
            return self._analyze_pointer_hook(change)
        elif change.change_type == ChangeType.CODE_INJECTED:
            return self._analyze_code_injection(change)
        elif change.change_type == ChangeType.DATA_WRITTEN:
            return self._analyze_data_write(change)
        return None

    def analyze_event(self, event: IntrospectionEvent) -> Optional[LiveFinding]:
        """Analyze an introspection event for malicious patterns."""
        if event.event_type == EventType.BST_HOOK_INSTALLED:
            return self._analyze_bst_hook_event(event)
        elif event.event_type == EventType.CODE_INJECTION:
            return LiveFinding(
                title="Code Injection Detected",
                severity="critical",
                description=event.description,
                evidence=event.details,
                timestamp=event.timestamp,
                detector="live_code_injection",
                mitre_id="T1542.001",
            )
        return None

    def check_trampoline(self, data: bytes, address: int) -> Optional[LiveFinding]:
        """Check if bytes at an address form a trampoline/hook."""
        for name, (pattern, min_size) in self.TRAMPOLINE_PATTERNS.items():
            if len(data) >= min_size and data[:len(pattern)] == pattern:
                target = self._extract_trampoline_target(data, name)
                finding = LiveFinding(
                    title=f"Trampoline Detected ({name})",
                    severity="high",
                    description=(
                        f"Hook trampoline at {address:#x} using {name} "
                        f"pattern, target: {target:#x}"
                    ),
                    evidence={
                        "address": f"{address:#x}",
                        "pattern": name,
                        "target": f"{target:#x}",
                        "bytes": data[:min_size].hex(),
                    },
                    timestamp=time.time(),
                    detector="live_trampoline",
                    mitre_id="T1574.013",
                )
                self._findings.append(finding)
                return finding
        return None

    def get_summary(self) -> Dict:
        """Get detection summary."""
        severity_counts = {}
        for f in self._findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "total_findings": len(self._findings),
            "by_severity": severity_counts,
            "hooks_detected": len(self._hook_history),
            "baseline_set": bool(self._baseline_pointers),
        }

    def _analyze_pointer_hook(self, change: MemoryChange) -> Optional[LiveFinding]:
        """Analyze a pointer modification for hooking behavior."""
        func_name = MemoryWatcher.BST_OFFSETS.get(change.offset, "")
        new_ptr = change.new_value_int
        old_ptr = change.old_value_int

        # Check if new pointer is outside legitimate ranges
        is_suspicious = not any(
            start <= new_ptr <= end for start, end in self.LEGITIMATE_RANGES
        )

        if not is_suspicious and func_name:
            # Check against baseline if available
            if func_name in self._baseline_pointers:
                if new_ptr != self._baseline_pointers[func_name]:
                    is_suspicious = True

        if is_suspicious and func_name:
            self._hook_history.append({
                "function": func_name,
                "old": old_ptr,
                "new": new_ptr,
                "time": change.timestamp,
            })

            finding = LiveFinding(
                title=f"BST Hook: {func_name}",
                severity="critical" if func_name in EventStream.HIGH_VALUE_BST_HOOKS else "high",
                description=(
                    f"Boot Services Table function '{func_name}' hooked: "
                    f"pointer changed from {old_ptr:#x} to {new_ptr:#x} "
                    f"(outside legitimate code range)"
                ),
                evidence={
                    "function": func_name,
                    "old_pointer": f"{old_ptr:#x}",
                    "new_pointer": f"{new_ptr:#x}",
                    "offset": f"{change.offset:#x}",
                    "legitimate_ranges": [
                        f"{s:#x}-{e:#x}" for s, e in self.LEGITIMATE_RANGES
                    ],
                },
                timestamp=change.timestamp,
                detector="live_bst_hook",
                mitre_id="T1542.001",
            )
            self._findings.append(finding)
            return finding

        return None

    def _analyze_code_injection(self, change: MemoryChange) -> Optional[LiveFinding]:
        """Analyze code injection in a memory region."""
        # Check for common shellcode patterns
        new_data = change.new_value
        patterns_found = []

        for name, (pattern, _) in self.TRAMPOLINE_PATTERNS.items():
            if pattern in new_data:
                patterns_found.append(name)

        # Check for NOP sleds
        nop_count = sum(1 for b in new_data if b == 0x90)
        if nop_count > 8:
            patterns_found.append("nop_sled")

        finding = LiveFinding(
            title="Code Injection in Runtime Memory",
            severity="critical",
            description=(
                f"Executable code written to {change.address:#x} "
                f"in region '{change.region_name}'. "
                f"Patterns: {', '.join(patterns_found) or 'raw code'}"
            ),
            evidence={
                "address": f"{change.address:#x}",
                "region": change.region_name,
                "patterns": patterns_found,
                "bytes_hex": new_data[:32].hex(),
                "size": len(new_data),
            },
            timestamp=change.timestamp,
            detector="live_code_injection",
            mitre_id="T1055.012",
        )
        self._findings.append(finding)
        return finding

    def _analyze_data_write(self, change: MemoryChange) -> Optional[LiveFinding]:
        """Analyze general data writes for suspicious patterns."""
        # Only flag large writes to monitored regions
        if len(change.new_value) < 32:
            return None

        # Check for PE header being written (MZ magic)
        if change.new_value[:2] == b'MZ':
            finding = LiveFinding(
                title="PE Image Written to Memory",
                severity="high",
                description=(
                    f"PE/COFF image written at {change.address:#x} "
                    f"in region '{change.region_name}'"
                ),
                evidence={
                    "address": f"{change.address:#x}",
                    "region": change.region_name,
                    "magic": "MZ",
                },
                timestamp=change.timestamp,
                detector="live_pe_injection",
                mitre_id="T1542.001",
            )
            self._findings.append(finding)
            return finding

        return None

    def _analyze_bst_hook_event(self, event: IntrospectionEvent) -> Optional[LiveFinding]:
        """Analyze a BST hook event from the event stream."""
        func_name = event.details.get("function", "unknown")
        new_ptr = event.details.get("new_pointer", "0x0")

        finding = LiveFinding(
            title=f"Real-time BST Hook: {func_name}",
            severity="critical",
            description=event.description,
            evidence=event.details,
            timestamp=event.timestamp,
            detector="live_event_bst_hook",
            mitre_id="T1542.001",
        )
        self._findings.append(finding)
        return finding

    @staticmethod
    def _extract_trampoline_target(data: bytes, pattern_name: str) -> int:
        """Extract the target address from a trampoline."""
        if pattern_name == "mov_rax_jmp" and len(data) >= 10:
            return struct.unpack_from('<Q', data, 2)[0]
        elif pattern_name == "push_ret" and len(data) >= 5:
            return struct.unpack_from('<I', data, 1)[0]
        elif pattern_name in ("jmp_rip_rel", "call_rip_rel") and len(data) >= 6:
            offset = struct.unpack_from('<i', data, 2)[0]
            return offset  # Relative offset, caller needs to add PC+6
        return 0

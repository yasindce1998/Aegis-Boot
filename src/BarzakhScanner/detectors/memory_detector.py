"""
Memory Detector - Runtime Memory Analysis

Detects bootkit artifacts in memory dumps by identifying suspicious
allocations, hook trampolines, and persistence mechanisms.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import re
import struct
from typing import Dict, List, Optional, Tuple
from pathlib import Path

try:
    import ahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    HAS_AHOCORASICK = False


class MemoryDetector:
    """Detector for memory-resident bootkit artifacts."""

    # UEFI memory type constants
    MEMORY_TYPES = {
        0: "EfiReservedMemoryType",
        1: "EfiLoaderCode",
        2: "EfiLoaderData",
        3: "EfiBootServicesCode",
        4: "EfiBootServicesData",
        5: "EfiRuntimeServicesCode",
        6: "EfiRuntimeServicesData",
        7: "EfiConventionalMemory",
        8: "EfiUnusableMemory",
        9: "EfiACPIReclaimMemory",
        10: "EfiACPIMemoryNVS",
        11: "EfiMemoryMappedIO",
        12: "EfiMemoryMappedIOPortSpace",
        13: "EfiPalCode"
    }

    # Suspicious instruction patterns (x86_64)
    HOOK_PATTERNS = [
        (b'\x48\xb8', 'MOV RAX, imm64 (absolute jump setup)'),
        (b'\xff\xe0', 'JMP RAX (indirect jump)'),
        (b'\xe9', 'JMP rel32 (relative jump)'),
        (b'\xeb', 'JMP rel8 (short jump)'),
        (b'\x48\x89\x44\x24', 'MOV [RSP+offset], RAX (stack manipulation)'),
        (b'\x48\x83\xec', 'SUB RSP, imm8 (stack allocation)'),
        (b'\xc3', 'RET (return instruction)')
    ]

    def __init__(self, baseline: Optional[Dict] = None):
        """
        Initialize memory detector.

        Args:
            baseline: Baseline memory layout for comparison
        """
        self.baseline = baseline
        self.findings = []
        
        # Build Aho-Corasick automaton for pattern matching
        if HAS_AHOCORASICK:
            try:
                self.automaton = ahocorasick.Automaton()
                for pattern, description in self.HOOK_PATTERNS:
                    self.automaton.add_word(pattern, (pattern, description))
                self.automaton.make_automaton()
            except TypeError:
                self.automaton = None
        else:
            self.automaton = None

    def detect(self, target_path: str) -> List[Dict]:
        """
        Analyze memory dump for bootkit artifacts.

        Args:
            target_path: Path to memory dump

        Returns:
            List of findings
        """
        self.findings = []

        # Load memory dump
        memory_data = self._load_memory_dump(target_path)
        
        if not memory_data:
            self.findings.append({
                'detector': 'memory',
                'severity': 'medium',
                'title': 'Unable to load memory dump',
                'description': f'Could not read memory dump from {target_path}',
                'recommendation': 'Verify file format and accessibility'
            })
            return self.findings

        # Scan for suspicious allocations
        self._scan_runtime_allocations(memory_data)

        # Scan for hook trampolines
        self._scan_hook_trampolines(memory_data)

        # Scan for hidden code sections
        self._scan_hidden_code(memory_data)

        # Check for persistence mechanisms
        self._check_persistence_mechanisms(memory_data)

        # Scan for known bootkit signatures
        self._scan_bootkit_signatures(memory_data)

        return self.findings

    def _load_memory_dump(self, target_path: str) -> Optional[bytes]:
        """
        Load memory dump from file.

        Args:
            target_path: Path to memory dump

        Returns:
            Memory data or None
        """
        target = Path(target_path)
        
        if not target.exists():
            return None

        try:
            with open(target, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"[WARNING] Failed to load memory dump: {e}")
            return None

    def _scan_runtime_allocations(self, memory_data: bytes):
        """
        Scan for suspicious runtime memory allocations.

        Args:
            memory_data: Raw memory dump
        """
        # Look for EfiRuntimeServicesCode allocations (type 5)
        # These survive OS transition and are prime bootkit targets
        
        # Search for memory map entries
        # Format: Type(4) + PhysicalStart(8) + VirtualStart(8) + NumberOfPages(8) + Attribute(8)
        entry_size = 36
        
        for offset in range(0, len(memory_data) - entry_size, 4):
            try:
                mem_type = struct.unpack('<I', memory_data[offset:offset+4])[0]
                
                if mem_type == 5:  # EfiRuntimeServicesCode
                    phys_start = struct.unpack('<Q', memory_data[offset+4:offset+12])[0]
                    num_pages = struct.unpack('<Q', memory_data[offset+20:offset+28])[0]
                    size = num_pages * 4096
                    
                    # Check if allocation is suspicious
                    if self._is_suspicious_allocation(phys_start, size):
                        self.findings.append({
                            'detector': 'memory',
                            'severity': 'high',
                            'title': 'Suspicious runtime memory allocation',
                            'description': f'Found EfiRuntimeServicesCode allocation at 0x{phys_start:x} '
                                         f'({size} bytes) that may indicate bootkit persistence.',
                            'details': {
                                'address': f'0x{phys_start:x}',
                                'size': size,
                                'type': 'EfiRuntimeServicesCode'
                            },
                            'recommendation': 'Analyze allocation contents for malicious code'
                        })
            except (struct.error, ValueError, IndexError) as e:
                # Handle specific parsing errors gracefully
                continue

    def _is_suspicious_allocation(self, address: int, size: int) -> bool:
        """
        Determine if memory allocation is suspicious.

        Args:
            address: Physical address
            size: Allocation size

        Returns:
            True if suspicious
        """
        # Check against baseline
        if self.baseline and 'memory_map' in self.baseline:
            for entry in self.baseline['memory_map']:
                if entry['address'] == address and entry['size'] == size:
                    return False  # Known allocation

        # Suspicious if small runtime allocation (typical for hooks)
        if size < 8192:  # Less than 2 pages
            return True

        # Suspicious if at unusual address
        if address > 0x100000000:  # Above 4GB
            return True

        return False

    def _scan_hook_trampolines(self, memory_data: bytes):
        """
        Scan for hook trampoline code patterns using Aho-Corasick.

        Args:
            memory_data: Raw memory dump
        """
        if self.automaton:
            # Use Aho-Corasick for O(n) multi-pattern matching
            for offset, (pattern, description) in self.automaton.iter(memory_data):
                # Adjust offset to start of pattern
                offset = offset - len(pattern) + 1
                
                # Extract surrounding context
                context_start = max(0, offset - 16)
                context_end = min(len(memory_data), offset + 32)
                context = memory_data[context_start:context_end]

                # Check if this looks like a hook trampoline
                if self._is_hook_trampoline(context):
                    self.findings.append({
                        'detector': 'memory',
                        'severity': 'high',
                        'title': 'Potential hook trampoline detected',
                        'description': f'Found instruction pattern at offset 0x{offset:x} '
                                     f'matching hook trampoline: {description}',
                        'details': {
                            'offset': f'0x{offset:x}',
                            'pattern': pattern.hex(),
                            'context': context.hex(),
                            'description': description
                        },
                        'recommendation': 'Analyze surrounding code for hook implementation'
                    })
        else:
            # Fallback to naive O(n*m) search if Aho-Corasick unavailable
            for pattern, description in self.HOOK_PATTERNS:
                offset = 0
                while True:
                    offset = memory_data.find(pattern, offset)
                    if offset == -1:
                        break

                    # Extract surrounding context
                    context_start = max(0, offset - 16)
                    context_end = min(len(memory_data), offset + 32)
                    context = memory_data[context_start:context_end]

                    # Check if this looks like a hook trampoline
                    if self._is_hook_trampoline(context):
                        self.findings.append({
                            'detector': 'memory',
                            'severity': 'high',
                            'title': 'Potential hook trampoline detected',
                            'description': f'Found instruction pattern at offset 0x{offset:x} '
                                         f'matching hook trampoline: {description}',
                            'details': {
                                'offset': f'0x{offset:x}',
                                'pattern': pattern.hex(),
                                'context': context.hex(),
                                'description': description
                            },
                            'recommendation': 'Analyze surrounding code for hook implementation'
                        })

                    offset += 1

    def _is_hook_trampoline(self, code: bytes) -> bool:
        """
        Determine if code sequence is a hook trampoline.

        Args:
            code: Code bytes

        Returns:
            True if likely a trampoline
        """
        # Look for common trampoline patterns:
        # 1. Save registers
        # 2. Jump to handler
        # 3. Restore registers
        # 4. Jump to original

        # Check for register saves (PUSH instructions)
        push_count = code.count(b'\x50') + code.count(b'\x51') + code.count(b'\x52')
        
        # Check for jumps
        has_jump = b'\xe9' in code or b'\xff\xe0' in code or b'\xeb' in code

        # Check for returns
        has_ret = b'\xc3' in code

        return push_count >= 2 and has_jump and has_ret

    def _scan_hidden_code(self, memory_data: bytes):
        """
        Scan for hidden executable code sections.

        Args:
            memory_data: Raw memory dump
        """
        # Look for PE headers in unexpected locations
        pe_signature = b'MZ'
        offset = 0
        
        while True:
            offset = memory_data.find(pe_signature, offset)
            if offset == -1:
                break

            # Check if this is a valid PE header
            if offset + 64 < len(memory_data):
                try:
                    e_lfanew = struct.unpack('<I', memory_data[offset+60:offset+64])[0]
                    
                    if offset + e_lfanew + 4 < len(memory_data):
                        pe_sig = memory_data[offset+e_lfanew:offset+e_lfanew+4]
                        
                        if pe_sig == b'PE\x00\x00':
                            self.findings.append({
                                'detector': 'memory',
                                'severity': 'critical',
                                'title': 'Hidden PE executable detected',
                                'description': f'Found PE executable at offset 0x{offset:x} '
                                             'which may be injected bootkit payload.',
                                'details': {
                                    'offset': f'0x{offset:x}',
                                    'signature': 'PE'
                                },
                                'recommendation': 'Extract and analyze PE file for malicious code'
                            })
                except:
                    pass

            offset += 1

    def _check_persistence_mechanisms(self, memory_data: bytes):
        """
        Check for bootkit persistence mechanisms.

        Args:
            memory_data: Raw memory dump
        """
        # Look for UEFI variable manipulation
        var_patterns = [
            (b'BootOrder', 'Boot order manipulation'),
            (b'Boot0', 'Boot entry modification'),
            (b'SecureBoot', 'Secure Boot tampering'),
            (b'PK', 'Platform Key modification'),
            (b'KEK', 'Key Exchange Key modification')
        ]

        for pattern, description in var_patterns:
            if pattern in memory_data:
                offset = memory_data.find(pattern)
                self.findings.append({
                    'detector': 'memory',
                    'severity': 'high',
                    'title': f'UEFI variable access detected: {pattern.decode()}',
                    'description': f'Found reference to {pattern.decode()} variable at offset 0x{offset:x}. '
                                 f'This may indicate {description}.',
                    'details': {
                        'offset': f'0x{offset:x}',
                        'variable': pattern.decode(),
                        'threat': description
                    },
                    'recommendation': 'Verify UEFI variable integrity and check for unauthorized modifications'
                })

    def _scan_bootkit_signatures(self, memory_data: bytes):
        """
        Scan for known bootkit signatures.

        Args:
            memory_data: Raw memory dump
        """
        # Known bootkit signatures
        signatures = {
            'barzakh_dxe': (b'BARZAKH_DXE_INJECT', 'Barzakh DXE injection module'),
            'barzakh_hook': (b'BARZAKH_HOOK', 'Barzakh hook handler'),
            'barzakh_persist': (b'BARZAKH_PERSIST', 'Barzakh persistence mechanism')
        }

        for sig_name, (pattern, description) in signatures.items():
            if pattern in memory_data:
                offset = memory_data.find(pattern)
                self.findings.append({
                    'detector': 'memory',
                    'severity': 'critical',
                    'title': f'Known bootkit signature: {sig_name}',
                    'description': f'Detected {description} at offset 0x{offset:x}',
                    'details': {
                        'signature': sig_name,
                        'offset': f'0x{offset:x}',
                        'pattern': pattern.hex()
                    },
                    'recommendation': 'System is infected with known bootkit. Immediate remediation required.'
                })



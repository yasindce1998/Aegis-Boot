#!/usr/bin/env python3
"""
Synthetic Test Corpus Generator

Generates benign and malicious firmware samples for testing detection accuracy.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import json
import struct
import hashlib
import random
import os
from pathlib import Path
from typing import Dict, List
from datetime import datetime


class CorpusGenerator:
    """Generator for synthetic firmware test samples."""
    
    # UEFI signatures
    FV_SIGNATURE = b'_FVH'
    BST_SIGNATURE = 0x56524553544f4f42  # "BOOTSERV"
    
    def __init__(self, output_dir: str = "tests/corpus"):
        """Initialize corpus generator."""
        self.output_dir = Path(output_dir)
        self.benign_dir = self.output_dir / "benign"
        self.malicious_dir = self.output_dir / "malicious"
        self.manifest = []
        
        # Create directories
        self.benign_dir.mkdir(parents=True, exist_ok=True)
        self.malicious_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_all(self):
        """Generate complete test corpus."""
        print("[*] Generating synthetic test corpus...")
        
        # Benign samples
        self._generate_benign_samples()
        
        # Malicious samples
        self._generate_malicious_samples()
        
        # Save manifest
        self._save_manifest()
        
        print(f"[+] Generated {len(self.manifest)} samples")
        print(f"[+] Corpus saved to {self.output_dir}")
    
    def _generate_benign_samples(self):
        """Generate benign firmware samples."""
        print("[*] Generating benign samples...")
        
        # 1. Valid FV with normal BST
        self._create_sample(
            "benign_valid_fv_bst.bin",
            "benign",
            self._build_valid_firmware(),
            "Valid firmware volume with unmodified Boot Services Table"
        )
        
        # 2. Normal entropy firmware
        self._create_sample(
            "benign_normal_entropy.bin",
            "benign",
            self._build_normal_entropy_firmware(),
            "Firmware with normal entropy distribution"
        )
        
        # 3. Valid TPM event log
        self._create_sample(
            "benign_tpm_eventlog.bin",
            "benign",
            self._build_valid_eventlog(),
            "Valid TPM event log with correct PCR values"
        )
        
        # 4. Clean memory dump
        self._create_sample(
            "benign_memory_dump.bin",
            "benign",
            self._build_clean_memory(),
            "Clean memory dump without suspicious allocations"
        )
    
    def _generate_malicious_samples(self):
        """Generate malicious firmware samples."""
        print("[*] Generating malicious samples...")
        
        # 1. Hooked BST
        self._create_sample(
            "malicious_hooked_bst.bin",
            "malicious",
            self._build_hooked_bst(),
            "Boot Services Table with hooked function pointers",
            threat_type="hook"
        )
        
        # 2. High entropy (packed/encrypted)
        self._create_sample(
            "malicious_high_entropy.bin",
            "malicious",
            self._build_high_entropy_firmware(),
            "Firmware with suspiciously high entropy (packed malware)",
            threat_type="entropy"
        )
        
        # 3. Tampered PCRs
        self._create_sample(
            "malicious_tampered_pcrs.bin",
            "malicious",
            self._build_tampered_pcrs(),
            "TPM event log with PCR mismatches",
            threat_type="pcr_tampering"
        )
        
        # 4. Trampoline injection
        self._create_sample(
            "malicious_trampoline.bin",
            "malicious",
            self._build_trampoline_injection(),
            "Memory with trampoline code injection",
            threat_type="code_injection"
        )
        
        # 5. Truncated event log
        self._create_sample(
            "malicious_truncated_eventlog.bin",
            "malicious",
            self._build_truncated_eventlog(),
            "Truncated TPM event log (log manipulation)",
            threat_type="log_tampering"
        )
        
        # 6. Suspicious runtime allocation
        self._create_sample(
            "malicious_runtime_alloc.bin",
            "malicious",
            self._build_suspicious_runtime_alloc(),
            "Suspicious EfiRuntimeServicesCode allocation",
            threat_type="memory_manipulation"
        )
    
    def _build_valid_firmware(self) -> bytes:
        """Build valid firmware volume with BST."""
        data = bytearray(0x10000)  # 64KB
        
        # Add FV header
        offset = 0x1000
        data[offset:offset+4] = self.FV_SIGNATURE
        struct.pack_into('<Q', data, offset+32, 0x8000)  # FV length
        
        # Add valid BST
        bst_offset = 0x5000
        struct.pack_into('<Q', data, bst_offset, self.BST_SIGNATURE)
        
        # Add function pointers (valid addresses)
        for i in range(10):
            struct.pack_into('<Q', data, bst_offset + 8 + i*8, 0x7FF00000 + i*0x1000)
        
        return bytes(data)
    
    def _build_normal_entropy_firmware(self) -> bytes:
        """Build firmware with normal entropy."""
        data = bytearray(0x10000)
        
        # Mix of code, data, and padding (entropy ~4-6)
        for i in range(0, len(data), 256):
            if i % 1024 < 512:
                # Code-like pattern
                data[i:i+256] = bytes([random.randint(0, 255) for _ in range(128)]) + b'\x00' * 128
            else:
                # Data pattern
                data[i:i+256] = bytes([i % 256] * 256)
        
        return bytes(data)
    
    def _build_valid_eventlog(self) -> bytes:
        """Build valid TPM event log."""
        events = bytearray()
        
        # PCR 0 events
        for i in range(3):
            event = self._create_event(0, f"Event_{i}".encode(), b'\x00' * 32)
            events.extend(event)
        
        # EV_SEPARATOR
        events.extend(self._create_event(0, b'\xFF\xFF\xFF\xFF', b'\x00' * 32))
        
        return bytes(events)
    
    def _build_clean_memory(self) -> bytes:
        """Build clean memory dump."""
        data = bytearray(0x100000)  # 1MB
        
        # Normal memory patterns
        for i in range(0, len(data), 0x1000):
            data[i:i+8] = struct.pack('<Q', 0x7FF00000 + i)
        
        return bytes(data)
    
    def _build_hooked_bst(self) -> bytes:
        """Build BST with hooked pointers."""
        data = bytearray(0x10000)
        
        # Add BST
        bst_offset = 0x5000
        struct.pack_into('<Q', data, bst_offset, self.BST_SIGNATURE)
        
        # Add hooked function pointers (suspicious addresses)
        for i in range(10):
            if i == 3:  # Hook AllocatePool
                struct.pack_into('<Q', data, bst_offset + 8 + i*8, 0xDEADBEEF)
            else:
                struct.pack_into('<Q', data, bst_offset + 8 + i*8, 0x7FF00000 + i*0x1000)
        
        return bytes(data)
    
    def _build_high_entropy_firmware(self) -> bytes:
        """Build firmware with high entropy (encrypted/packed)."""
        # Random data (entropy ~8.0)
        return bytes([random.randint(0, 255) for _ in range(0x10000)])
    
    def _build_tampered_pcrs(self) -> bytes:
        """Build event log with PCR mismatches."""
        events = bytearray()
        
        # Events that don't match PCR replay
        for i in range(3):
            event = self._create_event(0, f"Event_{i}".encode(), bytes([i] * 32))
            events.extend(event)
        
        return bytes(events)
    
    def _build_trampoline_injection(self) -> bytes:
        """Build memory with trampoline code."""
        data = bytearray(0x10000)
        
        # Add trampoline pattern (JMP instruction)
        offset = 0x5000
        data[offset:offset+5] = b'\xE9\x00\x10\x00\x00'  # JMP +0x1000
        
        return bytes(data)
    
    def _build_truncated_eventlog(self) -> bytes:
        """Build truncated event log."""
        events = bytearray()
        
        # Only 1 event (suspicious)
        event = self._create_event(0, b"Event_0", b'\x00' * 32)
        events.extend(event)
        
        return bytes(events)
    
    def _build_suspicious_runtime_alloc(self) -> bytes:
        """Build memory with suspicious runtime allocation."""
        data = bytearray(0x100000)
        
        # Large EfiRuntimeServicesCode allocation at unusual address
        offset = 0x80000
        data[offset:offset+0x10000] = bytes([0x90] * 0x10000)  # NOP sled
        
        return bytes(data)
    
    def _create_event(self, pcr: int, event_data: bytes, digest: bytes) -> bytes:
        """Create TPM event structure."""
        event = bytearray()
        event.extend(struct.pack('<I', pcr))
        event.extend(struct.pack('<I', 0x0B))  # Event type
        event.extend(digest)
        event.extend(struct.pack('<I', len(event_data)))
        event.extend(event_data)
        return bytes(event)
    
    def _create_sample(self, filename: str, category: str, data: bytes,
                      description: str, threat_type: str | None = None):
        """Create and save a sample."""
        if category == "benign":
            filepath = self.benign_dir / filename
        else:
            filepath = self.malicious_dir / filename
        
        # Write sample
        with open(filepath, 'wb') as f:
            f.write(data)
        
        # Calculate hash
        sha256 = hashlib.sha256(data).hexdigest()
        
        # Add to manifest
        entry = {
            "filename": filename,
            "category": category,
            "description": description,
            "sha256": sha256,
            "size": len(data),
            "created": datetime.now().isoformat()
        }
        
        if threat_type:
            entry["threat_type"] = threat_type
        
        self.manifest.append(entry)
        print(f"  [+] Created {filename} ({len(data)} bytes)")
    
    def _save_manifest(self):
        """Save corpus manifest."""
        manifest_path = self.output_dir / "corpus_manifest.json"
        
        with open(manifest_path, 'w') as f:
            json.dump({
                "generated": datetime.now().isoformat(),
                "total_samples": len(self.manifest),
                "benign_count": sum(1 for s in self.manifest if s["category"] == "benign"),
                "malicious_count": sum(1 for s in self.manifest if s["category"] == "malicious"),
                "samples": self.manifest
            }, f, indent=2)
        
        print(f"[+] Manifest saved to {manifest_path}")


def main():
    """Main entry point."""
    generator = CorpusGenerator()
    generator.generate_all()
    print("\n[+] Corpus generation complete!")


if __name__ == "__main__":
    main()



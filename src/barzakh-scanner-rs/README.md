# Barzakh Scanner

High-performance UEFI bootkit detection engine written in Rust.

Barzakh Scanner analyzes firmware images, memory dumps, and boot measurements to detect bootkit artifacts with high accuracy and minimal false positives. It implements 60 specialized detectors covering the full spectrum of firmware-level threats across x86_64, AArch64, and RISC-V architectures — from Ring 0 (UEFI DXE) down through Ring -4 (CPU microarchitecture).

## Detection Capabilities

### Core Detectors

| Detector | Technique | Targets |
|----------|-----------|---------|
| PCR Analysis | TPM measurement comparison | Tampered boot measurements |
| PCR Replay | Event log reconstruction | Forged PCR values |
| PCR Oracle | Statistical anomaly detection | Subtle measurement drift |
| Memory Scanner | Runtime memory analysis | Injected PE images in EfiRuntimeServicesCode |
| Hook Detection | Boot Services table inspection | Modified function pointers |
| Runtime Hooks | Runtime Services monitoring | Post-ExitBootServices persistence |
| Firmware Volume | FV structure validation | Malicious DXE driver injection |
| Firmware Differ | Binary diff against baseline | Unauthorized firmware modifications |
| Entropy Analysis | Shannon entropy profiling | Packed/encrypted payloads |
| Event Log | TCG event sequence analysis | Anomalous boot sequences |
| Secure Boot | Signature chain validation | Bypassed/disabled Secure Boot |
| SMM Detection | SMI handler analysis | SMM-based rootkits |
| SPI Integrity | Flash region verification | SPI flash persistence (LoJax-style) |
| MBR/VBR | Legacy boot sector analysis | MBR/VBR infectors |
| Introspection | Code flow analysis | Trampolines and code injection |
| Self-Erasure | Anti-forensics detection | Evidence destruction patterns |
| Symbolic Execution | Path constraint solving | Obfuscated trigger conditions |
| Time-Travel Debug | Execution trace replay | Hidden execution paths |

### Intel ME / Management Engine

| Detector | Technique | Targets |
|----------|-----------|---------|
| HECI Traffic | HECI/MEI command analysis | Suspicious host-ME communication |
| ME SPI Region | ME region structure validation | Tampered ME firmware partitions |
| AMT/SOL | AMT provisioning state inspection | Unauthorized remote management |
| fTPM Integrity | TPM2 command stream analysis | Forged fTPM responses |

### Platform Security

| Detector | Technique | Targets |
|----------|-----------|---------|
| AMD PSP | PSP directory/entry validation | Tampered AMD Platform Security Processor firmware |
| Intel Boot Guard | ACM/KM/BPM structure analysis | Boot Guard policy bypass, SVN rollback |
| Auth Variable | Authenticated variable validation | PK/KEK/db rollback, missing signatures |

### Boot Process Integrity

| Detector | Technique | Targets |
|----------|-----------|---------|
| LogoFAIL | BMP/image parser overflow detection | Malicious logo images triggering CVE-2023-40238 |
| PixieFail | DHCPv6/PXE option validation | Network boot stack exploits (CVE-2023-45229+) |
| BlackLotus | MOK/BCD manipulation detection | BlackLotus bootkit persistence |
| DXE Dispatcher | DEPEX section analysis | DXE load-order hijacking via dependency manipulation |
| PEI Implant | PEI Core/PEIM structure validation | Pre-EFI initialization phase rootkits |
| Capsule Update | Capsule header integrity checks | Firmware update mechanism abuse |

### Hardware/Bus Attacks

| Detector | Technique | Targets |
|----------|-----------|---------|
| CXL Device | CXL DVSEC/DMA range analysis | CXL.mem DMA attacks against system memory |
| Attestation | Remote attestation validation | Forged attestation evidence |
| Live Forensics | Runtime state analysis | Active bootkit indicators |

### ARM / TrustZone

| Detector | Technique | Targets |
|----------|-----------|---------|
| ARM TrustZone | OP-TEE TA header / SMC call / IMG4 analysis | TrustZone persistence, iBoot chain bypass |
| ARM TBBR | FIP header / NV counter / CoT hash validation | Trusted Board Boot chain-of-trust bypass |

### RISC-V

| Detector | Technique | Targets |
|----------|-----------|---------|
| OpenSBI | SBI extension table / mtvec / M-mode CSR analysis | OpenSBI firmware hooking, privilege escalation |
| PMP Bypass | PMP config / CSR write / NOP sled detection | Physical Memory Protection misconfiguration exploits |

### Ring -4 / CPU Microarchitecture

| Detector | Technique | Targets |
|----------|-----------|---------|
| Microcode Injection | Intel MCU header / AMD equiv table analysis | Malicious CPU microcode updates in firmware |
| Spectre Gadgets | Indirect branch / CLFLUSH+RDTSC / barrier removal detection | Speculative execution side-channel gadgets |
| Thermal Covert | RAPL MSR / thermal throttle / P-state modulation analysis | Thermal/power covert channel patterns |
| Voltage Glitch | MSR 0x150 / DVFS / PMIC I2C write detection | Plundervolt/CLKscrew voltage fault injection |
| Debug Interface | DCI enable / JTAG TAP / DAP unlock / HDC MSR analysis | Unauthorized debug port exploitation |
| Rowhammer | CLFLUSH loop / TRR bypass / refresh suppression detection | Rowhammer exploitation patterns |

### 2024-2026 Threat Detectors

| Detector | Technique | Targets |
|----------|-----------|---------|
| Linux Bootchain | GRUB NOP-sled / vmlinuz integrity analysis | Bootkitty-style Linux UEFI bootkits |
| Reloader | PE-in-PE / signed loader exploitation | CVE-2024-7344 reloader.efi bypass |
| SBAT | SBAT generation counter validation | Secure Boot Advanced Targeting rollback |
| ESP Integrity | FAT32 / EFI bootloader path analysis | ESP partition persistence rootkits |
| Confidential VM | TDVF/SEV-SNP measurement validation | TDX injection, VMPL confusion attacks |
| BMC SPI | IPMI KCS / Redfish SPI targeting | BMC-to-host lateral movement |
| HTTP Boot | HTTP response + embedded PE detection | UEFI HTTP Boot MITM attacks |
| TPM Command | TPM2 command buffer size validation | CVE-2023-1017/1018 buffer overflow |
| WiFi DXE | Intel CNVi device / DXE dep-ex analysis | Wireless firmware DXE injection |
| Pluton | Pluton mailbox / DICE attestation analysis | Microsoft Pluton interception attacks |

## Installation

```bash
# Build from source
cd src/barzakh-scanner-rs
cargo build --release

# Binary outputs at:
#   target/release/barzakh-scanner    (defensive: scan, baseline, report, validate, detectors, info)
#   target/release/barzakh-adversary  (offensive: generate, list, corpus, validate, qemu, esp)
```

## Usage

### barzakh-scanner (Defensive)

```bash
# Scan a firmware image
barzakh-scanner scan --target firmware.bin

# Scan with baseline comparison
barzakh-scanner scan --target firmware.bin --baseline baseline.json

# Generate HTML report
barzakh-scanner report --target firmware.bin --format html --output report.html

# Run specific detectors only
barzakh-scanner scan --target dump.bin --scan-types pcr,memory,hook

# Validate detectors against test corpus
barzakh-scanner validate --corpus test-data/

# List all available detectors
barzakh-scanner detectors

# Show platform and build info
barzakh-scanner info
```

### barzakh-adversary (Offensive)

```bash
# List all 55 available payloads
barzakh-adversary list

# Generate payloads for a specific architecture
barzakh-adversary generate --arch x86_64

# Generate full test corpus (malicious + clean pairs)
barzakh-adversary corpus --output ./corpus

# Validate corpus against scanner (measure TPR/FPR)
barzakh-adversary validate --corpus ./corpus

# Boot a payload in QEMU for live testing
barzakh-adversary qemu --payload trampoline

# Build ESP image for hardware testing
barzakh-adversary esp --payload dxe_persistence
```

## Architecture

```
barzakh-scanner-rs/
├── Cargo.toml                    # Workspace root
└── crates/
    ├── barzakh-core/             # Library crate (detection engine)
    │   ├── src/
    │   │   ├── lib.rs            # Public API
    │   │   ├── scanner.rs        # Scan orchestration
    │   │   ├── baseline.rs       # Baseline configuration
    │   │   ├── detector.rs       # Detector trait + types
    │   │   ├── detectors/        # 60 detection modules
    │   │   └── reports/          # HTML/JSON/Markdown reports
    │   └── tests/
    │       └── scanner_integration.rs
    ├── barzakh-cli/              # Binary crate (produces `barzakh-scanner` + `barzakh-adversary`)
    │   └── src/
    │       ├── main.rs           # Scanner CLI (defensive commands)
    │       └── adversary_main.rs # Adversary CLI (offensive commands)
    └── barzakh-adversary/        # Red-team payload generator
        ├── src/
        │   ├── lib.rs            # Payload trait + public API
        │   ├── payloads/         # 55 payload generators
        │   ├── validate/         # Scanner invocation + result comparison
        │   ├── corpus.rs         # Malicious/clean pair generator
        │   └── deploy/           # ESP image builder + QEMU orchestration (WIP)
        └── tests/
            └── integration.rs    # Generate → scan → assert detection
```

## Detection Metrics

| Metric | Target |
|--------|--------|
| True Positive Rate | >= 85% |
| False Positive Rate | < 5% |
| ROC-AUC | >= 0.92 |
| Mean Time to Detect | < 500ms |

## Development

```bash
# Run tests (22 integration + unit tests)
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy -- -D warnings

# Security audit
cargo audit
```

## CI/CD

The workspace is gated by four CI jobs on every push:

- **Build Rust Scanner** — release build verification
- **Test Rust Scanner** — fmt + clippy + full test suite
- **Adversary Red-Team Tests** — payload generation + scanner detection validation + corpus E2E
- **Security Audit (Rust)** — dependency vulnerability scan via `cargo-audit`

## License

BSD-2-Clause-Patent

# Barzakh Scanner

High-performance UEFI bootkit detection engine written in Rust.

Barzakh Scanner analyzes firmware images, memory dumps, and boot measurements to detect bootkit artifacts with high accuracy and minimal false positives. It implements 43 specialized detectors covering the full spectrum of firmware-level threats across x86_64, AArch64, and RISC-V architectures.

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

### RISC-V

| Detector | Technique | Targets |
|----------|-----------|---------|
| OpenSBI | SBI extension table / mtvec / M-mode CSR analysis | OpenSBI firmware hooking, privilege escalation |
| PMP Bypass | PMP config / CSR write / NOP sled detection | Physical Memory Protection misconfiguration exploits |

## Installation

```bash
# Build from source
cd src/barzakh-scanner-rs
cargo build --release

# Binary output at target/release/barzakh-scanner
```

## Usage

```bash
# Scan a firmware image
barzakh-scanner --target firmware.bin

# Scan with baseline comparison
barzakh-scanner --target firmware.bin --baseline baseline.json

# Generate HTML report
barzakh-scanner --target firmware.bin --report --format html --output report.html

# Run specific detectors only
barzakh-scanner --target dump.bin --scan-types pcr,memory,hook

# Validate against test corpus
barzakh-scanner --target firmware.bin --validate --corpus test-data/
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
    │   │   ├── detectors/        # 43 detection modules
    │   │   └── reports/          # HTML/JSON/Markdown reports
    │   └── tests/
    │       └── scanner_integration.rs
    ├── barzakh-cli/              # Binary crate (produces `barzakh-scanner`)
    │   └── src/main.rs           # CLI interface (clap)
    └── barzakh-adversary/        # Red-team payload generator
        ├── src/
        │   ├── lib.rs            # Payload trait + public API
        │   ├── payloads/         # 33 payload generators
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

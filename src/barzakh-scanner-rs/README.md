# Barzakh Scanner

High-performance UEFI bootkit detection engine written in Rust.

Barzakh Scanner analyzes firmware images, memory dumps, and boot measurements to detect bootkit artifacts with high accuracy and minimal false positives. It implements 18 specialized detectors covering the full spectrum of firmware-level threats.

## Detection Capabilities

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

## Installation

```bash
# Build from source
cd src/barzakh-scanner-rs
cargo build --release

# Binary output at target/release/barzakh-cli
```

## Usage

```bash
# Scan a firmware image
barzakh-cli --target firmware.bin

# Scan with baseline comparison
barzakh-cli --target firmware.bin --baseline baseline.json

# Generate HTML report
barzakh-cli --target firmware.bin --report --format html --output report.html

# Run specific detectors only
barzakh-cli --target dump.bin --scan-types pcr,memory,hook

# Validate against test corpus
barzakh-cli --target firmware.bin --validate --corpus test-data/
```

## Architecture

```
barzakh-scanner-rs/
├── Cargo.toml                    # Workspace root
└── crates/
    ├── barzakh-core/             # Library crate
    │   ├── src/
    │   │   ├── lib.rs            # Public API
    │   │   ├── scanner.rs        # Scan orchestration
    │   │   ├── baseline.rs       # Baseline configuration
    │   │   ├── detector.rs       # Detector trait + types
    │   │   ├── detectors/        # 18 detection modules
    │   │   └── reports/          # HTML/JSON/Markdown reports
    │   └── tests/
    │       └── scanner_integration.rs
    └── barzakh-cli/              # Binary crate
        └── src/main.rs           # CLI interface (clap)
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

The scanner is gated by three CI jobs on every push:

- **Build Rust Scanner** — release build verification
- **Test Rust Scanner** — fmt + clippy + full test suite
- **Security Audit (Rust)** — dependency vulnerability scan via `cargo-audit`

## License

BSD-2-Clause-Patent

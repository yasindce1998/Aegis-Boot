# Project Barzakh

**⚠️ ACADEMIC RESEARCH PROJECT - DEFENSIVE SECURITY ONLY ⚠️**

A production-ready UEFI bootkit research platform for studying firmware-level security threats and defenses.

## ⚖️ Legal & Ethical Notice

This project is developed **strictly for academic research purposes** under institutional oversight:

- ✅ Must operate in air-gapped, virtualized environments only
- ✅ Contains multiple hardware-rooted kill-switches preventing unauthorized execution
- ❌ NOT for weaponization, deployment, or malicious use
- ❌ Violating these constraints may result in legal consequences

**By accessing this repository, you agree to use it solely for legitimate security research and educational purposes.**

## 📋 Project Overview

Barzakh safely models Tactics, Techniques, and Procedures (TTPs) from known in-the-wild bootkits to:
- Validate Measured Boot integrity against UEFI execution tampering
- Develop robust detection capabilities (Barzakh-Scanner)
- Produce peer-reviewed academic research on defensive methodologies

### Reference Adversaries
- **BlackLotus** (CVE-2023-24932): Secure Boot bypass via vulnerable bootloaders
- **CosmicStrand/FinSpy**: Firmware persistence via DXE driver implantation
- **Lojax**: SPI flash persistence surviving OS reinstalls

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Firmware (SEC/PEI) → DXE Phase → Barzakhkit Hooks       │
│  → Boot Device Selection → OS Bootloader                    │
│  → ExitBootServices Intercept → TPM Attestation             │
│  → OS Kernel (Infection Complete)                           │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

1. **BootkitPkg** (Offensive Emulation)
   - DXE phase driver injection
   - Boot Services table hooking
   - ExitBootServices interception
   - MSR hooking for stealth emulation

2. **AttestationPkg** (Defensive Telemetry)
   - TPM PCR querying [0, 2, 4, 7]
   - TCG Event Log extraction
   - Ground truth data generation

3. **Barzakh Scanner** (Detection Engine — Rust)
   - 18 specialized detectors for bootkit artifact detection
   - Target: ≥85% TPR, <5% FPR, ROC-AUC ≥0.92
   - See [`src/barzakh-scanner-rs/README.md`](src/barzakh-scanner-rs/README.md)

## 🔒 Security Safeguards

### Hardware-Rooted Kill-Switches
- **UUID Binding**: Cryptographically bound to whitelisted SMBIOS UUIDs
- **TPM EK Pinning**: Bound to specific TPM Endorsement Keys
- **Time-Bomb**: Hardcoded expiry date enforcement
- **Air-Gap**: No network connectivity in test environment

### Operational Security
- QEMU + OVMF virtualization only (no bare metal)
- Append-only GPG-signed audit logs
- AES-256 encrypted cold storage
- No pre-compiled binaries in repository
- All commits must be GPG-signed

## 🛠️ Technology Stack

| Component | Technology |
|-----------|-----------|
| Development Kit | EDK II (UEFI Development Kit) |
| Languages | C11 (EDK II), Rust (Scanner) |
| Virtualization | QEMU + KVM + OVMF |
| Security Module | TPM 2.0 (swtpm) |
| Guest OS | Windows 10/11, Ubuntu Linux |

## 📁 Repository Structure

```
barzakh/
├── docs/
│   ├── SETUP.md                    # Environment setup guide
│   ├── ARCHITECTURE.md             # Technical architecture
│   └── TESTING.md                  # Testing strategy
├── src/
│   ├── BootkitPkg/                 # UEFI bootkit emulation
│   │   ├── DxeInject/              # DXE phase injection + kill-switches
│   │   └── ExitBootHook/           # ExitBootServices interception
│   ├── AttestationPkg/             # TPM attestation & telemetry
│   │   ├── TpmAttestation/         # PCR monitoring
│   │   └── EventLogExtractor/      # TCG event log parsing
│   └── barzakh-scanner-rs/           # Detection engine (Rust)
│       ├── crates/barzakh-core/    # Library: 18 detectors + reports
│       └── crates/barzakh-cli/     # CLI binary
├── scripts/
│   ├── build.sh                    # EDK II compilation
│   ├── qemu-run.sh                 # QEMU test harness with vTPM
│   ├── nvram-recovery.py           # NVRAM backup/restore
│   ├── audit-log.sh                # GPG-signed audit logging
│   └── validate-environment.sh     # Pre-flight checks
├── tests/                          # Test suite
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   └── corpus/                     # Test corpus samples
├── .github/workflows/              # CI/CD pipeline
├── CONTRIBUTING.md
└── SECURITY.md
```

## 🚀 Quick Start

### Prerequisites

1. **Hardware Requirements**
   - Air-gapped lab environment or isolated VLAN
   - Dedicated test machines with TPM 2.0
   - Minimum 16GB RAM, 100GB storage

3. **Software Requirements**
   - Linux host (Ubuntu 22.04+ recommended)
   - QEMU 7.0+ with KVM support
   - EDK II development environment
   - swtpm (software TPM emulator)
   - Rust toolchain (stable)
   - GCC 11+ or Clang 14+

### Environment Setup

1. **Clone EDK II and dependencies**
   ```bash
   # See docs/SETUP.md for detailed instructions
   git clone https://github.com/tianocore/edk2.git
   cd edk2
   git checkout edk2-stable202405  # Pinned version
   git submodule update --init --recursive
   ```

2. **Build OVMF**
   ```bash
   # Configure EDK II environment
   source edksetup.sh
   
   # Build OVMF with TPM support
   build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc -D TPM2_ENABLE=TRUE
   ```

3. **Setup Barzakh**
   ```bash
   cd /path/to/barzakh
   
   # Configure environment variables
   export WORKSPACE=/path/to/edk2
   export PACKAGES_PATH=$WORKSPACE:$(pwd)/src
   
   # Run pre-flight checks
   ./scripts/validate-environment.sh
   ```

## 🧪 Usage

### Building the Bootkit (Research Only)
```bash
# Build all UEFI packages
./scripts/build.sh

# This creates:
# - BootkitPkg DXE drivers
# - AttestationPkg modules
# - Signed artifacts with SBOM
```

### Running in Test Environment
```bash
# Launch QEMU with vTPM and bootkit
./scripts/qemu-run.sh

# Features:
# - Air-gap enforcement
# - vTPM integration
# - Audit logging
# - NVRAM snapshots
```

### Using Barzakh Scanner
```bash
# Build the scanner
cd src/barzakh-scanner-rs
cargo build --release

# Scan a firmware/memory dump
./target/release/barzakh-cli --target /path/to/firmware.bin --report --format html --output report.html

# With baseline comparison
./target/release/barzakh-cli --target firmware.bin --baseline baseline.json --report

# Run specific detectors
./target/release/barzakh-cli --target firmware.bin --scan-types pcr,memory,hook
```

### Running Tests
```bash
# Run scanner tests
cd src/barzakh-scanner-rs
cargo test

# Check formatting & lint
cargo fmt --check
cargo clippy -- -D warnings

# Security audit
cargo audit
```

## 📊 Detection Targets

| Metric | Target |
|--------|--------|
| True Positive Rate (TPR) | ≥85% |
| False Positive Rate (FPR) | <5% |
| ROC-AUC | ≥0.92 |
| Mean Time to Detect | <500ms |

## 📝 Documentation

- [`docs/SETUP.md`](docs/SETUP.md) - Environment setup instructions
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - System architecture
- [`docs/TESTING.md`](docs/TESTING.md) - Testing strategy
- [`src/barzakh-scanner-rs/README.md`](src/barzakh-scanner-rs/README.md) - Scanner documentation
- [`tests/README.md`](tests/README.md) - Test suite guide
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - Contribution guidelines
- [`SECURITY.md`](SECURITY.md) - Security policy

## 🤝 Contributing

This is a controlled research project. Contributions are limited to:
- Authorized researchers on the project team
- Institutional collaborators with signed agreements
- Peer reviewers during academic publication process

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for detailed guidelines.

## 📜 License

This project is released under a restrictive academic research license. See [`LICENSE`](LICENSE) for details.

**Key restrictions:**
- Academic and educational use only
- No commercial use
- No weaponization or malicious deployment
- Must maintain all safety mechanisms
- Must comply with institutional oversight

## 🔐 Responsible Disclosure

If you discover a novel vulnerability during research:
1. **Immediate embargo** - Do not disclose publicly
2. **Notify Principal Investigator** within 24 hours
3. **90-day coordinated disclosure** to affected vendors
4. See [`SECURITY.md`](SECURITY.md) for full procedure

## 📞 Contact

**Principal Investigator:** Yasin  
**Institution:** Dead Lock Corp 
**Email:** yasindce1998@gmail.com

**For vulnerability reports:** security@deadlockcorp.edu

## ⚠️ Disclaimer

This software is provided for academic research purposes only. The authors and affiliated institutions:
- Make no warranties regarding fitness for any purpose
- Accept no liability for misuse or unauthorized deployment
- Require strict adherence to institutional oversight and legal frameworks
- Reserve the right to terminate access for policy violations

**USE AT YOUR OWN RISK. UNAUTHORIZED USE MAY VIOLATE LAWS.**

---

## 🎓 Research Contributions

This project models real-world threats including BlackLotus (CVE-2023-24932), CosmicStrand, LoJax, MoonBounce, and MosaicRegressor. Key research contributions:

- PCR replay algorithm for TPM attestation validation
- FV-based detection to reduce false positives
- Automated CI/CD pipeline for bootkit research
- Ground truth validation framework using test corpus


# Project Aegis-Boot

**⚠️ ACADEMIC RESEARCH PROJECT - DEFENSIVE SECURITY ONLY ⚠️**

A controlled, white-hat UEFI bootkit simulation environment for academic research and defensive detection engineering.

## ⚖️ Legal & Ethical Notice

This project is developed **strictly for academic research purposes** under institutional oversight:

- ✅ Requires formal IRB (Institutional Review Board) approval before execution
- ✅ Must operate in air-gapped, virtualized environments only
- ✅ Contains multiple hardware-rooted kill-switches preventing unauthorized execution
- ❌ NOT for weaponization, deployment, or malicious use
- ❌ Violating these constraints may result in legal consequences

**By accessing this repository, you agree to use it solely for legitimate security research and educational purposes.**

## 📋 Project Overview

Aegis-Boot safely models Tactics, Techniques, and Procedures (TTPs) from known in-the-wild bootkits to:
- Validate Measured Boot integrity against UEFI execution tampering
- Develop robust detection capabilities (Aegis-Scanner)
- Produce peer-reviewed academic research on defensive methodologies

### Reference Adversaries
- **BlackLotus** (CVE-2023-24932): Secure Boot bypass via vulnerable bootloaders
- **CosmicStrand/FinSpy**: Firmware persistence via DXE driver implantation
- **Lojax**: SPI flash persistence surviving OS reinstalls

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Firmware (SEC/PEI) → DXE Phase → Aegis-Bootkit Hooks      │
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

3. **AegisScanner** (Detection Engine)
   - Bootkit artifact detection
   - Target: ≥85% TPR, <5% FPR
   - ROC-AUC ≥0.92

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
| Languages | C11, NASM Assembly |
| Virtualization | QEMU + KVM + OVMF |
| Security Module | TPM 2.0 (swtpm) |
| Guest OS | Windows 10/11, Ubuntu Linux |

## 📁 Repository Structure

```
aegis-boot/
├── docs/                           # Documentation
│   ├── IMPLEMENTATION_COMPLETE.md  # Complete implementation details
│   ├── SETUP.md                    # Environment setup guide
│   ├── technical_details.md        # Technical architecture
│   ├── testing.md                  # Testing strategy
│   └── audit/                      # Immutable execution logs
├── src/
│   ├── BootkitPkg/                 # UEFI bootkit emulation
│   │   ├── DxeInject/              # DXE phase injection + kill-switches
│   │   └── ExitBootHook/           # ExitBootServices interception
│   ├── AttestationPkg/             # TPM attestation & telemetry
│   │   ├── TpmAttestation/         # PCR monitoring
│   │   └── EventLogExtractor/      # TCG event log parsing
│   └── AegisScanner/               # Detection engine (Python)
│       ├── scanner.py              # Main scanner
│       ├── detectors/              # Detection modules
│       │   ├── pcr_detector.py     # PCR analysis
│       │   ├── memory_detector.py  # Memory artifact detection
│       │   ├── hook_detector.py    # Boot Services hook detection
│       │   └── eventlog_detector.py # Event log forensics
│       └── reports/                # Report generation
├── scripts/
│   ├── build.sh                    # EDK II compilation + SBOM
│   ├── qemu-run.sh                 # QEMU test harness with vTPM
│   ├── nvram-recovery.py           # NVRAM backup/restore
│   ├── audit-log.sh                # GPG-signed audit logging
│   └── validate-environment.sh     # Pre-flight checks
├── tests/                          # Test suite
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   ├── run_tests.py                # Test runner
│   └── requirements.txt            # Test dependencies
├── .gitignore
├── .env.example
├── README.md
├── QUICKSTART.md
├── CONTRIBUTING.md
└── SECURITY.md
```

## 🚀 Quick Start

### Prerequisites

**⚠️ STOP: Do not proceed without IRB approval ⚠️**

1. **Legal Clearance**
   - Formal IRB/ethics committee approval
   - Signed institutional agreements
   - Legal counsel review

2. **Hardware Requirements**
   - Air-gapped lab environment or isolated VLAN
   - Dedicated test machines with TPM 2.0
   - Minimum 16GB RAM, 100GB storage

3. **Software Requirements**
   - Linux host (Ubuntu 22.04+ recommended)
   - QEMU 7.0+ with KVM support
   - EDK II development environment
   - swtpm (software TPM emulator)
   - Python 3.10+
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

3. **Setup Aegis-Boot**
   ```bash
   cd /path/to/aegis-boot
   
   # Configure environment variables
   export WORKSPACE=/path/to/edk2
   export PACKAGES_PATH=$WORKSPACE:$(pwd)/src
   
   # Run setup script
   ./scripts/setup-environment.sh
   ```

4. **Validate Environment**
   ```bash
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

### Using AegisScanner
```bash
# Scan a firmware/memory dump
cd src/AegisScanner
python scanner.py --target /path/to/firmware.bin --report --output report.html

# With baseline comparison
python scanner.py --target firmware.bin --baseline baseline.json --report

# Validate against test corpus
python scanner.py --validate --corpus /path/to/corpus
```

### Running Tests
```bash
# Run all tests
cd tests
python run_tests.py --coverage

# Run specific test suites
python run_tests.py --unit          # Unit tests only
python run_tests.py --integration   # Integration tests only
python run_tests.py --corpus        # Corpus validation
```

## 📊 Project Statistics

| Component | Files | Lines of Code | Status |
|-----------|-------|---------------|--------|
| **BootkitPkg** | 8 | 1,224 | ✅ Complete |
| **AttestationPkg** | 6 | 837 | ✅ Complete |
| **AegisScanner** | 10 | 2,299 | ✅ Complete |
| **Test Suite** | 7 | 532 | ✅ Complete |
| **Scripts** | 5 | 1,957 | ✅ Complete |
| **Documentation** | 8 | 2,100+ | ✅ Complete |
| **TOTAL** | **50** | **9,099+** | ✅ Complete |

### Detection Performance Targets

| Metric | Target | Description |
|--------|--------|-------------|
| True Positive Rate | ≥85% | Detect 85%+ of bootkits |
| False Positive Rate | <5% | False alarms <5% |
| ROC-AUC | ≥0.90 | Excellent discrimination |
| Scan Time | <30s | Per sample analysis |

## 📝 Documentation

- [`README.md`](README.md) - This file (project overview)
- [`QUICKSTART.md`](QUICKSTART.md) - Quick start guide
- [`docs/IMPLEMENTATION_COMPLETE.md`](docs/IMPLEMENTATION_COMPLETE.md) - Complete implementation details
- [`docs/SETUP.md`](docs/SETUP.md) - Detailed setup instructions
- [`docs/technical_details.md`](docs/technical_details.md) - Technical architecture
- [`docs/testing.md`](docs/testing.md) - Testing strategy
- [`src/AegisScanner/README.md`](src/AegisScanner/README.md) - Scanner documentation
- [`tests/README.md`](tests/README.md) - Test suite guide
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - Contribution guidelines
- [`SECURITY.md`](SECURITY.md) - Security policy

## 🤝 Contributing

This is a controlled research project. Contributions are limited to:
- IRB-approved researchers
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
**Institution:** [Insert Institution/Organization]  
**Email:** [Insert Contact Email]

**For vulnerability reports:** security@[institution].edu  
**For IRB inquiries:** irb@[institution].edu

## ⚠️ Disclaimer

This software is provided for academic research purposes only. The authors and affiliated institutions:
- Make no warranties regarding fitness for any purpose
- Accept no liability for misuse or unauthorized deployment
- Require strict adherence to institutional oversight and legal frameworks
- Reserve the right to terminate access for policy violations

**USE AT YOUR OWN RISK. UNAUTHORIZED USE MAY VIOLATE LAWS.**

---

**Version:** 1.0.0  
**Last Updated:** May 11, 2026  
**Status:** Development - Pending IRB Approval
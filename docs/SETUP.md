# Aegis-Boot: Detailed Environment Setup Guide

**⚠️ PREREQUISITE: This guide assumes you have obtained formal IRB approval and legal clearance. Do not proceed without proper authorization. ⚠️**

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Pre-Installation Checklist](#pre-installation-checklist)
3. [EDK II Environment Setup](#edk-ii-environment-setup)
4. [OVMF Build Configuration](#ovmf-build-configuration)
5. [QEMU and vTPM Setup](#qemu-and-vtpm-setup)
6. [Aegis-Boot Package Configuration](#aegis-boot-package-configuration)
7. [Verification and Testing](#verification-and-testing)
8. [Troubleshooting](#troubleshooting)

---

## 1. System Requirements

### Hardware Requirements
- **CPU**: x86_64 with hardware virtualization support (Intel VT-x or AMD-V)
- **RAM**: Minimum 16GB (32GB recommended for parallel testing)
- **Storage**: 100GB free space (SSD recommended)
- **Network**: Air-gapped environment or isolated VLAN (NO internet access during testing)
- **TPM**: Physical TPM 2.0 on host (optional but recommended)

### Software Requirements
- **OS**: Linux (Ubuntu 22.04 LTS or 24.04 LTS recommended)
- **Kernel**: 5.15+ with KVM support
- **QEMU**: Version 7.0 or later
- **Python**: 3.10 or later
- **GCC**: 11.0 or later (or Clang 14+)
- **Git**: 2.30 or later with GPG signing capability
- **Build Tools**: make, nasm, iasl, uuid-dev

### Verification Commands
```bash
# Check CPU virtualization support
egrep -c '(vmx|svm)' /proc/cpuinfo  # Should return > 0

# Check KVM availability
lsmod | grep kvm  # Should show kvm_intel or kvm_amd

# Check QEMU version
qemu-system-x86_64 --version  # Should be >= 7.0

# Check Python version
python3 --version  # Should be >= 3.10

# Check GCC version
gcc --version  # Should be >= 11.0
```

---

## 2. Pre-Installation Checklist

### Legal and Compliance
- [ ] IRB approval obtained and documented
- [ ] Legal counsel review completed
- [ ] Institutional agreements signed
- [ ] Air-gapped lab environment prepared
- [ ] Audit logging infrastructure ready
- [ ] Data retention policy documented
- [ ] Decommissioning plan approved

### Technical Preparation
- [ ] Dedicated test machine(s) identified
- [ ] SMBIOS UUIDs documented for binding
- [ ] TPM Endorsement Keys recorded
- [ ] Project expiry date determined
- [ ] GPG keys generated for commit signing
- [ ] Ed25519 keys generated for artifact signing
- [ ] Encrypted cold storage volume prepared

### Team Readiness
- [ ] Principal Investigator assigned
- [ ] Information Security Officer notified
- [ ] Infrastructure Lead designated
- [ ] All personnel completed ethics training
- [ ] Emergency contact list prepared

---

## 3. EDK II Environment Setup

### 3.1 Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    uuid-dev \
    iasl \
    git \
    nasm \
    python3-distutils \
    python3-pip \
    gcc-multilib \
    g++-multilib \
    qemu-system-x86 \
    qemu-utils \
    ovmf \
    swtpm \
    swtpm-tools \
    libtool \
    autoconf \
    automake \
    pkg-config \
    libglib2.0-dev \
    libpixman-1-dev \
    libssl-dev \
    gpg
```

**Fedora/RHEL:**
```bash
sudo dnf install -y \
    @development-tools \
    libuuid-devel \
    acpica-tools \
    git \
    nasm \
    python3-devel \
    gcc \
    gcc-c++ \
    qemu-system-x86 \
    qemu-img \
    edk2-ovmf \
    swtpm \
    swtpm-tools \
    libtool \
    autoconf \
    automake \
    pkgconfig \
    glib2-devel \
    pixman-devel \
    openssl-devel \
    gnupg2
```

### 3.2 Clone and Configure EDK II

```bash
# Create workspace directory
mkdir -p ~/aegis-workspace
cd ~/aegis-workspace

# Clone EDK II repository
git clone https://github.com/tianocore/edk2.git
cd edk2

# Checkout pinned stable version (CRITICAL: Use exact version for reproducibility)
git checkout edk2-stable202405
PINNED_COMMIT=$(git rev-parse HEAD)
echo "EDK II Pinned Commit: $PINNED_COMMIT" > ../edk2-version.txt

# Initialize submodules
git submodule update --init --recursive

# Verify submodule integrity
git submodule status
```

### 3.3 Build EDK II BaseTools

```bash
cd ~/aegis-workspace/edk2

# Set up EDK II environment
export WORKSPACE=$(pwd)
export PACKAGES_PATH=$WORKSPACE
source edksetup.sh BaseTools

# Build BaseTools
make -C BaseTools

# Verify BaseTools
ls -la BaseTools/Source/C/bin/
# Should show: GenFfs, GenFv, GenFw, GenSec, etc.
```

### 3.4 Configure Build Environment

Create `~/aegis-workspace/edk2/Conf/target.txt` with the following settings:

```ini
ACTIVE_PLATFORM       = OvmfPkg/OvmfPkgX64.dsc
TARGET                = DEBUG
TARGET_ARCH           = X64
TOOL_CHAIN_TAG        = GCC5
BUILD_RULE_CONF       = Conf/build_rule.txt
```

---

## 4. OVMF Build Configuration

### 4.1 Build OVMF with TPM Support

```bash
cd ~/aegis-workspace/edk2
source edksetup.sh

# Build OVMF with TPM 2.0 and Secure Boot support
build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc \
    -D TPM2_ENABLE=TRUE \
    -D SECURE_BOOT_ENABLE=TRUE \
    -D SMM_REQUIRE=TRUE \
    -D DEBUG_ON_SERIAL_PORT=TRUE

# Verify build artifacts
ls -lh Build/OvmfX64/DEBUG_GCC5/FV/
# Should show: OVMF_CODE.fd, OVMF_VARS.fd, OVMF.fd
```

### 4.2 Create OVMF Backup and SBOM

```bash
# Create backup directory
mkdir -p ~/aegis-workspace/ovmf-builds/$(date +%Y%m%d)

# Copy build artifacts
cp Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd \
   ~/aegis-workspace/ovmf-builds/$(date +%Y%m%d)/

cp Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd \
   ~/aegis-workspace/ovmf-builds/$(date +%Y%m%d)/

# Generate SBOM (Software Bill of Materials)
cat > ~/aegis-workspace/ovmf-builds/$(date +%Y%m%d)/SBOM.txt <<EOF
Build Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
EDK II Version: edk2-stable202405
EDK II Commit: $(git rev-parse HEAD)
GCC Version: $(gcc --version | head -n1)
Build Configuration:
  - TPM2_ENABLE=TRUE
  - SECURE_BOOT_ENABLE=TRUE
  - SMM_REQUIRE=TRUE
  - DEBUG_ON_SERIAL_PORT=TRUE
Build Artifacts:
  - OVMF_CODE.fd: $(sha256sum Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd | cut -d' ' -f1)
  - OVMF_VARS.fd: $(sha256sum Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd | cut -d' ' -f1)
EOF

cat ~/aegis-workspace/ovmf-builds/$(date +%Y%m%d)/SBOM.txt
```

---

## 5. QEMU and vTPM Setup

### 5.1 Verify QEMU Installation

```bash
# Check QEMU version and capabilities
qemu-system-x86_64 --version
qemu-system-x86_64 -machine help | grep q35
qemu-system-x86_64 -device help | grep tpm

# Verify KVM support
ls -l /dev/kvm
# Should show: crw-rw---- 1 root kvm
```

### 5.2 Configure vTPM (Software TPM)

```bash
# Create vTPM state directory
mkdir -p ~/aegis-workspace/vtpm-state

# Initialize vTPM
swtpm socket \
    --tpmstate dir=~/aegis-workspace/vtpm-state \
    --ctrl type=unixio,path=~/aegis-workspace/vtpm-state/swtpm-sock \
    --tpm2 \
    --log level=20 &

# Verify vTPM is running
ps aux | grep swtpm
netstat -an | grep swtpm-sock
```

### 5.3 Test QEMU with OVMF and vTPM

```bash
# Create test disk image
qemu-img create -f qcow2 ~/aegis-workspace/test-disk.qcow2 20G

# Test boot (should reach UEFI shell)
qemu-system-x86_64 \
    -machine q35,smm=on,accel=kvm \
    -cpu host \
    -m 4096 \
    -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file=~/aegis-workspace/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=~/aegis-workspace/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd \
    -drive file=~/aegis-workspace/test-disk.qcow2,if=virtio,format=qcow2 \
    -chardev socket,id=chrtpm,path=~/aegis-workspace/vtpm-state/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -serial stdio \
    -nographic

# You should see UEFI boot messages and reach the UEFI Shell
# Type 'exit' to quit
```

---

## 6. Aegis-Boot Package Configuration

### 6.1 Clone Aegis-Boot Repository

```bash
cd ~/aegis-workspace
git clone <aegis-boot-repo-url> aegis-boot
cd aegis-boot

# Verify repository structure
ls -la
# Should show: docs/, src/, scripts/, test/, README.md, etc.
```

### 6.2 Configure Environment Variables

Create `~/aegis-workspace/aegis-boot/.env`:

```bash
# EDK II Workspace
export WORKSPACE=~/aegis-workspace/edk2
export PACKAGES_PATH=$WORKSPACE:~/aegis-workspace/aegis-boot/src
export EDK_TOOLS_PATH=$WORKSPACE/BaseTools

# Build Configuration
export TARGET=DEBUG
export TARGET_ARCH=X64
export TOOL_CHAIN_TAG=GCC5

# OVMF Paths
export OVMF_CODE=~/aegis-workspace/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd
export OVMF_VARS=~/aegis-workspace/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd

# vTPM Configuration
export VTPM_STATE_DIR=~/aegis-workspace/vtpm-state

# Security Configuration (CRITICAL: Set these values)
export AEGIS_ALLOWED_UUID="00000000-0000-0000-0000-000000000000"  # Replace with actual UUID
export AEGIS_EXPIRY_DATE="2027-05-11"  # Replace with actual expiry
export IRB_APPROVAL_DATE="2026-05-11"  # Replace with actual IRB date

# Audit Logging
export AUDIT_LOG_DIR=~/aegis-workspace/aegis-boot/docs/audit
export AUDIT_LOG_ENCRYPTION_KEY=~/aegis-workspace/keys/audit-key.gpg
```

### 6.3 Generate Security Keys

```bash
# Generate GPG key for commit signing
gpg --full-generate-key
# Follow prompts: RSA and RSA, 4096 bits, no expiration

# Generate Ed25519 key for artifact signing
ssh-keygen -t ed25519 -f ~/aegis-workspace/keys/artifact-signing-key -C "aegis-boot-artifacts"

# Configure Git to use GPG signing
git config --global user.signingkey <YOUR_GPG_KEY_ID>
git config --global commit.gpgsign true
```

### 6.4 Document Hardware Bindings

```bash
# Get SMBIOS UUID from test machine
sudo dmidecode -s system-uuid

# Get TPM EK public key (if physical TPM available)
sudo tpm2_readpublic -c 0x81010001 -o /tmp/ek.pub
sha256sum /tmp/ek.pub

# Document these values in docs/HARDWARE_BINDINGS.md
cat > ~/aegis-workspace/aegis-boot/docs/HARDWARE_BINDINGS.md <<EOF
# Hardware Bindings for Aegis-Boot

**CONFIDENTIAL - DO NOT DISTRIBUTE**

## Authorized Test Machines

### Machine 1: Primary Test Rig
- **SMBIOS UUID**: $(sudo dmidecode -s system-uuid)
- **TPM EK SHA256**: $(sha256sum /tmp/ek.pub | cut -d' ' -f1)
- **Location**: Lab Room [REDACTED]
- **Authorized Personnel**: [REDACTED]

## Expiry Configuration
- **Project Start**: 2026-05-11
- **IRB Approval Date**: 2026-05-11
- **Project Expiry**: 2027-05-11
- **Data Retention End**: 2029-05-11

## Emergency Contacts
- **Principal Investigator**: [REDACTED]
- **Information Security Officer**: [REDACTED]
- **IRB Chair**: [REDACTED]
EOF
```

---

## 7. Verification and Testing

### 7.1 Environment Validation Script

Create and run the validation script:

```bash
cd ~/aegis-workspace/aegis-boot
./scripts/validate-environment.sh
```

Expected output:
```
✓ EDK II workspace found
✓ BaseTools compiled
✓ OVMF binaries present
✓ QEMU version >= 7.0
✓ KVM support available
✓ vTPM configured
✓ GPG signing configured
✓ Artifact signing keys present
✓ Environment variables set
✓ IRB approval date valid
```

### 7.2 Build Test

```bash
# Source environment
source ~/aegis-workspace/aegis-boot/.env
source $WORKSPACE/edksetup.sh

# Attempt a test build (will fail until packages are implemented)
cd ~/aegis-workspace/aegis-boot
./scripts/build.sh --dry-run
```

---

## 8. Troubleshooting

### Common Issues

#### Issue: "KVM not available"
```bash
# Solution: Enable KVM module
sudo modprobe kvm
sudo modprobe kvm_intel  # or kvm_amd for AMD CPUs

# Add user to kvm group
sudo usermod -aG kvm $USER
# Log out and back in
```

#### Issue: "OVMF build fails"
```bash
# Solution: Clean and rebuild
cd ~/aegis-workspace/edk2
rm -rf Build/
source edksetup.sh
make -C BaseTools clean
make -C BaseTools
build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc -D TPM2_ENABLE=TRUE
```

#### Issue: "vTPM socket not found"
```bash
# Solution: Restart swtpm
pkill swtpm
rm -rf ~/aegis-workspace/vtpm-state/*
swtpm socket \
    --tpmstate dir=~/aegis-workspace/vtpm-state \
    --ctrl type=unixio,path=~/aegis-workspace/vtpm-state/swtpm-sock \
    --tpm2 \
    --log level=20 &
```

#### Issue: "Permission denied on /dev/kvm"
```bash
# Solution: Fix permissions
sudo chmod 666 /dev/kvm
# Or add user to kvm group (preferred)
sudo usermod -aG kvm $USER
```

---

## Next Steps

After completing this setup:

1. ✅ Verify all checklist items are complete
2. ✅ Document hardware bindings
3. ✅ Test QEMU boot with OVMF and vTPM
4. ➡️ Proceed to implementing BootkitPkg (see `docs/IMPLEMENTATION.md`)
5. ➡️ Configure audit logging (see `scripts/audit-log.sh`)
6. ➡️ Set up CI/CD pipeline (see `docs/CI_CD.md`)

---

**Last Updated:** May 11, 2026  
**Maintainer:** Principal Investigator  
**Review Cycle:** Monthly or upon major EDK II updates
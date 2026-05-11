# Aegis-Boot Quick Start Guide

**⚠️ STOP: Do not proceed without IRB approval and proper authorization ⚠️**

This guide provides a rapid setup path for authorized researchers. For detailed instructions, see [`docs/SETUP.md`](docs/SETUP.md).

## Prerequisites Checklist

- [ ] IRB approval obtained
- [ ] Linux system (Ubuntu 22.04+ recommended)
- [ ] 16GB+ RAM, 100GB+ free disk space
- [ ] Air-gapped lab environment ready
- [ ] GPG keys generated for commit signing

## 5-Minute Setup

### 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y \
    build-essential uuid-dev iasl git nasm python3 \
    gcc-multilib qemu-system-x86 swtpm gpg

# Verify installations
gcc --version    # Should be ≥11.0
python3 --version # Should be ≥3.10
qemu-system-x86_64 --version # Should be ≥7.0
```

### 2. Clone and Setup EDK II

```bash
# Create workspace
mkdir -p ~/aegis-workspace && cd ~/aegis-workspace

# Clone EDK II
git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout edk2-stable202405
git submodule update --init --recursive

# Build BaseTools
source edksetup.sh BaseTools
make -C BaseTools
```

### 3. Build OVMF

```bash
cd ~/aegis-workspace/edk2
source edksetup.sh

# Build OVMF with TPM support
build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc \
    -D TPM2_ENABLE=TRUE \
    -D SECURE_BOOT_ENABLE=TRUE \
    -D SMM_REQUIRE=TRUE
```

### 4. Setup Aegis-Boot

```bash
cd ~/aegis-workspace
git clone <aegis-boot-repo-url> aegis-boot
cd aegis-boot

# Copy and configure environment
cp .env.example .env
nano .env  # Edit with your values

# CRITICAL: Set these in .env:
# - AEGIS_ALLOWED_UUID (get with: sudo dmidecode -s system-uuid)
# - IRB_APPROVAL_DATE (your actual IRB approval date)
# - AEGIS_EXPIRY_DATE (project expiry date)
```

### 5. Validate Environment

```bash
cd ~/aegis-workspace/aegis-boot
source .env

# Run validation
./scripts/validate-environment.sh

# Expected output: "All validation checks passed!"
```

### 6. Test QEMU Setup

```bash
# Start vTPM
mkdir -p ~/aegis-workspace/vtpm-state
swtpm socket \
    --tpmstate dir=~/aegis-workspace/vtpm-state \
    --ctrl type=unixio,path=~/aegis-workspace/vtpm-state/swtpm-sock \
    --tpm2 --daemon

# Test QEMU boot
./scripts/qemu-run.sh --test-mode --snapshot

# You should see UEFI boot messages
# Press Ctrl+A then X to exit
```

## Next Steps

### For Development

1. **Read Documentation**
   - [`docs/SETUP.md`](docs/SETUP.md) - Detailed setup
   - [`docs/technical_details.md`](docs/technical_details.md) - Architecture
   - [`docs/testing.md`](docs/testing.md) - Testing strategy

2. **Implement Packages**
   - Start with BootkitPkg structure
   - Follow EDK II package conventions
   - Implement kill-switches first

3. **Build and Test**
   ```bash
   ./scripts/build.sh
   ./scripts/qemu-run.sh --test-mode
   ```

### For Testing

1. **Create NVRAM Backup**
   ```bash
   python3 scripts/nvram-recovery.py --backup --description "Initial clean state"
   ```

2. **Run Safety Tests**
   ```bash
   # Test UUID mismatch (should abort gracefully)
   # Test TPM EK mismatch (should abort gracefully)
   # Test expiry validation (should abort when expired)
   ```

3. **Enable Audit Logging**
   ```bash
   # Configure GPG key for audit logs
   export AUDIT_GPG_KEY_ID="YOUR_GPG_KEY_ID"
   
   # Test audit logging
   ./scripts/audit-log.sh --event-type TEST "Quick start validation"
   ```

## Common Issues

### "KVM not available"
```bash
sudo modprobe kvm kvm_intel  # or kvm_amd
sudo usermod -aG kvm $USER
# Log out and back in
```

### "OVMF build fails"
```bash
cd ~/aegis-workspace/edk2
rm -rf Build/
source edksetup.sh
make -C BaseTools clean && make -C BaseTools
build -a X64 -t GCC5 -p OvmfPkg/OvmfPkgX64.dsc -D TPM2_ENABLE=TRUE
```

### "vTPM socket not found"
```bash
pkill swtpm
rm -rf ~/aegis-workspace/vtpm-state/*
swtpm socket --tpmstate dir=~/aegis-workspace/vtpm-state \
    --ctrl type=unixio,path=~/aegis-workspace/vtpm-state/swtpm-sock \
    --tpm2 --daemon
```

## Security Reminders

- ✅ Always work in air-gapped environment
- ✅ Never commit binaries to repository
- ✅ Sign all commits with GPG
- ✅ Keep audit logs intact
- ✅ Test kill-switches regularly
- ❌ Never bypass safety mechanisms
- ❌ Never execute on unauthorized hardware
- ❌ Never share compiled binaries

## Getting Help

- **Documentation**: See `docs/` directory
- **Issues**: GitHub Issues (authorized contributors only)
- **Security**: security@[institution].edu
- **IRB**: irb@[institution].edu

## Verification Checklist

Before proceeding with implementation:

- [ ] All validation checks pass
- [ ] QEMU boots successfully with OVMF
- [ ] vTPM is functional
- [ ] Audit logging works
- [ ] NVRAM backup/restore tested
- [ ] Environment variables configured
- [ ] GPG commit signing enabled
- [ ] IRB approval documented

---

**Ready to proceed?** See [`docs/SETUP.md`](docs/SETUP.md) for detailed implementation guidance.

**Last Updated**: May 11, 2026
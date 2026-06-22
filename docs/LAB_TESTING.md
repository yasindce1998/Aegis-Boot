# Barzakh: Real Hardware Lab Testing Guide

> **Last Updated:** 2026-06-22 | **Applies to:** Ring -3 offense/defense modules

---

## ⚠️ Critical Warnings

**READ THIS ENTIRE SECTION BEFORE PROCEEDING.**

| Risk | Description |
|------|-------------|
| **Hardware Brick** | Incorrect SPI flash writes can permanently brick the motherboard. Recovery requires an external programmer and a known-good firmware image. |
| **Warranty Void** | Opening the chassis, attaching a flash programmer, or modifying firmware voids manufacturer warranty on all tested hardware. |
| **Legal Liability** | Modifying firmware on systems you do not own is a criminal offense in most jurisdictions. Even on owned hardware, some regions restrict firmware modification tools. |
| **Data Loss** | A failed flash can destroy NVRAM (UEFI variables, BitLocker keys, Secure Boot keys). Back up everything before starting. |
| **Intel ME / AMD PSP Damage** | Corrupting the Management Engine or Platform Security Processor region can cause irreversible 30-minute boot delays, permanent ME disable, or total board failure requiring RMA. |

**This guide assumes you are working on a dedicated, sacrificial test machine in an air-gapped lab. Never perform these procedures on production hardware, shared infrastructure, or machines containing important data.**

---

## 🔧 Lab Hardware Requirements

| Item | Purpose | What Happens Without It |
|------|---------|------------------------|
| Dedicated test machine (Intel Skylake+ or AMD Zen+) | Target for firmware operations | Cannot test platform-specific ME/PSP detectors |
| SPI flash programmer (CH341A ~$5, or Dediprog SF600 ~$400) | External read/write of SPI flash chip | **No recovery path** if firmware is corrupted — machine becomes a brick |
| SOIC-8 or SOIC-16 test clip | In-circuit connection to flash chip without desoldering | Must desolder the chip for every read/write (slow, risks pad damage) |
| USB-to-UART adapter (FTDI FT232R or CP2102) | Serial console output from firmware | No visibility into boot process — debugging becomes guesswork |
| Second machine (control station) | Run flashrom, analyze dumps, store backups | Single point of failure if test machine is also the recovery station |
| Isolated network switch | AMT SOL testing over dedicated VLAN | AMT traffic leaks to production network (security/compliance violation) |
| Multimeter | Verify 3.3V SPI voltage, check clip connections | Risk of applying wrong voltage or incomplete connection during flash |
| **Optional:** Logic analyzer (Saleae, DSLogic) | Debug SPI bus timing issues | Cannot diagnose intermittent flash failures |
| **Optional:** JTAG/SWD debugger | Deep platform debug (Intel DCI, AMD HDT) | Limited to black-box observation of boot behavior |

### Minimum Budget Breakdown

| Tier | Total Cost | Components |
|------|-----------|------------|
| Budget | ~$50 | CH341A + SOIC-8 clip + CP2102 + spare test machine (recycled) |
| Professional | ~$700 | Dediprog SF600 + Pomona clip + FTDI + logic analyzer |
| Full Lab | ~$2000+ | Above + multiple test platforms (Intel/AMD) + KVM switch + rack |

---

## 📋 Safety Prerequisites

Complete **every** step below before any destructive testing. These are not optional.

### Step 1: Dump Original Firmware via External Programmer

Connect the SPI programmer to the flash chip using the SOIC clip, then read the full image:

```bash
# CH341A example (most common budget programmer)
flashrom -p ch341a_spi -r original_firmware.bin

# Dediprog SF600
flashrom -p dediprog -r original_firmware.bin

# ALWAYS read twice and compare checksums
flashrom -p ch341a_spi -r original_firmware_verify.bin
sha256sum original_firmware.bin original_firmware_verify.bin
```

**⚠️ What happens if you skip this:** You have no recovery image. Any flash corruption means the machine is permanently bricked. There is no software-only recovery path once the SPI flash is corrupted — the chip must be reprogrammed externally.

**⚠️ Why read twice:** SPI clip connections are unreliable. A single bit flip in the dump means your "backup" is corrupt. If both reads produce identical SHA-256 hashes, the dump is trustworthy.

---

### Step 2: Verify External Reflash Works (Round-Trip Test)

```bash
# Write your dump back and verify it matches
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
```

Then **boot the machine** and confirm it starts normally.

**⚠️ What happens if you skip this:** You assume your programmer/clip setup works, but you've never proven it. If the clip has a bad connection on pin 3 (MOSI), writes silently corrupt data. You discover this only after flashing a modified image and failing to recover.

---

### Step 3: Check Intel Boot Guard / AMD PSB Status

```bash
# Using chipsec (requires Linux with kernel module)
sudo python chipsec_main.py -m common.bios_wp
sudo python chipsec_main.py -m common.secureboot.variables

# Check Boot Guard specifically
sudo python chipsec_main.py -m common.cpu.ia_untrusted

# Or examine the firmware image directly
ifdtool -x original_firmware.bin
```

**⚠️ What happens if you skip this:** If Intel Boot Guard is provisioned (fuses blown in the PCH), the CPU will **refuse to execute** any firmware not signed with the OEM's key. You flash a modified image, the machine appears dead (no POST, no beep, no serial output), and you waste hours debugging what is actually a cryptographic lockout. The machine still boots fine when you reflash the original — but modified images will **never** work on Boot Guard-enabled hardware.

**Key indicators:**

| Platform | Check | Boot Guard Active |
|----------|-------|-------------------|
| Intel | `MSR 0x13A` bit 0 | If set, Boot Guard fuses are blown |
| Intel | ACM (Authenticated Code Module) present in flash | OEM has provisioned verified boot |
| AMD | PSB fuse check via `chipsec` | Platform Secure Boot enabled |

**If Boot Guard/PSB is enabled:** You can still run Phase 1 and Phase 2 (analysis only). Phase 3-5 require either a Boot Guard-disabled board or signing your test images with the OEM key (not possible without the private key).

---

### Step 4: Document Platform Details

Record the following before any modifications:

```bash
# BIOS version
sudo dmidecode -t bios

# Board model
sudo dmidecode -t baseboard

# ME version (Intel)
sudo python chipsec_main.py -m common.me

# Full SMBIOS dump
sudo dmidecode > platform_info.txt

# SPI flash chip identification
flashrom -p ch341a_spi --flash-name
```

Store this in your lab notebook. If you need vendor support or a replacement BIOS image, you'll need the exact model, revision, and firmware version.

**⚠️ What happens if you skip this:** You corrupt the ME region and need the vendor's original ME firmware binary. Without the exact board model and BIOS version, you download the wrong image. Flashing a mismatched ME version causes additional failures.

---

### Step 5: Prepare Recovery Media

```bash
# Store multiple copies of the original dump
cp original_firmware.bin /mnt/usb_backup/
cp original_firmware.bin /mnt/network_share/

# Create a recovery script
cat > recover.sh << 'EOF'
#!/bin/bash
echo "=== EMERGENCY RECOVERY ==="
echo "Ensure SOIC clip is properly seated"
read -p "Press Enter to begin recovery flash..."
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
echo "Verification complete. Check output above for errors."
EOF
chmod +x recover.sh
```

**⚠️ What happens if you skip this:** Under pressure (machine won't POST, deadline approaching), you mistype a flashrom command or grab the wrong file. A pre-written recovery script eliminates human error during the most stressful moment.

---

## 🧪 Test Progression

### Phase 1: Non-Destructive Firmware Analysis

**Risk Level: None** — All operations are read-only against a file on your control station.

#### What You Do

```bash
# Scan the real firmware dump with Barzakh
cd src/barzakh-scanner-rs
cargo build --release
./target/release/barzakh-scanner --target /path/to/original_firmware.bin --report --format html --output real_hw_report.html

# Run with all detectors explicitly
./target/release/barzakh-scanner --target /path/to/original_firmware.bin --scan-types all
```

#### What Happens

The scanner reads the binary file you provide. It never opens hardware devices, never writes to disk (other than the report file), and never modifies the input. This is equivalent to running `strings` or `hexdump` on the file — purely passive analysis.

**Expected results on clean firmware:**
- 0-3 Low/Medium findings (normal — some vendors ship with FLOCKDN not set in the image, or have unusual ACPI table counts)
- Any Critical/High findings on stock firmware indicate either a pre-existing compromise or a false positive worth investigating

#### What You Learn

- Whether your real hardware's firmware has any suspicious artifacts before you modify it
- Baseline finding count for comparison after testing
- Whether any detectors produce false positives on your specific platform's firmware

---

### Phase 2: Adversary Payload Validation Against Real Images

**Risk Level: None** — All operations happen on files on your control station. No hardware interaction.

#### What You Do

```bash
# Generate tampered versions of your real firmware dump
cd src/barzakh-scanner-rs
cargo test -p barzakh-adversary -- --ignored corpus_validation

# Or manually inject specific payloads into a copy of the real dump
cp /path/to/original_firmware.bin /tmp/test_image.bin

# Run the adversary payloads against the real image structure
cargo run -p barzakh-adversary -- generate --input /tmp/test_image.bin --output /tmp/tampered/

# Scan all tampered images
for img in /tmp/tampered/*.bin; do
    echo "=== Scanning: $img ==="
    ./target/release/barzakh-scanner --target "$img" --report
done
```

#### What Happens

The adversary tool reads your real firmware dump, injects known-bad patterns (corrupted ACPI checksums, fake ME region overlaps, suspicious SMM handler patterns), and writes modified copies to your output directory. The scanner then analyzes these modified copies.

**No hardware is involved.** The test machine remains untouched. You are validating that Barzakh's detectors can find implants in the specific binary layout of your real platform's firmware.

#### What You Learn

- Whether detectors work against your specific platform's firmware structure (some platforms have non-standard flash layouts that may confuse pattern matching)
- True positive rate on a realistic image rather than synthetic test data
- Which payloads are detectable and which might need detector tuning for your platform

---

### Phase 3: External Flash with Modified Images

**Risk Level: Medium** — You are writing to the SPI flash chip. The machine may fail to boot.

#### What You Do

```bash
# 1. Create a test image with a KNOWN, MINIMAL modification
cp original_firmware.bin test_phase3.bin

# Example: inject an ACPI checksum error (detectable, harmless to boot)
# Use barzakh-adversary to create a minimally modified image
cargo run -p barzakh-adversary -- inject-single \
    --input original_firmware.bin \
    --output test_phase3.bin \
    --payload acpi_checksum

# 2. Flash the modified image via external programmer
flashrom -p ch341a_spi -w test_phase3.bin

# 3. Attempt to boot — observe serial console
# (Connect UART adapter, open minicom/screen on control station)
screen /dev/ttyUSB0 115200

# 4. After testing, IMMEDIATELY recover
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
```

#### What Happens

When you write the modified image:
- **flashrom erases the entire chip** (or affected sectors), then writes the new data, then optionally verifies
- The erase+write cycle takes 30-120 seconds depending on chip size (typically 8-32 MB)
- **If the clip loses contact during write:** Partial write = corrupted chip. The machine won't POST. Reflash with the original to recover.
- **If the modification corrupts a critical region (PEI/SEC volume):** Machine won't POST (black screen, no beep). This is expected. Reflash original to recover.
- **If only ACPI/BGRT/padding areas are modified:** Machine boots normally. You can then dump firmware from the running OS and scan it to validate detection works end-to-end.

#### Recovery

```bash
# Machine won't POST? Don't panic. External reflash:
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
# If verify passes: remove clip, boot. Machine should recover.
```

**⚠️ Critical caution:** Never remove the SOIC clip while a flash operation is in progress. Wait for flashrom to report completion. Interrupting a write leaves the chip in an inconsistent state.

---

### Phase 4: Intel ME / AMD PSP Testing

**Risk Level: High** — Modifications to ME/PSP regions can cause irreversible platform behavior changes.

#### Intel ME Testing

```bash
# Extract ME region from firmware dump
ifdtool -x original_firmware.bin
# Produces: flashregion_2_intel_me.bin

# Analyze ME version and configuration
python me_analyzer.py flashregion_2_intel_me.bin

# Set HAP (High Assurance Platform) bit to disable ME post-boot
# WARNING: This is a ONE-WAY operation on some platforms
python me_cleaner.py -s -O modified_me.bin original_firmware.bin

# Flash the HAP-modified image
flashrom -p ch341a_spi -w modified_me.bin
```

#### What Happens When You Modify ME

| Action | Consequence | Reversible? |
|--------|-------------|-------------|
| Set HAP bit | ME initializes hardware then halts. AMT/vPro disabled. | Yes — reflash original ME region |
| Truncate ME region (me_cleaner -r) | ME fails to boot, enters recovery mode. 30-min boot delay on some platforms. | Yes — reflash original, but delay persists for one boot cycle |
| Zero-fill ME region | **Platform may not POST at all.** Intel CPU requires ME for power management initialization. | Yes — reflash, but some Skylake+ boards require specific ME recovery procedure |
| Corrupt ME partition table | ME enters manufacturing mode. All ME interfaces exposed. Security implications. | Yes — reflash original |

**⚠️ Critical:** On platforms where ME handles the initial power sequencing (Skylake and newer), a completely missing ME region means the CPU cannot initialize. The machine appears completely dead — no fans, no LED, nothing. This is NOT a brick; external reflash of the correct ME firmware restores it. But it is indistinguishable from hardware failure until you reflash.

#### AMD PSP Testing

```bash
# PSP firmware is embedded in the BIOS image
# Extract PSP directory using PSPTool
python psptool.py original_firmware.bin

# Examine fTPM firmware blob
python psptool.py --entry-type 0x07 original_firmware.bin
```

#### What Happens When You Modify PSP

| Action | Consequence | Reversible? |
|--------|-------------|-------------|
| Extract and re-inject PSP firmware | If signatures invalid, PSP refuses to boot. CPU halts. | Yes — reflash original |
| Modify fTPM blob | TPM becomes non-functional. BitLocker keys lost if sealed to TPM. | Yes — reflash, but sealed keys are gone |
| Enable PSP debug mode | Requires AMD-signed debug key (not publicly available) | N/A — cannot be done without AMD partnership |

**⚠️ AMD Platform Secure Boot:** If PSB fuses are blown (check with `chipsec`), any modification to the PSP region causes immediate boot failure. The CPU refuses to execute. Unlike Intel Boot Guard which only protects the IBB (Initial Boot Block), AMD PSB covers the entire PSP firmware.

#### HECI Bus Monitoring (Safe, Read-Only)

```bash
# Monitor HECI (Host Embedded Controller Interface) via PCI config space
# This is READ-ONLY observation — cannot damage hardware
sudo setpci -s 00:16.0 40.l  # HECI-1 base address
sudo python chipsec_main.py -m common.me

# Watch for ME-to-host communication patterns
sudo cat /dev/mei0 | xxd | head -100
```

**What happens:** Reading HECI/MEI device files is passive observation. The ME processes your read request and returns status data. No writes occur. This is safe on any platform regardless of Boot Guard status.

---

### Phase 5: Live Offense Module Testing

**Risk Level: Very High** — You are running actual DXE implants on real hardware. System crash is expected.

#### Prerequisites for Phase 5

- Completed Phases 1-3 successfully
- Boot Guard / PSB is NOT enabled (or you have signing keys)
- Secure Boot is disabled in UEFI settings
- Serial console connected and logging
- External programmer verified working (you WILL need recovery)

#### What You Do

```bash
# 1. Disable SIMULATION_MODE in offense modules
#    Edit src/BootkitPkg/Ring3Offense/spi_write_implant.c
#    Change: #define SIMULATION_MODE TRUE
#    To:     #define SIMULATION_MODE FALSE
#    Repeat for all 5 offense modules you want to test

# 2. Build with EDK2 for your real platform
source edksetup.sh
build -a X64 -t GCC5 -p BootkitPkg/BootkitPkg.dsc -D TARGET_PLATFORM=REAL

# 3. Inject built DXE drivers into firmware image
#    Use UEFITool to insert the .efi into a firmware volume
#    Or use FMMT (Firmware Module Management Tool)

# 4. Flash the complete image
flashrom -p ch341a_spi -w firmware_with_implants.bin

# 5. Boot and observe serial output
screen /dev/ttyUSB0 115200
# You should see DXE driver load messages and hook confirmations

# 6. IMMEDIATELY recover after testing
flashrom -p ch341a_spi -w original_firmware.bin
```

#### What Happens

When the machine boots with live offense modules:

| Module | Runtime Behavior | Likely Outcome |
|--------|-----------------|----------------|
| `spi_write_implant` | Attempts to write-protect SPI regions via HSFS register | May conflict with platform's existing SPI controller init — crash or hang during DXE |
| `dxe_persistence` | Hooks Boot Services table, installs notify callbacks | Works on most platforms but exact table offsets differ from OVMF — potential crash |
| `smm_callout` | Triggers SMI and attempts SMRAM access | Will be blocked by hardware SMRAM protection on modern platforms. TSEG lock causes immediate reset. |
| `me_heci_exfil` | Opens HECI channel to communicate with ME | ME may reject unauthorized HECI traffic. Unlikely to crash but returns error codes. |
| `amt_sol_pivot` | Attempts to establish Serial-over-LAN channel | Requires AMT to be provisioned and in the correct state. Fails gracefully if AMT not configured. |

**⚠️ Critical differences from QEMU/OVMF:**

1. **Memory map is different.** OVMF has a predictable memory layout. Real hardware has OEM-specific memory holes, reserved regions, and ME stolen memory. Hardcoded addresses will fault.
2. **SMM is actually protected.** QEMU doesn't enforce SMRAM boundaries. Real hardware has D_LCK set — any access to TSEG triggers immediate platform reset.
3. **DXE dispatch order varies.** On real hardware, other DXE drivers may have already claimed resources your implant expects. Race conditions that never happen in QEMU appear on real boards.
4. **Crash = no debug output.** In QEMU, a crash produces a stack trace. On real hardware, you see the serial output stop and the machine resets. You must infer the failure point from the last successful output line.

**Expected outcome for first attempt:** The machine boots partway, one of the implants faults due to an incorrect assumption about the platform, and the machine resets. This is normal. You iterate by examining serial output, identifying the failure, adjusting the module, and reflashing.

---

## 🔬 Module-Specific Testing Notes

### SPI/Flash Modules (`spi_write_implant`, `me_spi` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Fully testable with external programmer |
| Prerequisites | CH341A or Dediprog + SOIC clip |
| What to observe | Flash write-protect bits (HSFS/FRAP registers), descriptor lock (FLOCKDN) |
| Safe test method | Dump firmware, check FLOCKDN bit in image, compare against running platform's actual register state (via `chipsec`) |

### SMM Modules (`smm_callout`, `smm_timing` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Limited on modern hardware — TSEG is locked |
| Prerequisites | Older board with known SMM unlock (pre-2015 consumer boards) OR a debug platform |
| What to observe | D_LCK status, TSEG base/mask, SMI handler entry points |
| Safe test method | Run `chipsec_main.py -m common.smm` to check if SMRAM is actually locked. If locked, test only the detector against firmware dumps — live SMM access will trigger platform reset. |

### HECI/ME Modules (`me_heci_exfil`, `heci_comm` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Passive monitoring works everywhere; active HECI requires ME cooperation |
| Prerequisites | Platform with ME enabled, HECI device visible in PCI enumeration |
| What to observe | HECI message queues, ME firmware status register (FWSTS) |
| Safe test method | Read `/dev/mei0` and PCI config space. This is passive and cannot damage the platform. |

### AMT SOL Module (`amt_sol_pivot`)

| Aspect | Detail |
|--------|--------|
| Testability | Fully testable once AMT is provisioned |
| Prerequisites | Intel vPro platform with AMT, provisioned via MEBx (press Ctrl+P at boot) |
| What to observe | SOL session establishment, OOB data channel |
| Setup | Enter MEBx (Ctrl+P during POST), set password, enable AMT, configure network. Then from control station: `amtterm <target-ip>` |

### fTPM Module (`ftpm_extract` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Observation only — cannot modify PSP without AMD debug keys |
| Prerequisites | AMD Zen+ platform with fTPM enabled |
| What to observe | fTPM NV indices, sealed key states, PCR values |
| Safe test method | Use `tpm2-tools` to read TPM state: `tpm2_pcrread`, `tpm2_nvreadpublic`. Purely read-only. |

### DMA/IOMMU Module (`iommu_bypass` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Observable via IOMMU logs; active testing requires Thunderbolt/PCIe device |
| Prerequisites | Platform with IOMMU enabled, DMA-capable expansion slot or Thunderbolt port |
| What to observe | IOMMU fault logs, DMA remapping table (DMAR) entries |
| Safe test method | Enable IOMMU verbose logging: `intel_iommu=on iommu=verbose` kernel params. Monitor `dmesg` for DMA translation faults. |

---

## 🔄 Recovery Procedures

### Scenario: Machine Won't POST After Flash

**Symptoms:** Power LED on, fans spin, but no video output, no beep codes, no serial output.

```bash
# 1. Power off completely (hold power 10s or disconnect AC)
# 2. Re-seat SOIC clip on flash chip
# 3. Verify clip connection:
flashrom -p ch341a_spi --flash-name
# Should report the chip model. If "No EEPROM/flash found", clip is not connected.

# 4. Reflash original firmware
flashrom -p ch341a_spi -w original_firmware.bin

# 5. Verify the write
flashrom -p ch341a_spi -v original_firmware.bin
# Must report "VERIFIED"

# 6. Remove clip, reconnect all cables, attempt boot
```

**If flashrom cannot detect the chip:** The clip is not making good contact. Clean the chip pins with isopropyl alcohol, re-seat the clip ensuring pin 1 alignment (dot on chip = red wire on clip), and retry.

---

### Scenario: ME Region Corrupted (30-Minute Boot Delay)

**Symptoms:** Machine eventually boots after ~30 minutes, or displays "ME in Recovery Mode" message.

```bash
# 1. Extract clean ME region from your original dump
ifdtool -x original_firmware.bin
# Produces flashregion_2_intel_me.bin

# 2. If you have a modified image that corrupted ME, rebuild it:
ifdtool -i ME:flashregion_2_intel_me.bin modified_firmware.bin -O repaired_firmware.bin

# 3. Or just reflash the entire original
flashrom -p ch341a_spi -w original_firmware.bin

# 4. After reflash, the FIRST boot may still show the 30-min delay
#    (ME needs one clean boot cycle to exit recovery state)
#    Wait for it. Subsequent boots will be normal.
```

---

### Scenario: Partial SPI Write (Clip Slipped During Flash)

**Symptoms:** flashrom reported an error mid-write. Machine state unknown.

```bash
# DO NOT attempt to boot. The image is partially written.

# 1. Verify you can still communicate with the chip
flashrom -p ch341a_spi --flash-name

# 2. If chip responds, do a FULL erase + write (not differential)
flashrom -p ch341a_spi -E  # Full erase
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin

# 3. If chip does NOT respond:
#    - Check clip seating
#    - Check programmer power (some need external 3.3V)
#    - If chip is in a locked state, try: flashrom -p ch341a_spi --force
```

**⚠️ Caution:** A partial write that corrupted only the descriptor region may have changed the flash access permissions. The `--force` flag bypasses safety checks. Use only when normal recovery fails.

---

### Scenario: Boot Loop After Modification

**Symptoms:** Machine starts to boot, shows vendor logo or early POST, then resets. Repeats indefinitely.

```bash
# This usually means the DXE phase loads but a driver crashes.
# The platform resets via watchdog timer.

# Option A: Clear NVRAM to reset boot variables
# (If your firmware image has a separate NVRAM region)
# Extract layout:
ifdtool -x original_firmware.bin
# Identify NVRAM volume in UEFITool
# Zero-fill only the NVRAM FV, keep everything else from the image that was booting

# Option B: Just reflash original (simplest)
flashrom -p ch341a_spi -w original_firmware.bin
```

---

## 📖 Tool Reference

### flashrom — SPI Flash Read/Write/Verify

```bash
# Read entire flash chip to file
flashrom -p <programmer> -r <output.bin>

# Write file to flash chip (erases first)
flashrom -p <programmer> -w <input.bin>

# Verify flash contents match file
flashrom -p <programmer> -v <file.bin>

# Full chip erase
flashrom -p <programmer> -E

# Identify flash chip without read/write
flashrom -p <programmer> --flash-name

# Common programmers:
#   ch341a_spi      - CH341A USB programmer ($5)
#   dediprog        - Dediprog SF600 ($400)
#   linux_spi       - Raspberry Pi GPIO SPI (/dev/spidev0.0)
#   internal        - Read via CPU's SPI controller (read-only on locked systems)
```

### me_cleaner — Intel ME Manipulation

```bash
# Set HAP bit (disables ME after hardware init)
python me_cleaner.py -s -O output.bin input.bin

# Remove non-essential ME modules (aggressive)
python me_cleaner.py -r -O output.bin input.bin

# Show ME version and partition info
python me_cleaner.py -c input.bin
```

**⚠️ Caution:** me_cleaner modifies a FILE. It does not touch hardware directly. You must flash the output file using flashrom separately.

### UEFITool — Firmware Image Inspector

```bash
# GUI tool — open firmware images and inspect structure
UEFITool original_firmware.bin

# Key operations:
# - Extract specific firmware volumes or DXE drivers
# - Search for GUIDs, text strings, hex patterns
# - Insert/replace modules (for implant injection testing)
# - Validate image structure and checksums
```

### ifdtool — Intel Flash Descriptor Tool

```bash
# Extract all flash regions to separate files
ifdtool -x firmware.bin
# Produces: flashregion_0_flashdescriptor.bin
#           flashregion_1_bios.bin
#           flashregion_2_intel_me.bin
#           flashregion_3_gbe.bin

# Show flash descriptor layout
ifdtool -d firmware.bin

# Inject ME region from separate file
ifdtool -i ME:me_firmware.bin firmware.bin -O output.bin

# Unlock flash descriptor (remove region write protections)
ifdtool -u firmware.bin -O unlocked.bin
```

### chipsec — Platform Security Assessment

```bash
# Run all security checks
sudo python chipsec_main.py

# Check specific module:
sudo python chipsec_main.py -m common.bios_wp        # BIOS write protection
sudo python chipsec_main.py -m common.smm            # SMM protection (SMRAM)
sudo python chipsec_main.py -m common.spi_lock       # SPI flash lock status
sudo python chipsec_main.py -m common.secureboot     # Secure Boot status
sudo python chipsec_main.py -m common.me             # ME configuration

# Dump SPI flash via CPU (internal, read-only if locked)
sudo python chipsec_util.py spi dump spi_dump.bin

# Read specific MSR
sudo python chipsec_util.py msr 0x13A  # IA32_FEATURE_CONTROL (Boot Guard)
```

**⚠️ Caution:** chipsec requires a kernel module that grants ring-0 access. Installing `chipsec` on production systems creates a privilege escalation vector. Use only on dedicated test machines.

### barzakh-scanner — Firmware Threat Detection

```bash
# Scan a firmware dump
./target/release/barzakh-scanner --target firmware.bin

# Generate HTML report
./target/release/barzakh-scanner --target firmware.bin --report --format html --output report.html

# Compare against baseline
./target/release/barzakh-scanner --target firmware.bin --baseline clean_baseline.json

# Scan with specific detector categories
./target/release/barzakh-scanner --target firmware.bin --scan-types spi,smm,acpi,me
```

---

## ⚖️ Legal & Ethical Notice

### Authorized Use Only

- **Only test on hardware you own** or have explicit written authorization to modify
- **Do not deploy** offense modules on production systems, enterprise infrastructure, or shared equipment
- **Do not distribute** modified firmware images containing implants
- **Air-gap the test environment** — no network connectivity between test machines and production networks (except isolated VLAN for AMT testing)

### Jurisdictional Considerations

| Region | Key Restriction |
|--------|----------------|
| USA | CFAA prohibits unauthorized access to computer systems. Firmware modification on owned hardware is legal, but distributing tools "primarily designed" for unauthorized access may violate DMCA §1201 |
| EU | Computer Misuse Directive (2013/40/EU). Similar to CFAA — authorized research is permitted, unauthorized modification is criminal |
| UK | Computer Misuse Act 1990. Explicit exemption for authorized security testing |
| India | IT Act 2000, Section 43/66. Unauthorized modification is punishable. Ensure institutional authorization documentation |

### Institutional Requirements

If conducting this research under an academic or corporate institution:

1. Obtain written approval from your security research ethics board
2. Maintain a lab access log (who accessed what hardware, when)
3. Keep all test machines physically secured (locked lab)
4. Document all firmware modifications in an append-only audit log
5. Follow your institution's responsible disclosure policy for any vulnerabilities discovered

### References

- See [`SECURITY.md`](../SECURITY.md) for vulnerability disclosure procedures
- See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for code contribution guidelines
- See [`docs/TESTING.md`](TESTING.md) for the virtualization-first testing approach (recommended before hardware testing)

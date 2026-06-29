# Android Boot Security Analysis (2026+)

Barzakh's Android boot security modules target the hardware-rooted chain of trust from Application Boot Loader (ABL) through pKVM to userspace `init`. These modules generate adversarial firmware payloads and detect real-world attack patterns against Android 14-16+ security mechanisms on ARM64 (Aarch64) devices.

---

## Android Boot Chain Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Hardware Root of Trust (Titan M2 / TrustZone Secure World)  │
└──────────────────────────────┬──────────────────────────────┘
                               │ DICE attestation (UDS → CDI chain)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Primary Bootloader (PBL) → ABL (Android Bootloader)         │
│   • Verified Boot (AVB 2.0)                                 │
│   • Boot Control HAL (A/B slot management)                  │
│   • Bootconfig parameter passing                            │
└──────────────────────────────┬──────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
┌──────────────┐   ┌───────────────────┐   ┌──────────────┐
│ Trusty TEE   │   │ pvmfw → pKVM (EL2)│   │ GKI Kernel   │
│ (Secure OS)  │   │ (Protected VMs)   │   │ (boot.img v4)│
└──────────────┘   └───────────────────┘   └──────┬───────┘
                                                   │
                              ┌─────────────────────┼──────────┐
                              ▼                     ▼          ▼
                   ┌───────────────┐    ┌──────────────┐  ┌────────┐
                   │ vendor_dlkm   │    │ init_boot    │  │ vendor │
                   │ (EROFS + .ko) │    │ (first-stage │  │ _boot  │
                   └───────────────┘    │  ramdisk)    │  └────────┘
                                        └──────────────┘
```

**Key 2026+ Changes:**
- AVF (Android Virtualization Framework) is mandatory on new devices — pKVM runs at EL2
- DICE attestation chain is standardized across all vendors
- GKI 2.0 enforces signed vendor kernel modules exclusively
- RKP (Remote Key Provisioning) replaces factory-provisioned attestation keys
- Binary Transparency provides public verifiability of factory images

---

## Attack Surfaces and Detection Modules

### 1. pKVM / AVF Hypervisor (`android_pkvm`)

**Target:** Protected Virtual Machine firmware (pvmfw) and the pKVM hypervisor running at Exception Level 2.

**Attack Vectors:**
- Forge pvmfw instance signature to boot unauthorized pVM workloads
- Patch EL2 exception vector table to intercept host/guest transitions
- Manipulate AVF instance.img debug policy to enable pVM debugging on production devices

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `pvmf` magic | pvmfw image header |
| `PKVM` + zeroed signature field | Hypervisor image with removed authentication |
| `AVFi` + debug policy byte ≠ 0 | Debug-enabled AVF instance configuration |

**Payload:** `android_pkvm_escape` — Generates pvmfw image with zeroed authentication, EL2 shellcode branch at vector base, and debug-enabled AVF instance policy.

---

### 2. DICE Attestation Chain (`android_dice`)

**Target:** Device Identifier Composition Engine — the hardware-rooted certificate chain that provides boot measurement attestation from ROM through every boot stage.

**Attack Vectors:**
- Forge DICE certificate chain (COSE_Sign1 CBOR structures) with predictable CDI values
- Extract or predict Unique Device Secret (UDS) through low-entropy seeding
- Zero the CDI_Attest code hash to claim arbitrary boot measurements

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `0xD2 0x84` (COSE_Sign1 tag 18) | CBOR-encoded certificate in DICE chain |
| `CDI_Attest` + 32 zero bytes | Forged code measurement (no actual boot stage measured) |
| `UDS` + repeating byte pattern | Predictable device secret (entropy < threshold) |
| `DiceCertChain` | Chain container identifier |

**Payload:** `android_dice_forge` — Generates fake CBOR-encoded DICE chain with zeroed CDI_Attest code hash and low-entropy UDS pattern.

---

### 3. GKI Boot Image v4/v5 (`android_gki_boot`)

**Target:** Generic Kernel Image boot format (boot.img header version 4+), which separates kernel, ramdisk, and vendor components with independent AVB verification.

**Attack Vectors:**
- Strip or zero the AVB hash descriptor to bypass verified boot for the kernel
- Tamper init_boot ramdisk (first-stage init) while leaving kernel hash intact
- Inject oversized vendor_boot ramdisk to smuggle persistent implants

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `ANDROID!` + header_version ≥ 4 | GKI boot image header |
| `AVB0` + zeroed hash descriptor | AVB verification data nullified |
| `VNDRBOOT` + ramdisk > 64MB | Suspiciously large vendor ramdisk |

**Payload:** `android_gki_tamper` — Generates boot.img v4 with modified ramdisk, zeroed AVB hash descriptor, and oversized vendor_boot ramdisk section.

---

### 4. Remote Key Provisioning (`android_rkp`)

**Target:** Google's RKP infrastructure for KeyMint attestation — replaces factory-burned attestation keys with remotely provisioned, short-lived certificates.

**Attack Vectors:**
- Spoof the EEK (Endpoint Encryption Key) certificate chain with a non-Google root CA
- Downgrade CSR (Certificate Signing Request) security level from TRUSTED_ENVIRONMENT to SOFTWARE
- Inject factory test certificates to bypass production RKP validation

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `0xA5 0x01 0x02` (COSE_Key) | CBOR-encoded key structure in RKP blob |
| `google/keymint` + security_level ≠ 2 | KeyMint CSR with downgraded security level |
| `FactoryKeys` marker | Test/factory certificate present in production blob |

**Payload:** `android_rkp_spoof` — Generates RKP provisioning blob with fake EEK chain, CSR security level set to SOFTWARE (0x01), and factory test certificate marker.

---

### 5. Binary Transparency (`android_binary_transparency`)

**Target:** Pixel Binary Transparency / AOSP transparency log — a public Merkle tree that allows verification of factory image authenticity against a tamper-evident log.

**Attack Vectors:**
- Forge Merkle inclusion proofs with fabricated leaf hashes to validate malicious images
- Manipulate SignedTreeHead (STH) to present a fraudulent log state
- Supply empty consistency proofs to hide log splits/forks

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `tree_size` + `leaf_index` in JSON | Transparency log entry structure |
| Repeated 32-byte hash values in proof | Fabricated Merkle path (real paths have unique nodes) |
| `consistency` + empty array `[]` | Missing consistency proof (hides log fork) |

**Payload:** `android_bt_forge` — Generates fake transparency log entry with repeating Merkle hashes, zeroed STH root hash, and empty consistency proof.

---

### 6. Trusty TEE (`android_trusty`)

**Target:** Google's Trusted Execution Environment OS based on Little Kernel (LK), loaded by ABL into TrustZone secure world memory.

**Attack Vectors:**
- Zero the Trusty image signature field to load patched secure OS
- Set load address outside secure memory range (< 0xB0000000) to place Trusty in normal world
- Patch LK entry point with branch + NOP sled to redirect initial execution

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `TRUS` magic | Trusty OS image header |
| Load address < 0xB0000000 | Image targeting normal-world memory (not secure) |
| Entry point with `0x14` (ARM64 branch) + `0xD503201F` (NOP) sled | Patched execution redirect |
| Zeroed 256-byte signature field | Signature authentication removed |

**Payload:** `android_trusty_tamper` — Generates Trusty image with load address at 0x80000000 (normal world), zeroed signature block, and LK entry containing branch + NOP sled.

---

### 7. Boot Control HAL (`android_bootctrl`)

**Target:** A/B (seamless update) boot slot metadata managed by the bootloader — controls which slot boots, retry counts, and Virtual A/B merge state.

**Attack Vectors:**
- Mark both A and B slots as unbootable — device bricks on next reboot with no recovery path
- Exhaust retry counts to zero — one boot failure permanently disables the active slot
- Set merge_status to invalid value — blocks OTA update completion

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `BCHL` magic (0x42434C48) | Boot Control HAL metadata header |
| Both slot bootable flags = 0 | Dual-slot denial-of-boot |
| retry_count = 0 for both slots | One-failure-from-brick condition |
| merge_status > 3 | Invalid Virtual A/B state (blocks OTA) |

**Payload:** `android_bootctrl_poison` — Generates boot_ctrl metadata with both slots unbootable, zero retries, and merge_status=0xFF (invalid).

**Severity:** Critical — causes immediate or near-immediate device brick.

---

### 8. vendor_dlkm Partition (`android_vendor_dlkm`)

**Target:** Vendor Dynamic Loadable Kernel Modules partition (EROFS filesystem containing `.ko` files loaded at boot). GKI 2.0 mandates all vendor modules be signed.

**Attack Vectors:**
- Inject unsigned ELF kernel module into EROFS image — loads before module signature enforcement
- Disable dm-verity flag or zero the verity salt — allows persistent modification without detection
- Compile module against debug kernel (vermagic mismatch) — indicates non-GKI source

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| EROFS magic `0xE0F5E1E2` + ELF `0x7F454C46` | Kernel module inside EROFS partition |
| `init_module` symbol without `~Module signature appended` trailer | Unsigned loadable module |
| `verity` + disabled flag (0x02) or 32 zero-byte salt | dm-verity integrity bypass |
| `vermagic=` containing `debug` | Module compiled against non-production kernel |

**Payload:** `android_dlkm_inject` — Generates EROFS image containing unsigned ELF module with `init_module` export and disabled dm-verity metadata.

**Severity:** Critical — provides kernel-level code execution persistence across reboots.

---

### 9. Bootconfig Parameter Injection (`android_bootconfig`)

**Target:** Android 12+ bootconfig mechanism (replaces kernel command line for passing boot parameters). Appended after the boot image with its own trailer.

**Attack Vectors:**
- Inject `androidboot.init=/path/to/malicious` — replaces init binary with attacker-controlled PID 1
- Override `androidboot.verifiedbootstate=green` — spoofs verified boot status to apps and attestation
- Set `androidboot.selinux=permissive` — disables mandatory access control
- Inflate bootconfig size beyond 64KB — smuggle parameters past size-based validation

**Detection Signatures:**
| Marker | Meaning |
|--------|---------|
| `#BOOTCONFIG\n` | Bootconfig section magic trailer |
| `androidboot.init=` | Arbitrary init binary override (root execution) |
| `androidboot.verifiedbootstate=` | Verified boot status spoofing |
| `androidboot.selinux=permiss` | SELinux enforcement disabled |
| Config size > 0x10000 | Oversized section (parameter smuggling) |

**Payload:** `android_bootconfig_inject` — Generates boot image with oversized bootconfig containing malicious init override, spoofed verified boot state, and SELinux=permissive.

**Severity:** Critical — `androidboot.init=` provides arbitrary root execution at earliest userspace.

---

## 2026+ Threat Landscape

### Emerging Attack Trends

| Trend | Impact | Barzakh Coverage |
|-------|--------|-----------------|
| AVF mandatory on all new ARM64 devices | pKVM becomes universal attack surface | `android_pkvm` |
| DICE standardization (Open Profile) | Uniform cert chain = uniform attack patterns | `android_dice` |
| RKP migration complete (no more factory keys) | Key provisioning infrastructure is sole trust anchor | `android_rkp` |
| GKI 2.0 modules-only vendor code | vendor_dlkm is the only path for vendor kernel code | `android_vendor_dlkm` |
| Bootconfig replaces cmdline entirely | New injection surface replaces legacy parameter passing | `android_bootconfig` |
| Binary Transparency expanding beyond Pixel | Broader deployment = higher-value forgery target | `android_binary_transparency` |

### Adversary Capabilities by Tier

| Tier | Access Level | Relevant Modules |
|------|-------------|-----------------|
| Supply chain (factory) | Flash-time image modification | All 9 modules |
| Physical (fastboot/JTAG) | Bootloader-unlocked reflash | `android_gki_boot`, `android_bootctrl`, `android_bootconfig` |
| Privileged software (root) | Runtime partition modification | `android_vendor_dlkm`, `android_bootconfig`, `android_bootctrl` |
| Remote (RCE + persistence) | Post-exploit persistence | `android_vendor_dlkm`, `android_bootconfig` |

---

## Detection Methodology

Each detector follows Barzakh's standard analysis pipeline:

1. **Magic/header identification** — locate the target structure in the firmware blob
2. **Structural validation** — check field values against known-good ranges
3. **Anomaly scoring** — assign severity based on deviation type and exploit potential
4. **Finding generation** — produce structured findings with confidence scores and remediation

All Android detectors operate on raw binary images (not mounted filesystems), making them suitable for:
- Pre-flash firmware auditing
- OTA update package inspection
- Forensic analysis of extracted partitions
- Supply chain verification workflows

---

## Usage

```bash
# Scan a boot.img for all Android-specific threats
barzakh scan --arch aarch64 boot.img

# Generate adversarial payloads for testing
barzakh adversary generate android_pkvm_escape --output pvmfw_test.bin
barzakh adversary generate android_dice_forge --output dice_test.bin
barzakh adversary generate android_bootconfig_inject --output bootconfig_test.bin

# Run full Android boot security audit
barzakh scan --arch aarch64 \
  boot.img vendor_boot.img init_boot.img \
  vendor_dlkm.img pvmfw.bin trusty.bin
```

---

## References

- [Android Verified Boot (AVB) 2.0](https://source.android.com/docs/security/features/verifiedboot)
- [Android Virtualization Framework (AVF)](https://source.android.com/docs/core/virtualization)
- [pKVM Design (Protected KVM)](https://source.android.com/docs/core/virtualization/architecture)
- [DICE Layered Attestation (Open Profile for DICE)](https://pigweed.googlesource.com/open-dice/+/HEAD/docs/)
- [Remote Key Provisioning (RKP)](https://source.android.com/docs/security/features/keystore/implementer-ref)
- [GKI Boot Image Header v4](https://source.android.com/docs/core/architecture/bootloader/boot-image-header)
- [Pixel Binary Transparency](https://developers.google.com/android/binary_transparency)
- [Trusty TEE](https://source.android.com/docs/security/features/trusty)
- [Boot Control HAL](https://source.android.com/docs/core/ota/ab)
- [vendor_dlkm Partition](https://source.android.com/docs/core/architecture/partitions/vendor-dlkm)
- [Bootconfig](https://source.android.com/docs/core/architecture/bootloader/bootconfig)

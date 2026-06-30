pub mod acpi_backdoor;
pub mod amfi_bypass;
pub mod amt_sol;
pub mod android_avb_rollback;
pub mod android_bootconfig_inject;
pub mod android_bootctrl_poison;
pub mod android_bt_forge;
pub mod android_dice_forge;
pub mod android_dlkm_inject;
pub mod android_fastboot_unlock;
pub mod android_gki_tamper;
pub mod android_keymint_downgrade;
pub mod android_pkvm_escape;
pub mod android_rkp_spoof;
pub mod android_trusty_tamper;
pub mod apple_img4_downgrade;
pub mod arm_iboot;
pub mod arm_scm;
pub mod arm_tbbr_bypass;
pub mod arm_trustzone;
pub mod asus_nvram_redirect;
pub mod auth_var_rollback;
pub mod blacklotus_mok;
pub mod bmc_spi_lateral;
pub mod boot_guard_bypass;
pub mod boot_services_hook;
pub mod bootkitty_grub_patch;
pub mod bt_firmware_implant;
pub mod capsule_tamper;
pub mod clkscrew_voltage;
pub mod cxl_dma_attack;
pub mod dbx_rollback;
pub mod dell_bios_connect;
pub mod dmar_neuter;
pub mod dxe_depex_hijack;
pub mod esp_persistence;
pub mod ftpm_forge;
pub mod fv_tamper;
pub mod gpu_vbios_implant;
pub mod heci_traffic;
pub mod http_boot_mitm;
pub mod idrac_spi_lateral;
pub mod insyde_smm_capsule;
pub mod jtag_dci_unlock;
pub mod ktrr_disable;
pub mod logofail_image;
pub mod lvfs_capsule_spoof;
pub mod me_dma_inject;
pub mod me_spi_region;
pub mod meltdown_pte_leak;
pub mod microcode_malicious;
pub mod msi_key_leak;
pub mod network_boot_redirect;
pub mod nvram_capsule;
pub mod optionrom_inject;
pub mod pe_inject;
pub mod pei_core_patch;
pub mod pixiefail_dhcp;
pub mod plundervolt_sgx;
pub mod pluton_intercept;
pub mod psp_tamper;
pub mod riscv_opensbi;
pub mod riscv_pmp_bypass;
pub mod riscv_uefi_boot;
pub mod rowhammer_trr_bypass;
pub mod runtime_services_hook;
pub mod s3_bootscript_inject;
pub mod sbat_rollback;
pub mod secureboot_bypass;
pub mod secureboot_reloader;
pub mod sep_downgrade;
pub mod sev_snp_vmpl_escape;
pub mod signature_plant;
pub mod smm_timing_anomaly;
pub mod spectre_btb_inject;
pub mod spi_region_tamper;
pub mod tdx_ovmf_inject;
pub mod thermal_rapl_exfil;
pub mod tpm_ref_overflow;
pub mod trampoline;
pub mod trustcache_inject;
pub mod wifi_dxe_inject;
pub mod wifi_firmware_implant;
pub mod windows_bcd_tamper;

use crate::Payload;

pub fn create_all_payloads() -> Vec<Box<dyn Payload>> {
    vec![
        Box::new(trampoline::TrampolinePayload),
        Box::new(boot_services_hook::BootServicesHookPayload),
        Box::new(pe_inject::PeInjectPayload),
        Box::new(fv_tamper::FirmwareVolumeTamperPayload),
        Box::new(signature_plant::SignaturePlantPayload),
        Box::new(heci_traffic::HeciTrafficPayload),
        Box::new(me_spi_region::MeSpiRegionPayload),
        Box::new(amt_sol::AmtSolPayload),
        Box::new(ftpm_forge::FtpmForgePayload),
        Box::new(me_dma_inject::MeDmaInjectPayload),
        Box::new(spi_region_tamper::SpiRegionTamperPayload),
        Box::new(smm_timing_anomaly::SmmTimingAnomalyPayload),
        Box::new(nvram_capsule::NvramCapsulePayload),
        Box::new(s3_bootscript_inject::S3BootscriptInjectPayload),
        Box::new(secureboot_bypass::SecurebootBypassPayload),
        Box::new(optionrom_inject::OptionromInjectPayload),
        Box::new(acpi_backdoor::AcpiBackdoorPayload),
        Box::new(logofail_image::LogofailImagePayload),
        Box::new(pixiefail_dhcp::PixiefailDhcpPayload),
        Box::new(blacklotus_mok::BlacklotusMokPayload),
        Box::new(psp_tamper::PspTamperPayload),
        Box::new(boot_guard_bypass::BootGuardBypassPayload),
        Box::new(auth_var_rollback::AuthVarRollbackPayload),
        Box::new(dxe_depex_hijack::DxeDepexHijackPayload),
        Box::new(pei_core_patch::PeiCorePatchPayload),
        Box::new(capsule_tamper::CapsuleTamperPayload),
        Box::new(cxl_dma_attack::CxlDmaAttackPayload),
        Box::new(arm_trustzone::ArmTrustzonePayload),
        Box::new(arm_iboot::ArmIbootPayload),
        Box::new(arm_scm::ArmScmPayload),
        Box::new(riscv_opensbi::RiscvOpensbiPayload),
        Box::new(riscv_uefi_boot::RiscvUefiBootPayload),
        Box::new(riscv_pmp_bypass::RiscvPmpBypassPayload),
        Box::new(bootkitty_grub_patch::BootkittyGrubPatchPayload),
        Box::new(secureboot_reloader::SecurebootReloaderPayload),
        Box::new(sbat_rollback::SbatRollbackPayload),
        Box::new(esp_persistence::EspPersistencePayload),
        Box::new(runtime_services_hook::RuntimeServicesHookPayload),
        Box::new(tdx_ovmf_inject::TdxOvmfInjectPayload),
        Box::new(bmc_spi_lateral::BmcSpiLateralPayload),
        Box::new(gpu_vbios_implant::GpuVbiosImplantPayload),
        Box::new(http_boot_mitm::HttpBootMitmPayload),
        Box::new(tpm_ref_overflow::TpmRefOverflowPayload),
        Box::new(arm_tbbr_bypass::ArmTbbrBypassPayload),
        Box::new(wifi_dxe_inject::WifiDxeInjectPayload),
        Box::new(pluton_intercept::PlutonInterceptPayload),
        Box::new(sev_snp_vmpl_escape::SevSnpVmplEscapePayload),
        Box::new(microcode_malicious::MicrocodeMaliciousPayload),
        Box::new(spectre_btb_inject::SpectreBtbInjectPayload),
        Box::new(meltdown_pte_leak::MeltdownPteLeakPayload),
        Box::new(thermal_rapl_exfil::ThermalRaplExfilPayload),
        Box::new(plundervolt_sgx::PlundervoltSgxPayload),
        Box::new(clkscrew_voltage::ClkscrewVoltagePayload),
        Box::new(jtag_dci_unlock::JtagDciUnlockPayload),
        Box::new(rowhammer_trr_bypass::RowhammerTrrBypassPayload),
        Box::new(dell_bios_connect::DellBiosConnectPayload),
        Box::new(asus_nvram_redirect::AsusNvramRedirectPayload),
        Box::new(msi_key_leak::MsiKeyLeakPayload),
        Box::new(insyde_smm_capsule::InsydeSmmCapsulePayload),
        Box::new(idrac_spi_lateral::IdracSpiLateralPayload),
        Box::new(lvfs_capsule_spoof::LvfsCapsuleSpoofPayload),
        Box::new(android_pkvm_escape::AndroidPkvmEscapePayload),
        Box::new(android_dice_forge::AndroidDiceForgePayload),
        Box::new(android_gki_tamper::AndroidGkiTamperPayload),
        Box::new(android_rkp_spoof::AndroidRkpSpoofPayload),
        Box::new(android_bt_forge::AndroidBtForgePayload),
        Box::new(android_trusty_tamper::AndroidTrustyTamperPayload),
        Box::new(android_bootctrl_poison::AndroidBootctrlPoisonPayload),
        Box::new(android_dlkm_inject::AndroidDlkmInjectPayload),
        Box::new(android_bootconfig_inject::AndroidBootconfigInjectPayload),
        Box::new(dmar_neuter::DmarNeuterPayload),
        Box::new(dbx_rollback::DbxRollbackPayload),
        Box::new(apple_img4_downgrade::AppleImg4DowngradePayload),
        Box::new(windows_bcd_tamper::WindowsBcdTamperPayload),
        Box::new(android_avb_rollback::AndroidAvbRollbackPayload),
        Box::new(android_fastboot_unlock::AndroidFastbootUnlockPayload),
        Box::new(android_keymint_downgrade::AndroidKeymintDowngradePayload),
        Box::new(wifi_firmware_implant::WifiFirmwareImplantPayload),
        Box::new(network_boot_redirect::NetworkBootRedirectPayload),
        Box::new(bt_firmware_implant::BtFirmwareImplantPayload),
        Box::new(trustcache_inject::TrustcacheInjectPayload),
        Box::new(amfi_bypass::AmfiBypassPayload),
        Box::new(ktrr_disable::KtrrDisablePayload),
        Box::new(sep_downgrade::SepDowngradePayload),
    ]
}

pub mod acpi_backdoor;
pub mod amt_sol;
pub mod arm_iboot;
pub mod arm_scm;
pub mod arm_trustzone;
pub mod auth_var_rollback;
pub mod blacklotus_mok;
pub mod boot_guard_bypass;
pub mod boot_services_hook;
pub mod capsule_tamper;
pub mod cxl_dma_attack;
pub mod dxe_depex_hijack;
pub mod ftpm_forge;
pub mod fv_tamper;
pub mod heci_traffic;
pub mod logofail_image;
pub mod me_dma_inject;
pub mod me_spi_region;
pub mod nvram_capsule;
pub mod optionrom_inject;
pub mod pe_inject;
pub mod pei_core_patch;
pub mod pixiefail_dhcp;
pub mod psp_tamper;
pub mod riscv_opensbi;
pub mod riscv_pmp_bypass;
pub mod riscv_uefi_boot;
pub mod s3_bootscript_inject;
pub mod secureboot_bypass;
pub mod signature_plant;
pub mod smm_timing_anomaly;
pub mod spi_region_tamper;
pub mod trampoline;

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
    ]
}

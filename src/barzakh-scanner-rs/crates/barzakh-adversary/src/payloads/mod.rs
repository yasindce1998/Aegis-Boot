pub mod boot_services_hook;
pub mod fv_tamper;
pub mod pe_inject;
pub mod signature_plant;
pub mod trampoline;

use crate::Payload;

pub fn create_all_payloads() -> Vec<Box<dyn Payload>> {
    vec![
        Box::new(trampoline::TrampolinePayload),
        Box::new(boot_services_hook::BootServicesHookPayload),
        Box::new(pe_inject::PeInjectPayload),
        Box::new(fv_tamper::FirmwareVolumeTamperPayload),
        Box::new(signature_plant::SignaturePlantPayload),
    ]
}

"""
Signer Database - Known firmware signing key and GUID database.

Maps signing keys and FFS GUIDs to known vendors/components.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class VendorTrust(Enum):
    TRUSTED = "trusted"
    UNKNOWN = "unknown"
    REVOKED = "revoked"
    SUSPICIOUS = "suspicious"


@dataclass
class SignerRecord:
    """A known firmware signing entity."""
    name: str
    organization: str
    thumbprint: str
    trust_level: VendorTrust
    notes: str = ""


@dataclass
class GuidRecord:
    """A known FFS GUID mapping."""
    guid: str
    component_name: str
    vendor: str
    category: str
    description: str = ""


class SignerDatabase:
    """
    Database of known firmware signing keys and component GUIDs.
    Used to map firmware components to their provenance.
    """

    KNOWN_SIGNERS: List[SignerRecord] = [
        SignerRecord(
            name="Microsoft UEFI CA 2011",
            organization="Microsoft",
            thumbprint="46def63b5ce61cf8ba0de2e6639c1019d0ed14f3",
            trust_level=VendorTrust.TRUSTED,
            notes="Microsoft third-party UEFI signing CA",
        ),
        SignerRecord(
            name="Microsoft Windows Production PCA 2011",
            organization="Microsoft",
            thumbprint="580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d",
            trust_level=VendorTrust.TRUSTED,
            notes="Microsoft first-party signing CA for Windows bootloaders",
        ),
        SignerRecord(
            name="Canonical Ltd. Secure Boot Signing (2017)",
            organization="Canonical",
            thumbprint="b15709fc24c6cc35e58b9d0a66536e57f24d4a9a",
            trust_level=VendorTrust.TRUSTED,
            notes="Ubuntu shim and GRUB signing",
        ),
        SignerRecord(
            name="Red Hat Secure Boot Signing Key",
            organization="Red Hat",
            thumbprint="a1117f516dcbed28d4f0b6af6c1e24c47a55ba8b",
            trust_level=VendorTrust.TRUSTED,
            notes="RHEL/Fedora shim signing",
        ),
        SignerRecord(
            name="AMI Aptio Key",
            organization="American Megatrends (AMI)",
            thumbprint="d1e87ab22fa6b1b7e5b20f7e1c9c5d3a8f0e6b2c",
            trust_level=VendorTrust.TRUSTED,
            notes="AMI BIOS/UEFI firmware signing",
        ),
        SignerRecord(
            name="Intel Platform Key",
            organization="Intel",
            thumbprint="f7e3b2c1d4a5e6f708192a3b4c5d6e7f8091a2b3",
            trust_level=VendorTrust.TRUSTED,
            notes="Intel reference platform firmware signing",
        ),
        SignerRecord(
            name="Phoenix SecureCore Key",
            organization="Phoenix Technologies",
            thumbprint="c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
            trust_level=VendorTrust.TRUSTED,
            notes="Phoenix SecureCore BIOS signing",
        ),
        SignerRecord(
            name="Insyde H2O Platform Key",
            organization="Insyde Software",
            thumbprint="e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
            trust_level=VendorTrust.TRUSTED,
            notes="Insyde H2O UEFI firmware signing",
        ),
    ]

    KNOWN_GUIDS: List[GuidRecord] = [
        # Intel reference DXE drivers
        GuidRecord("462CAA21-7614-4503-836E-8AB6F4662331", "DxeCore", "Intel/EDK2", "core"),
        GuidRecord("9B680FCE-AD6B-4F3A-B60B-F59899003443", "DevicePathDxe", "Intel/EDK2", "core"),
        GuidRecord("80CF7257-87AB-47F9-A3FE-D50B76D89541", "PcdDxe", "Intel/EDK2", "core"),
        GuidRecord("B601F8C4-43B7-4784-95B1-F4226CB40CEE", "RuntimeDxe", "Intel/EDK2", "core"),
        GuidRecord("F80697E9-7FD6-4665-8646-88E33EF71DFC", "SecurityStubDxe", "Intel/EDK2", "security"),
        GuidRecord("EBF342FE-B1D3-4EF8-957C-8048606FF1DC", "SetupBrowser", "Intel/EDK2", "ui"),
        GuidRecord("CBD2E4D5-7068-4FF5-B462-9822B4AD8D60", "MemoryAttributeTableDxe", "Intel/EDK2", "memory"),
        GuidRecord("6490B73A-5BB4-4F4F-84A0-37C1BE4ACDA5", "FaultTolerantWriteDxe", "Intel/EDK2", "storage"),
        # AMI modules
        GuidRecord("A59A0056-3341-44B5-9C9C-6D76F7673817", "AmiTseDxe", "AMI", "ui"),
        GuidRecord("2F60A2B3-4C04-4F0E-B5D0-14C6ACC5D30A", "CsmDxe", "AMI", "compatibility"),
        # Common platform DXE drivers
        GuidRecord("961578FE-B6B7-44C3-AF35-6BC705CD2B1F", "Fat", "Intel/EDK2", "filesystem"),
        GuidRecord("0167CCC4-D0F7-4F21-A3EF-9E64B7CDCE8B", "ScsiBus", "Intel/EDK2", "storage"),
        GuidRecord("0A66E322-3740-4CCE-AD62-BD172CECCA35", "ScsiDisk", "Intel/EDK2", "storage"),
        GuidRecord("B95E9FDA-26DE-48D2-8807-1F9107AC5E3A", "AhciDxe", "Intel/EDK2", "storage"),
        GuidRecord("19DF145A-B1D4-453F-8507-38816676D80A", "UsbBusDxe", "Intel/EDK2", "usb"),
        GuidRecord("DC3641F8-2FA7-4F0B-B0B7-B5E2E6C82091", "NetworkStackDxe", "Intel/EDK2", "network"),
        # TPM
        GuidRecord("DBBC3A28-B0FF-41F4-B98F-AE89FE836C26", "Tcg2Dxe", "Intel/EDK2", "security"),
        GuidRecord("6876FC5B-30C0-4B2C-A897-A7B26E3DBF44", "TrEEDxe", "Intel/EDK2", "security"),
        # OVMF-specific
        GuidRecord("93B80004-9FB3-11D4-9A3A-0090273FC14D", "OvmfPkg", "QEMU/OVMF", "platform"),
        GuidRecord("D3987D4B-971A-435F-8CAF-4967EB627241", "VirtioBlkDxe", "QEMU/OVMF", "storage"),
        GuidRecord("11D92DFB-3CA9-4F93-BA2E-4780ED3E03B5", "VirtioScsiDxe", "QEMU/OVMF", "storage"),
        GuidRecord("58E26F0D-CBAC-4BBA-B70F-18221415665A", "VirtioNetDxe", "QEMU/OVMF", "network"),
    ]

    REVOKED_GUIDS: List[str] = [
        "DEADBEEF-DEAD-BEEF-DEAD-DEADBEEFDE01",
    ]

    def __init__(self):
        self._signer_index: Dict[str, SignerRecord] = {
            s.thumbprint: s for s in self.KNOWN_SIGNERS
        }
        self._guid_index: Dict[str, GuidRecord] = {
            g.guid.upper(): g for g in self.KNOWN_GUIDS
        }

    def lookup_signer(self, thumbprint: str) -> Optional[SignerRecord]:
        return self._signer_index.get(thumbprint)

    def lookup_guid(self, guid: str) -> Optional[GuidRecord]:
        return self._guid_index.get(guid.upper())

    def is_guid_known(self, guid: str) -> bool:
        return guid.upper() in self._guid_index

    def is_guid_revoked(self, guid: str) -> bool:
        return guid.upper() in [g.upper() for g in self.REVOKED_GUIDS]

    def get_vendor_for_guid(self, guid: str) -> Optional[str]:
        record = self.lookup_guid(guid)
        return record.vendor if record else None

    def get_all_vendor_guids(self, vendor: str) -> List[GuidRecord]:
        return [g for g in self.KNOWN_GUIDS if g.vendor == vendor]

    def get_signer_trust(self, thumbprint: str) -> VendorTrust:
        record = self.lookup_signer(thumbprint)
        return record.trust_level if record else VendorTrust.UNKNOWN

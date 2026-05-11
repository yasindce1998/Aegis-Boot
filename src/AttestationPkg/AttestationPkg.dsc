## @file
# Aegis-Boot Attestation Package
#
# This package contains defensive TPM querying and telemetry collection
# modules for validating Measured Boot integrity and generating detection
# ground truth data.
#
# Copyright (c) 2026, Aegis-Boot Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = AttestationPkg
  PLATFORM_GUID                  = FEDCBA98-7654-3210-FEDC-BA9876543210
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/AttestationPkg
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  #
  # Entry point
  #
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  
  #
  # Common Libraries
  #
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  
  #
  # Debug and Print
  #
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf
  
  #
  # TPM Libraries
  #
  Tpm2CommandLib|SecurityPkg/Library/Tpm2CommandLib/Tpm2CommandLib.inf
  Tpm2DeviceLib|SecurityPkg/Library/Tpm2DeviceLibDTpm/Tpm2DeviceLibDTpm.inf
  
  #
  # Cryptography
  #
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf

[LibraryClasses.common.DXE_DRIVER]
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf

[PcdsFixedAtBuild]
  # Debug output level
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2F
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000047
  
  # Serial port configuration
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultBaudRate|115200
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultDataBits|8
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultParity|1
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultStopBits|1

[Components]
  #
  # TPM Attestation Module
  #
  AttestationPkg/TpmAttestation/TpmAttestation.inf
  
  #
  # Event Log Extractor
  #
  AttestationPkg/EventLogExtractor/EventLogExtractor.inf

[BuildOptions]
  # Enable defensive features
  GCC:*_*_*_CC_FLAGS = -DAEGIS_ATTESTATION=1
  
  # Reproducible builds
  GCC:*_*_*_CC_FLAGS = -frandom-seed=aegis-attestation-$(SOURCE_DATE_EPOCH)
  
  # Security hardening
  GCC:*_*_*_CC_FLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2
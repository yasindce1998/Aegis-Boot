"""
PCR Prediction Oracle - Static TPM PCR Value Prediction

Predicts PCR[0-7] values for any firmware image without real TPM hardware
by walking FV/FFS structures and applying platform measurement policies.

Copyright (c) 2026, Barzakh Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

try:
    from .oracle import PCROracle, predict_pcrs
    from .firmware_measurer import FirmwareMeasurer
    from .measurement_policy import MeasurementPolicy, MeasurementEvent
    from .platform_profiles import PlatformProfile, get_profile
except ImportError:
    from pcr_oracle.oracle import PCROracle, predict_pcrs
    from pcr_oracle.firmware_measurer import FirmwareMeasurer
    from pcr_oracle.measurement_policy import MeasurementPolicy, MeasurementEvent
    from pcr_oracle.platform_profiles import PlatformProfile, get_profile

__all__ = [
    'PCROracle',
    'predict_pcrs',
    'FirmwareMeasurer',
    'MeasurementPolicy',
    'MeasurementEvent',
    'PlatformProfile',
    'get_profile',
]

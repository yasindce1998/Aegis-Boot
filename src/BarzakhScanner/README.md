# BarzakhScanner - Bootkit Detection Engine

BarzakhScanner is the defensive detection component of the Barzakh project. It analyzes firmware, memory, and boot measurements to detect bootkit artifacts with high accuracy and low false positive rates.

## Overview

BarzakhScanner uses multiple detection techniques:
- **PCR Analysis**: Compares TPM measurements against known-good baselines
- **Memory Scanning**: Identifies suspicious EfiRuntimeServicesCode allocations
- **Hook Detection**: Finds modified Boot Services table entries
- **Event Log Analysis**: Detects anomalous boot sequences
- **Signature Matching**: Identifies known bootkit patterns

## Target Metrics

- **True Positive Rate (TPR)**: ≥85%
- **False Positive Rate (FPR)**: <5%
- **ROC-AUC**: ≥0.92
- **Mean Time to Detect (MTTD)**: <500ms

## Architecture

```
BarzakhScanner/
├── scanner.py                # Main scanner engine
├── detectors/
│   ├── base_detector.py      # Base detector interface
│   ├── pcr_detector.py       # PCR anomaly detection
│   ├── pcr_replay.py         # PCR replay algorithm
│   ├── memory_detector.py    # Memory scanning
│   ├── hook_detector_v2.py   # Boot Services hook detection
│   ├── runtime_hook_detector.py # Runtime hook detection
│   ├── eventlog_detector.py  # Event log analysis
│   ├── entropy_analyzer.py   # Entropy-based detection
│   ├── fv_parser.py          # Firmware volume parsing
│   ├── secure_boot_detector.py # Secure Boot validation
│   └── smm_detector.py       # SMM-based detection
└── reports/
    └── report_generator.py   # HTML/JSON/Markdown reports
```

## Usage

```bash
# Scan a system
python3 scanner.py --target /path/to/firmware --baseline baseline.json

# Generate report
python3 scanner.py --report --output report.html

# Validate against test corpus
python3 scanner.py --validate --corpus test-data/
```

## Detection Rules

Rules are defined in YAML format:

```yaml
name: "BlackLotus DXE Hook"
severity: critical
type: hook_detection
indicators:
  - modified_boot_services_table
  - suspicious_allocatepool_hook
  - runtime_memory_persistence
confidence: 0.95
```

## Integration

BarzakhScanner integrates with:
- AttestationPkg (TPM data)
- BootkitPkg (telemetry)
- Event Log Extractor (boot measurements)
- External SIEM systems (via JSON export)
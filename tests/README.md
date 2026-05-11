# Aegis-Boot Test Suite

Comprehensive test suite for validating bootkit detection capabilities and ensuring system integrity.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── test_pcr_detector.py
│   ├── test_memory_detector.py
│   ├── test_hook_detector.py
│   └── test_eventlog_detector.py
├── integration/             # Integration tests
│   ├── test_scanner_integration.py
│   └── test_report_generation.py
├── corpus/                  # Test corpus
│   ├── infected/           # Known infected samples
│   └── clean/              # Known clean samples
├── fixtures/               # Test fixtures and data
│   ├── baseline.json
│   ├── pcr_dumps/
│   ├── memory_dumps/
│   └── event_logs/
└── run_tests.py            # Test runner

```

## Running Tests

### All Tests
```bash
python tests/run_tests.py
```

### Unit Tests Only
```bash
python tests/run_tests.py --unit
```

### Integration Tests Only
```bash
python tests/run_tests.py --integration
```

### Specific Test Module
```bash
python -m pytest tests/unit/test_pcr_detector.py -v
```

### With Coverage
```bash
python -m pytest tests/ --cov=src/AegisScanner --cov-report=html
```

## Test Requirements

- Python 3.8+
- pytest
- pytest-cov
- pytest-mock

Install requirements:
```bash
pip install -r tests/requirements.txt
```

## Test Corpus

The test corpus contains:
- **Infected samples**: Known bootkit-infected firmware/memory dumps
- **Clean samples**: Verified clean firmware/memory dumps

### Corpus Validation

All corpus samples are validated against:
- SHA256 checksums
- Known signatures
- Expected detection rates

## CI/CD Integration

Tests are automatically run on:
- Every commit (unit tests)
- Pull requests (full test suite)
- Nightly builds (full suite + corpus validation)

### Test Gates

- **Unit Tests**: Must pass with 100% success rate
- **Integration Tests**: Must pass with 100% success rate
- **Detection Rate**: TPR ≥ 85%, FPR < 5%
- **Code Coverage**: ≥ 80%

## Writing New Tests

### Unit Test Template

```python
import pytest
from src.AegisScanner.detectors.pcr_detector import PCRDetector

class TestPCRDetector:
    def setup_method(self):
        """Setup test fixtures."""
        self.detector = PCRDetector()
    
    def test_detection(self):
        """Test basic detection."""
        results = self.detector.detect('path/to/sample')
        assert len(results) > 0
```

### Integration Test Template

```python
import pytest
from src.AegisScanner.scanner import AegisScanner

class TestScannerIntegration:
    def test_full_scan(self):
        """Test complete scan workflow."""
        scanner = AegisScanner()
        results = scanner.scan('path/to/sample')
        assert 'summary' in results
        assert 'findings' in results
```

## Test Data Management

Test data is managed separately and not committed to the repository due to size constraints.

Download test data:
```bash
./scripts/download-test-data.sh
```

## Performance Benchmarks

Tests include performance benchmarks to ensure scanner efficiency:
- Scan time < 30 seconds per sample
- Memory usage < 500MB
- Report generation < 5 seconds

## Troubleshooting

### Tests Failing

1. Verify test data is downloaded
2. Check Python version (3.8+)
3. Ensure all dependencies are installed
4. Review test logs in `tests/logs/`

### Corpus Issues

If corpus validation fails:
1. Re-download corpus: `./scripts/download-test-data.sh --force`
2. Verify checksums: `python tests/verify_corpus.py`
3. Report issues to maintainers

## Contributing

When adding new features:
1. Write unit tests first (TDD)
2. Ensure tests pass locally
3. Add integration tests if needed
4. Update this README if test structure changes

---

Copyright (c) 2026, Aegis-Boot Research Project  
SPDX-License-Identifier: BSD-2-Clause-Patent
#!/usr/bin/env python3
"""
Aegis-Boot Test Runner

Comprehensive test runner for the Aegis-Boot project with support for
unit tests, integration tests, and corpus validation.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import argparse
import sys
import subprocess
from pathlib import Path
from datetime import datetime


def run_command(cmd: list, description: str) -> bool:
    """
    Run a command and report results.

    Args:
        cmd: Command to run
        description: Description of the test

    Returns:
        True if successful
    """
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"✅ {description} PASSED")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} FAILED")
        return False


def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(
        description='Aegis-Boot Test Runner'
    )
    
    parser.add_argument(
        '--unit',
        action='store_true',
        help='Run unit tests only'
    )
    
    parser.add_argument(
        '--integration',
        action='store_true',
        help='Run integration tests only'
    )
    
    parser.add_argument(
        '--corpus',
        action='store_true',
        help='Run corpus validation'
    )
    
    parser.add_argument(
        '--coverage',
        action='store_true',
        help='Generate coverage report'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--html-report',
        action='store_true',
        help='Generate HTML test report'
    )

    args = parser.parse_args()

    # Determine which tests to run
    run_all = not (args.unit or args.integration or args.corpus)
    
    results = []
    start_time = datetime.now()

    print(f"\n{'='*60}")
    print(f"Aegis-Boot Test Suite")
    print(f"{'='*60}")
    print(f"Start Time: {start_time.isoformat()}")
    print(f"{'='*60}\n")

    # Unit tests
    if run_all or args.unit:
        cmd = ['python', '-m', 'pytest', 'tests/unit/']
        
        if args.verbose:
            cmd.append('-v')
        
        if args.coverage:
            cmd.extend(['--cov=src/AegisScanner', '--cov-report=term'])
        
        if args.html_report:
            cmd.extend(['--html=test_report.html', '--self-contained-html'])
        
        results.append(run_command(cmd, "Unit Tests"))

    # Integration tests
    if run_all or args.integration:
        cmd = ['python', '-m', 'pytest', 'tests/integration/']
        
        if args.verbose:
            cmd.append('-v')
        
        if args.html_report:
            cmd.extend(['--html=integration_report.html', '--self-contained-html'])
        
        results.append(run_command(cmd, "Integration Tests"))

    # Corpus validation
    if run_all or args.corpus:
        cmd = ['python', 'tests/corpus_validation.py']
        
        if args.verbose:
            cmd.append('--verbose')
        
        results.append(run_command(cmd, "Corpus Validation"))

    # Generate coverage report
    if args.coverage:
        print(f"\n{'='*60}")
        print("Generating Coverage Report")
        print(f"{'='*60}")
        
        subprocess.run([
            'python', '-m', 'coverage', 'html',
            '--directory=htmlcov'
        ])
        
        print("Coverage report generated in htmlcov/")

    # Summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\n{'='*60}")
    print(f"Test Summary")
    print(f"{'='*60}")
    print(f"Total Tests: {len(results)}")
    print(f"Passed: {sum(results)}")
    print(f"Failed: {len(results) - sum(results)}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"{'='*60}\n")

    # Exit with appropriate code
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()



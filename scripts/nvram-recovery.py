#!/usr/bin/env python3
"""
Barzakh NVRAM Recovery Tool

This script provides automated recovery and rollback mechanisms for OVMF
NVRAM variables. It prevents irreversible bricking of test environments
during failed DXE injections or corrupted firmware states.

Usage:
    python3 nvram-recovery.py [OPTIONS]

Options:
    --backup            Create a backup of current NVRAM state
    --restore BACKUP    Restore NVRAM from a backup file
    --list              List available backups
    --clean             Remove old backups (keeps last 10)
    --verify            Verify NVRAM integrity
    --help              Show this help message

Examples:
    # Create backup before risky operation
    python3 nvram-recovery.py --backup

    # Restore from specific backup
    python3 nvram-recovery.py --restore backups/OVMF_VARS_20260511_103045.fd

    # List all available backups
    python3 nvram-recovery.py --list
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def log_info(message: str) -> None:
    """Log info message"""
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")

def log_success(message: str) -> None:
    """Log success message"""
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {message}")

def log_warning(message: str) -> None:
    """Log warning message"""
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")

def log_error(message: str) -> None:
    """Log error message"""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}", file=sys.stderr)

class NVRAMRecovery:
    """NVRAM Recovery Manager"""

    def __init__(self, workspace_dir: Optional[str] = None):
        """Initialize NVRAM Recovery Manager"""
        # Determine workspace directory
        if workspace_dir:
            self.workspace = Path(workspace_dir)
        else:
            home = Path.home()
            self.workspace = home / "barzakh-workspace"

        # Set paths
        self.edk2_dir = self.workspace / "edk2"
        self.ovmf_vars = self.edk2_dir / "Build" / "OvmfX64" / "DEBUG_GCC5" / "FV" / "OVMF_VARS.fd"
        self.backup_dir = self.workspace / "nvram-backups"
        self.metadata_file = self.backup_dir / "backups.json"

        # Create backup directory if it doesn't exist
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Load metadata
        self.metadata = self._load_metadata()

    def _load_metadata(self) -> Dict:
        """Load backup metadata"""
        if self.metadata_file.exists():
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        return {"backups": []}

    def _save_metadata(self) -> None:
        """Save backup metadata"""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)

    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def verify_nvram(self) -> bool:
        """Verify NVRAM file integrity"""
        log_info("Verifying NVRAM integrity...")

        if not self.ovmf_vars.exists():
            log_error(f"NVRAM file not found: {self.ovmf_vars}")
            return False

        # Check file size (OVMF_VARS.fd should be exactly 528KB for OVMF)
        expected_size = 540672  # 528KB
        actual_size = self.ovmf_vars.stat().st_size

        if actual_size != expected_size:
            log_warning(f"NVRAM size mismatch: expected {expected_size}, got {actual_size}")
            log_warning("This may indicate corruption or a different OVMF build")

        # Calculate hash
        nvram_hash = self._calculate_hash(self.ovmf_vars)
        log_info(f"NVRAM SHA256: {nvram_hash}")

        # Check if this hash matches any known good backup
        for backup in self.metadata["backups"]:
            if backup["hash"] == nvram_hash:
                log_success(f"NVRAM matches known good backup: {backup['name']}")
                return True

        log_warning("NVRAM does not match any known good backup")
        log_info("This may be normal if you haven't created a backup yet")
        return True

    def create_backup(self, description: str = "") -> bool:
        """Create a backup of current NVRAM state"""
        log_info("Creating NVRAM backup...")

        if not self.ovmf_vars.exists():
            log_error(f"NVRAM file not found: {self.ovmf_vars}")
            return False

        # Generate backup filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"OVMF_VARS_{timestamp}.fd"
        backup_path = self.backup_dir / backup_name

        # Copy NVRAM file
        try:
            shutil.copy2(self.ovmf_vars, backup_path)
        except Exception as e:
            log_error(f"Failed to create backup: {e}")
            return False

        # Calculate hash
        backup_hash = self._calculate_hash(backup_path)

        # Add to metadata
        backup_info = {
            "name": backup_name,
            "path": str(backup_path),
            "timestamp": datetime.now().isoformat(),
            "hash": backup_hash,
            "size": backup_path.stat().st_size,
            "description": description,
            "user": os.environ.get("USER", "unknown")
        }

        self.metadata["backups"].append(backup_info)
        self._save_metadata()

        log_success(f"Backup created: {backup_name}")
        log_info(f"Location: {backup_path}")
        log_info(f"SHA256: {backup_hash}")

        return True

    def list_backups(self) -> None:
        """List all available backups"""
        if not self.metadata["backups"]:
            log_info("No backups found")
            return

        log_info(f"Available backups ({len(self.metadata['backups'])} total):")
        print()

        for i, backup in enumerate(self.metadata["backups"], 1):
            print(f"{i}. {backup['name']}")
            print(f"   Timestamp: {backup['timestamp']}")
            print(f"   Size: {backup['size']} bytes")
            print(f"   SHA256: {backup['hash']}")
            print(f"   User: {backup['user']}")
            if backup.get('description'):
                print(f"   Description: {backup['description']}")
            print()

    def restore_backup(self, backup_identifier: str) -> bool:
        """Restore NVRAM from a backup"""
        log_info(f"Restoring NVRAM from backup: {backup_identifier}")

        # Find backup
        backup_path = None
        backup_info = None

        # Check if it's a direct path
        if Path(backup_identifier).exists():
            backup_path = Path(backup_identifier)
        else:
            # Search in metadata
            for backup in self.metadata["backups"]:
                if backup["name"] == backup_identifier or backup["path"] == backup_identifier:
                    backup_path = Path(backup["path"])
                    backup_info = backup
                    break

        if not backup_path or not backup_path.exists():
            log_error(f"Backup not found: {backup_identifier}")
            return False

        # Verify backup integrity
        if backup_info:
            current_hash = self._calculate_hash(backup_path)
            if current_hash != backup_info["hash"]:
                log_error("Backup file integrity check FAILED")
                log_error(f"Expected: {backup_info['hash']}")
                log_error(f"Got: {current_hash}")
                return False
            log_success("Backup integrity verified")

        # Create a backup of current state before restoring
        log_info("Creating safety backup of current state...")
        self.create_backup(description="Pre-restore safety backup")

        # Restore the backup
        try:
            shutil.copy2(backup_path, self.ovmf_vars)
        except Exception as e:
            log_error(f"Failed to restore backup: {e}")
            return False

        log_success("NVRAM restored successfully")
        log_info(f"Restored from: {backup_path}")

        # Verify restored NVRAM
        restored_hash = self._calculate_hash(self.ovmf_vars)
        if backup_info and restored_hash != backup_info["hash"]:
            log_error("Restored NVRAM hash mismatch!")
            return False

        log_success("Restoration verified")
        return True

    def clean_old_backups(self, keep_count: int = 10) -> None:
        """Remove old backups, keeping the most recent ones"""
        log_info(f"Cleaning old backups (keeping last {keep_count})...")

        if len(self.metadata["backups"]) <= keep_count:
            log_info("No backups to clean")
            return

        # Sort by timestamp
        sorted_backups = sorted(
            self.metadata["backups"],
            key=lambda x: x["timestamp"],
            reverse=True
        )

        # Keep the most recent ones
        to_keep = sorted_backups[:keep_count]
        to_remove = sorted_backups[keep_count:]

        # Remove old backups
        removed_count = 0
        for backup in to_remove:
            backup_path = Path(backup["path"])
            if backup_path.exists():
                try:
                    backup_path.unlink()
                    removed_count += 1
                    log_info(f"Removed: {backup['name']}")
                except Exception as e:
                    log_warning(f"Failed to remove {backup['name']}: {e}")

        # Update metadata
        self.metadata["backups"] = to_keep
        self._save_metadata()

        log_success(f"Cleaned {removed_count} old backups")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Barzakh NVRAM Recovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create a backup of current NVRAM state"
    )

    parser.add_argument(
        "--restore",
        metavar="BACKUP",
        help="Restore NVRAM from a backup file"
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available backups"
    )

    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove old backups (keeps last 10)"
    )

    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify NVRAM integrity"
    )

    parser.add_argument(
        "--workspace",
        help="Workspace directory (default: ~/barzakh-workspace)"
    )

    parser.add_argument(
        "--description",
        help="Description for backup"
    )

    args = parser.parse_args()

    # Create recovery manager
    recovery = NVRAMRecovery(workspace_dir=args.workspace)

    # Execute requested action
    if args.backup:
        success = recovery.create_backup(description=args.description or "")
        sys.exit(0 if success else 1)

    elif args.restore:
        success = recovery.restore_backup(args.restore)
        sys.exit(0 if success else 1)

    elif args.list:
        recovery.list_backups()
        sys.exit(0)

    elif args.clean:
        recovery.clean_old_backups()
        sys.exit(0)

    elif args.verify:
        success = recovery.verify_nvram()
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()



"""
Baseline Database - Store and retrieve known-good firmware baselines.

Uses SQLite for persistent storage of firmware image metadata, FV/FFS
inventories, and hash records for efficient diffing against baselines.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from ..detectors.fv_parser import FirmwareVolumeParser, FirmwareVolume, FirmwareFile
except ImportError:
    from detectors.fv_parser import FirmwareVolumeParser, FirmwareVolume, FirmwareFile


SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    firmware_path TEXT,
    firmware_hash TEXT NOT NULL,
    firmware_size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    vendor TEXT,
    platform TEXT,
    version TEXT
);

CREATE TABLE IF NOT EXISTS volumes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    baseline_id INTEGER NOT NULL,
    guid TEXT NOT NULL,
    offset INTEGER NOT NULL,
    size INTEGER NOT NULL,
    attributes INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    FOREIGN KEY (baseline_id) REFERENCES baselines(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    volume_id INTEGER NOT NULL,
    guid TEXT NOT NULL,
    file_type INTEGER NOT NULL,
    file_type_name TEXT NOT NULL,
    attributes INTEGER NOT NULL,
    size INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    hash TEXT NOT NULL,
    FOREIGN KEY (volume_id) REFERENCES volumes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_files_guid ON files(guid);
CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash);
CREATE INDEX IF NOT EXISTS idx_volumes_guid ON volumes(guid);
CREATE INDEX IF NOT EXISTS idx_baselines_name ON baselines(name);
"""


class BaselineDB:
    """
    SQLite-backed database for firmware baselines.

    Stores parsed FV/FFS structure so diffs can be computed against
    stored baselines without re-parsing the original firmware image.
    """

    def __init__(self, db_path: str = 'aegis_baselines.db'):
        """
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self):
        """Initialize database schema."""
        cursor = self.conn.cursor()
        cursor.executescript(SCHEMA_SQL)

        # Check/set schema version
        cursor.execute("SELECT COUNT(*) FROM schema_info")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO schema_info (version) VALUES (?)", (SCHEMA_VERSION,))

        self.conn.commit()

    def register_baseline(self, name: str, firmware_path: str,
                          description: str = '',
                          vendor: str = '',
                          platform: str = '',
                          version: str = '') -> int:
        """
        Register a firmware image as a known-good baseline.

        Parses the firmware and stores its full FV/FFS structure.

        Args:
            name: Unique name for this baseline
            firmware_path: Path to firmware image
            description: Human-readable description
            vendor: Firmware vendor
            platform: Platform identifier
            version: Firmware version string

        Returns:
            Baseline ID

        Raises:
            FileNotFoundError: If firmware_path doesn't exist
            ValueError: If name already exists
        """
        path = Path(firmware_path)
        if not path.exists():
            raise FileNotFoundError(f"Firmware image not found: {firmware_path}")

        # Check for duplicate name
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM baselines WHERE name = ?", (name,))
        if cursor.fetchone():
            raise ValueError(f"Baseline '{name}' already exists")

        # Read and hash firmware
        with open(firmware_path, 'rb') as f:
            fw_data = f.read()
        fw_hash = hashlib.sha256(fw_data).hexdigest()
        fw_size = len(fw_data)

        # Parse firmware
        parser = FirmwareVolumeParser()
        volumes = parser.parse(firmware_path)

        # Store baseline record
        cursor.execute(
            """INSERT INTO baselines (name, description, firmware_path, firmware_hash,
               firmware_size, created_at, vendor, platform, version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, firmware_path, fw_hash, fw_size,
             datetime.now().isoformat(), vendor, platform, version)
        )
        baseline_id = cursor.lastrowid

        # Store volumes and files
        for fv in volumes:
            cursor.execute(
                """INSERT INTO volumes (baseline_id, guid, offset, size, attributes, file_count)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (baseline_id, fv.guid, fv.offset, fv.size, fv.attributes, len(fv.files))
            )
            volume_id = cursor.lastrowid

            for ff in fv.files:
                file_type_name = FirmwareVolumeParser.FILE_TYPES.get(
                    ff.type, f'UNKNOWN(0x{ff.type:02x})')
                cursor.execute(
                    """INSERT INTO files (volume_id, guid, file_type, file_type_name,
                       attributes, size, offset, hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (volume_id, ff.guid, ff.type, file_type_name,
                     ff.attributes, ff.size, ff.offset, ff.hash)
                )

        self.conn.commit()
        return baseline_id

    def get_baseline(self, name: str) -> Optional[Dict]:
        """Get baseline metadata by name."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM baselines WHERE name = ?", (name,))
        row = cursor.fetchone()
        if not row:
            return None

        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))

    def list_baselines(self) -> List[Dict]:
        """List all registered baselines."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT name, description, firmware_hash, firmware_size, "
            "created_at, vendor, platform, version FROM baselines ORDER BY created_at DESC")

        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_baseline_volumes(self, name: str) -> List[FirmwareVolume]:
        """
        Reconstruct FirmwareVolume objects from stored baseline.

        Args:
            name: Baseline name

        Returns:
            List of FirmwareVolume with FirmwareFile objects (data field empty)
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM baselines WHERE name = ?", (name,))
        row = cursor.fetchone()
        if not row:
            return []
        baseline_id = row[0]

        cursor.execute(
            "SELECT id, guid, offset, size, attributes FROM volumes WHERE baseline_id = ?",
            (baseline_id,))
        volume_rows = cursor.fetchall()

        volumes = []
        for vol_row in volume_rows:
            vol_id, guid, offset, size, attributes = vol_row

            cursor.execute(
                "SELECT guid, file_type, attributes, size, offset, hash "
                "FROM files WHERE volume_id = ?", (vol_id,))
            file_rows = cursor.fetchall()

            files = []
            for fr in file_rows:
                files.append(FirmwareFile(
                    guid=fr[0],
                    type=fr[1],
                    attributes=fr[2],
                    size=fr[3],
                    offset=fr[4],
                    hash=fr[5],
                    data=b'',  # Data not stored in DB
                ))

            volumes.append(FirmwareVolume(
                guid=guid,
                size=size,
                offset=offset,
                attributes=attributes,
                files=files,
            ))

        return volumes

    def get_file_hashes(self, name: str) -> Dict[str, str]:
        """
        Get all file GUID->hash mappings for a baseline.

        Useful for quick lookup of expected hashes.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM baselines WHERE name = ?", (name,))
        row = cursor.fetchone()
        if not row:
            return {}
        baseline_id = row[0]

        cursor.execute(
            """SELECT f.guid, f.hash FROM files f
               JOIN volumes v ON f.volume_id = v.id
               WHERE v.baseline_id = ?""",
            (baseline_id,))

        return {row[0]: row[1] for row in cursor.fetchall()}

    def delete_baseline(self, name: str) -> bool:
        """Delete a baseline and all its associated data."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM baselines WHERE name = ?", (name,))
        row = cursor.fetchone()
        if not row:
            return False

        cursor.execute("DELETE FROM baselines WHERE id = ?", (row[0],))
        self.conn.commit()
        return True

    def close(self):
        """Close database connection."""
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

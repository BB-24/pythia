import sqlite3
import time
from typing import Dict, List

from src.exceptions import DatabaseError
from src.logger import logger

class CVEClient:
    def __init__(self, db_path: str = "cve_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """FR 3.2: Initializes the local SQLite cache."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id TEXT,
                        package_name TEXT,
                        ecosystem TEXT,
                        vulnerable_versions TEXT,
                        fixed_version TEXT,
                        severity TEXT,
                        source TEXT,
                        PRIMARY KEY (id, package_name, ecosystem, fixed_version)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS package_cache (
                        package_name TEXT NOT NULL,
                        ecosystem TEXT NOT NULL,
                        checked_at REAL NOT NULL,
                        vulnerability_count INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (package_name, ecosystem)
                    )
                    """
                )
        except sqlite3.Error as exc:
            logger.error("Unable to initialize vulnerability database %s: %s", self.db_path, exc, exc_info=True)
            raise DatabaseError("Unable to initialize vulnerability database") from exc

    def get_vulnerabilities(self, package: str, ecosystem: str) -> List[Dict]:
        """Fetches cached vulnerabilities for a specific package."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM vulnerabilities WHERE package_name = ? AND ecosystem = ? ORDER BY severity DESC",
                    (package, ecosystem),
                )
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            logger.error("Unable to query vulnerability database: %s", exc, exc_info=True)
            raise DatabaseError("Unable to query vulnerability database") from exc

    def insert_vulnerability(self, vuln_data: Dict):
        """Inserts a new vulnerability record into the local cache."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities
                    (id, package_name, ecosystem, vulnerable_versions, fixed_version, severity, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vuln_data["id"], vuln_data["package_name"], vuln_data["ecosystem"],
                        vuln_data.get("vulnerable_versions", "unknown"), vuln_data.get("fixed_version", "unknown"),
                        vuln_data.get("severity", "MEDIUM"), vuln_data.get("source", "unknown"),
                    ),
                )
        except sqlite3.Error as exc:
            logger.error("Unable to cache vulnerability %s: %s", vuln_data.get("id"), exc, exc_info=True)
            raise DatabaseError("Unable to cache vulnerability") from exc

    def is_package_cached(self, package: str, ecosystem: str, max_age_seconds: float) -> bool:
        """Return whether a positive or negative lookup is still fresh."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT checked_at FROM package_cache WHERE package_name = ? AND ecosystem = ?",
                    (package, ecosystem),
                ).fetchone()
                return row is not None and time.time() - row[0] <= max_age_seconds
        except sqlite3.Error as exc:
            logger.error("Unable to query package cache: %s", exc, exc_info=True)
            raise DatabaseError("Unable to query package cache") from exc

    def mark_package_cached(self, package: str, ecosystem: str, vulnerability_count: int):
        """Record a completed upstream lookup, including an empty result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO package_cache
                    (package_name, ecosystem, checked_at, vulnerability_count)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(package_name, ecosystem) DO UPDATE SET
                        checked_at = excluded.checked_at,
                        vulnerability_count = excluded.vulnerability_count
                    """,
                    (package, ecosystem, time.time(), vulnerability_count),
                )
        except sqlite3.Error as exc:
            logger.error("Unable to cache package lookup %s: %s", package, exc, exc_info=True)
            raise DatabaseError("Unable to cache package lookup") from exc

    def clear(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM vulnerabilities")
                conn.execute("DELETE FROM package_cache")
        except sqlite3.Error as exc:
            logger.error("Unable to clear vulnerability database: %s", exc, exc_info=True)
            raise DatabaseError("Unable to clear vulnerability database") from exc
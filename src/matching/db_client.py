import sqlite3
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

    def clear(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM vulnerabilities")
        except sqlite3.Error as exc:
            logger.error("Unable to clear vulnerability database: %s", exc, exc_info=True)
            raise DatabaseError("Unable to clear vulnerability database") from exc
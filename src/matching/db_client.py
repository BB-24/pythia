import sqlite3
from typing import Dict, List


class CVEClient:
    def __init__(self, db_path: str = "cve_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """FR 3.2: Initializes the local SQLite cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
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
            conn.commit()

    def get_vulnerabilities(self, package: str, ecosystem: str) -> List[Dict]:
        """Fetches cached vulnerabilities for a specific package."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE package_name = ? AND ecosystem = ? ORDER BY severity DESC",
                (package, ecosystem),
            )
            return [dict(row) for row in cursor.fetchall()]

    def insert_vulnerability(self, vuln_data: Dict):
        """Inserts a new vulnerability record into the local cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities
                (id, package_name, ecosystem, vulnerable_versions, fixed_version, severity, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln_data["id"],
                    vuln_data["package_name"],
                    vuln_data["ecosystem"],
                    vuln_data.get("vulnerable_versions", "unknown"),
                    vuln_data.get("fixed_version", "unknown"),
                    vuln_data.get("severity", "MEDIUM"),
                    vuln_data.get("source", "unknown"),
                ),
            )
            conn.commit()

    def clear(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM vulnerabilities")
            conn.commit()
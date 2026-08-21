from __future__ import annotations

import re
from typing import Dict, List

from packaging import version

from .db_client import CVEClient
from .normalizer import normalize_ecosystem, normalize_package_name
from .updater import IntelligenceUpdater


class MatchingEngine:
    def __init__(self, db_path: str = "cve_cache.db"):
        self.db = CVEClient(db_path=db_path)
        self.updater = IntelligenceUpdater(self.db)
        self.queried_packages: set[str] = set()

    def scan_sbom(self, sbom_data: Dict) -> List[Dict]:
        """FR 3.4 & 3.5: Compares SBOM packages against intelligence database."""
        print("=== Starting Vulnerability Matching ===")
        findings: List[Dict] = []

        for pkg in sbom_data.get("packages", []):
            ecosystem = normalize_ecosystem(pkg["type"])
            if ecosystem == "Unknown":
                continue

            normalized_name = normalize_package_name(pkg["name"], ecosystem)
            cache_key = f"{normalized_name}::{ecosystem}"

            if cache_key not in self.queried_packages:
                self.updater.fetch_and_cache(normalized_name, ecosystem)
                self.queried_packages.add(cache_key)

            known_vulns = self.db.get_vulnerabilities(normalized_name, ecosystem)
            for vuln in known_vulns:
                if self._is_vulnerable(pkg["version"], vuln["fixed_version"]):
                    findings.append(
                        {
                            "cve_id": vuln["id"],
                            "package": pkg["name"],
                            "installed_version": pkg["version"],
                            "fixed_version": vuln["fixed_version"],
                            "severity": vuln["severity"],
                            "source": vuln.get("source", "unknown"),
                        }
                    )

        print(f"[+] Matching complete. Found {len(findings)} vulnerabilities.")
        return findings

    def _is_vulnerable(self, installed_ver: str, fixed_ver: str) -> bool:
        """FR 3.4: Compares versions, including Debian epoch variants."""
        if not installed_ver or not fixed_ver or fixed_ver == "unknown":
            return bool(fixed_ver == "unknown")

        try:
            if self._looks_like_debian_version(installed_ver) or self._looks_like_debian_version(fixed_ver):
                return self._compare_debian_versions(installed_ver, fixed_ver) < 0
            return version.parse(self._clean_version(installed_ver)) < version.parse(self._clean_version(fixed_ver))
        except (TypeError, ValueError, version.InvalidVersion):
            return True

    def _clean_version(self, value: str) -> str:
        value = str(value).strip()
        if ":" in value:
            value = value.split(":")[-1]
        return value

    def _looks_like_debian_version(self, value: str) -> bool:
        return bool(re.search(r"\d+:|~", str(value))) or bool(re.search(r"\d+\.\d+.*-\d+", str(value)))

    def _compare_debian_versions(self, left: str, right: str) -> int:
        def parse_deb(value: str):
            value = str(value).strip()
            epoch = 0
            if ":" in value:
                epoch_part, value = value.split(":", 1)
                epoch = int(epoch_part)

            if "-" in value:
                upstream, revision = value.split("-", 1)
            else:
                upstream, revision = value, ""

            return epoch, upstream, revision

        left_epoch, left_upstream, left_revision = parse_deb(left)
        right_epoch, right_upstream, right_revision = parse_deb(right)

        if left_epoch != right_epoch:
            return -1 if left_epoch < right_epoch else 1

        left_key = self._deb_version_key(left_upstream)
        right_key = self._deb_version_key(right_upstream)
        if left_key != right_key:
            return -1 if left_key < right_key else 1

        left_rev = self._deb_version_key(left_revision)
        right_rev = self._deb_version_key(right_revision)
        if left_rev != right_rev:
            return -1 if left_rev < right_rev else 1
        return 0

    def _deb_version_key(self, value: str):
        value = str(value)
        if not value:
            return (0, [])
        parts = re.split(r"([0-9]+|[A-Za-z]+|[^0-9A-Za-z]+)", value)
        normalized = []
        for chunk in parts:
            if not chunk:
                continue
            if chunk.isdigit():
                normalized.append((0, int(chunk)))
            elif chunk.replace("~", "").isdigit():
                normalized.append((0, int(chunk.replace("~", ""))))
            else:
                normalized.append((1, chunk.lower()))
        return tuple(normalized)
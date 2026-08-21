from __future__ import annotations

import requests

from .db_client import CVEClient


class IntelligenceUpdater:
    def __init__(self, db_client: CVEClient):
        self.db_client = db_client
        self.osv_url = "https://api.osv.dev/v1/query"
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_and_cache(self, package_name: str, ecosystem: str):
        """FR 3.1: Fetches vulnerability data from OSV and caches it locally."""
        if not package_name:
            return

        try:
            osv_vulns = self._fetch_osv(package_name, ecosystem)
            for vuln in osv_vulns:
                self._cache_vulnerability(vuln, package_name, ecosystem, source="OSV")

            if not osv_vulns:
                nvd_vulns = self._fetch_nvd(package_name)
                for vuln in nvd_vulns:
                    self._cache_vulnerability(vuln, package_name, ecosystem, source="NVD")
        except requests.RequestException:
            return

    def _fetch_osv(self, package_name: str, ecosystem: str):
        payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
        response = requests.post(self.osv_url, json=payload, timeout=20)
        if response.status_code != 200:
            return []
        data = response.json()
        return data.get("vulns", [])

    def _fetch_nvd(self, package_name: str):
        params = {"keywordSearch": package_name, "resultsPerPage": 5, "startIndex": 0}
        response = requests.get(self.nvd_url, params=params, timeout=20)
        if response.status_code != 200:
            return []

        results = response.json().get("vulnerabilities", [])
        parsed = []
        for item in results:
            cve = item.get("cve", {})
            parsed.append(
                {
                    "id": cve.get("id"),
                    "severity": self._extract_nvd_severity(cve),
                    "fixed_version": "unknown",
                    "summary": cve.get("descriptions", [{}])[0].get("value", ""),
                }
            )
        return parsed

    def _cache_vulnerability(self, vuln: dict, package_name: str, ecosystem: str, source: str):
        vuln_id = vuln.get("id")
        if not vuln_id:
            return

        fixed_version = "unknown"
        if "affected" in vuln:
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_version = str(event["fixed"])
                            break
                    if fixed_version != "unknown":
                        break
                if fixed_version != "unknown":
                    break

        self.db_client.insert_vulnerability(
            {
                "id": vuln_id,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "vulnerable_versions": "unknown",
                "fixed_version": fixed_version,
                "severity": self._extract_severity(vuln),
                "source": source,
            }
        )

    def _extract_severity(self, vuln: dict) -> str:
        """Extracts a normalized CVSS severity level."""
        severities = vuln.get("severity", [])
        if severities:
            score = str(severities[0].get("score", "")).upper()
            if "CRITICAL" in score:
                return "CRITICAL"
            if "HIGH" in score:
                return "HIGH"
            if "MEDIUM" in score:
                return "MEDIUM"
            if "LOW" in score:
                return "LOW"

        summary = (vuln.get("summary") or "").upper()
        if "CRITICAL" in summary:
            return "CRITICAL"
        if "HIGH" in summary:
            return "HIGH"
        if "MEDIUM" in summary:
            return "MEDIUM"
        if "LOW" in summary:
            return "LOW"
        return "MEDIUM"

    def _extract_nvd_severity(self, cve: dict) -> str:
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}]) or metrics.get("cvssMetricV30", [{}])
        if not cvss:
            return "MEDIUM"
        score = str(cvss[0].get("cvssData", {}).get("baseSeverity", "MEDIUM")).upper()
        return score if score in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"
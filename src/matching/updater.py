from __future__ import annotations

from collections.abc import Mapping

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.exceptions import UpstreamAPIError
from src.logger import logger
from .db_client import CVEClient


class IntelligenceUpdater:
    def __init__(self, db_client: CVEClient):
        self.db_client = db_client
        self.osv_url = "https://api.osv.dev/v1/query"
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.5,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def fetch_and_cache(self, package_name: str, ecosystem: str):
        """FR 3.1: Fetches vulnerability data from OSV and caches it locally."""
        if not package_name:
            return

        osv_vulns = self._fetch_osv(package_name, ecosystem)
        for vuln in osv_vulns:
            self._cache_vulnerability(vuln, package_name, ecosystem, source="OSV")

        if not osv_vulns:
            nvd_vulns = self._fetch_nvd(package_name)
            for vuln in nvd_vulns:
                self._cache_vulnerability(vuln, package_name, ecosystem, source="NVD")

    def _fetch_osv(self, package_name: str, ecosystem: str):
        payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
        try:
            response = self.session.post(self.osv_url, json=payload, timeout=10)
            if response.status_code >= 400:
                raise UpstreamAPIError(f"OSV returned HTTP {response.status_code}")
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.error("OSV request failed for %s: %s", package_name, exc, exc_info=True)
            raise UpstreamAPIError(f"OSV request failed for {package_name}") from exc
        return data.get("vulns", [])

    def _fetch_nvd(self, package_name: str):
        params = {"keywordSearch": package_name, "resultsPerPage": 5, "startIndex": 0}
        try:
            response = self.session.get(self.nvd_url, params=params, timeout=10)
            if response.status_code >= 400:
                raise UpstreamAPIError(f"NVD returned HTTP {response.status_code}")
            results = response.json().get("vulnerabilities", [])
        except (requests.RequestException, ValueError) as exc:
            logger.error("NVD request failed for %s: %s", package_name, exc, exc_info=True)
            raise UpstreamAPIError(f"NVD request failed for {package_name}") from exc
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
        if isinstance(severities, str):
            severity = self._severity_from_value(severities)
            if severity:
                return severity
        elif isinstance(severities, Mapping):
            severity = self._severity_from_value(severities.get("score", ""))
            if severity:
                return severity
        elif isinstance(severities, (list, tuple)):
            for entry in severities:
                value = entry.get("score", "") if isinstance(entry, Mapping) else entry
                severity = self._severity_from_value(value)
                if severity:
                    return severity

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

    def _severity_from_value(self, value) -> str | None:
        normalized = str(value or "").upper()
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if severity in normalized:
                return severity

        try:
            score = float(value)
        except (TypeError, ValueError):
            return None
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return None

    def _extract_nvd_severity(self, cve: dict) -> str:
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}]) or metrics.get("cvssMetricV30", [{}])
        if not cvss:
            return "MEDIUM"
        score = str(cvss[0].get("cvssData", {}).get("baseSeverity", "MEDIUM")).upper()
        return score if score in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "MEDIUM"
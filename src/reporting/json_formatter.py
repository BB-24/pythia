from datetime import datetime, timezone
from typing import Dict, List


def generate_json_report(image_tag: str, sbom: Dict, vulnerabilities: List[Dict]) -> Dict:
    """FR 4.1: Structures the complete scan results into a standardized JSON payload."""
    critical = len([v for v in vulnerabilities if v.get("severity") == "CRITICAL"])
    high = len([v for v in vulnerabilities if v.get("severity") == "HIGH"])
    medium = len([v for v in vulnerabilities if v.get("severity") == "MEDIUM"])
    low = len([v for v in vulnerabilities if v.get("severity") == "LOW"])

    return {
        "scan_metadata": {
            "target_image": image_tag,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "summary": {
            "total_packages_scanned": sbom.get("total_packages", 0),
            "total_vulnerabilities": len(vulnerabilities),
            "breakdown": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
        },
        "sbom": sbom.get("packages", []),
        "vulnerabilities": vulnerabilities,
    }
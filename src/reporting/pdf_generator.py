from __future__ import annotations

from jinja2 import Template
from weasyprint import HTML

from src.exceptions import ReportGenerationError
from src.logger import logger

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: 'Helvetica Neue', Arial, sans-serif; margin: 40px; color: #333; }
        h1 { color: #2c3e50; border-bottom: 2px solid #34495e; padding-bottom: 10px; }
        .summary-box { background: #f8f9fa; padding: 20px; border-left: 5px solid #34495e; margin-bottom: 30px; }
        .severity-chip { padding: 4px 8px; border-radius: 999px; font-weight: bold; }
        .severity-CRITICAL { background: #f8d7da; color: #721c24; }
        .severity-HIGH { background: #f5c6cb; color: #842029; }
        .severity-MEDIUM { background: #fff3cd; color: #664d03; }
        .severity-LOW { background: #d1e7dd; color: #0f5132; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
        th, td { border: 1px solid #dee2e6; padding: 12px; text-align: left; }
        th { background-color: #34495e; color: white; }
        tr:nth-child(even) { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <h1>Container Security Scan Report</h1>

    <div class="summary-box">
        <h2>Executive Summary</h2>
        <p><strong>Target Image:</strong> {{ metadata.target_image }}</p>
        <p><strong>Scan Date (UTC):</strong> {{ metadata.timestamp }}</p>
        <p><strong>Total Packages Scanned:</strong> {{ summary.total_packages_scanned }}</p>
        <p><strong>Total Vulnerabilities:</strong> {{ summary.total_vulnerabilities }}</p>
        <ul>
            <li>Critical: {{ summary.breakdown.critical }}</li>
            <li>High: {{ summary.breakdown.high }}</li>
            <li>Medium: {{ summary.breakdown.medium }}</li>
            <li>Low: {{ summary.breakdown.low }}</li>
        </ul>
    </div>

    <h2>Detailed Vulnerability Findings</h2>
    <table>
        <thead>
            <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Package</th>
                <th>Installed Version</th>
                <th>Remediation (Fixed In)</th>
            </tr>
        </thead>
        <tbody>
            {% for vuln in vulnerabilities %}
            <tr>
                <td><strong>{{ vuln.cve_id }}</strong></td>
                <td><span class="severity-chip severity-{{ vuln.severity }}">{{ vuln.severity }}</span></td>
                <td>{{ vuln.package }}</td>
                <td>{{ vuln.installed_version }}</td>
                <td>{{ vuln.fixed_version }}</td>
            </tr>
            {% endfor %}
            {% if not vulnerabilities %}
            <tr>
                <td colspan="5" style="text-align: center;">No vulnerabilities found!</td>
            </tr>
            {% endif %}
        </tbody>
    </table>
</body>
</html>
"""


def generate_pdf(report_data: dict, output_path: str):
    """FR 4.3: Renders HTML template with scan data and outputs a PDF."""
    logger.info("Generating PDF report at %s", output_path)
    try:
        template = Template(REPORT_TEMPLATE)
        html_content = template.render(
            metadata=report_data["scan_metadata"],
            summary=report_data["summary"],
            vulnerabilities=report_data["vulnerabilities"],
        )
        HTML(string=html_content).write_pdf(output_path)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        logger.error("PDF report generation failed: %s", exc, exc_info=True)
        raise ReportGenerationError(f"Unable to generate PDF report: {output_path}") from exc
    logger.info("PDF report saved to %s", output_path)
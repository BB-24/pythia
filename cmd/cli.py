import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import click

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.discovery.manager import DiscoveryManager
from src.ingestion.manager import IngestionManager
from src.matching.engine import MatchingEngine
from src.reporting.json_formatter import generate_json_report
from src.reporting.pdf_generator import generate_pdf
from src.exceptions import ScannerBaseException
from src.logger import logger, quiet_console_logging, scan_logging


def _stage(label: str, detail: str):
    click.echo(f"  {click.style(label, fg='cyan', bold=True):<18}{detail}")


def _print_scan_header(scan_id: str, target: str):
    click.echo()
    click.echo(click.style("PYTHIA  /  CONTAINER SECURITY SCAN", fg="bright_white", bold=True))
    click.echo(click.style("=" * 38, fg="cyan"))
    click.echo(f"  {click.style('Scan ID', fg='bright_black'):<18}{scan_id}")
    click.echo(f"  {click.style('Target', fg='bright_black'):<18}{target}")
    click.echo()


def _print_summary(report_data: dict, output_path: Path, log_path: Path, pdf_path: str | None):
    summary = report_data["summary"]
    breakdown = summary["breakdown"]
    click.echo(click.style("SCAN COMPLETE", fg="green", bold=True))
    click.echo(click.style("-" * 38, fg="green"))
    click.echo(f"  Packages scanned    {summary['total_packages_scanned']}")
    click.echo(f"  Vulnerabilities      {summary['total_vulnerabilities']}")
    critical = click.style(f"C {breakdown['critical']}", fg="red")
    high = click.style(f"H {breakdown['high']}", fg="yellow")
    medium = click.style(f"M {breakdown['medium']}", fg="bright_yellow")
    low = click.style(f"L {breakdown['low']}", fg="green")
    click.echo(
        f"  Severity             {critical}  {high}  {medium}  {low}"
    )
    click.echo()
    click.echo(click.style("ARTIFACTS", fg="bright_white", bold=True))
    click.echo(f"  JSON                 {output_path}")
    if pdf_path:
        click.echo(f"  PDF                  {pdf_path}")
    click.echo(f"  Log                  {log_path}")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.1.0", prog_name="pythia")
def cli():
    """Pythia container vulnerability scanner."""


@cli.command("scan")
@click.argument("image_ref", required=False)
@click.option(
    "--archive",
    "archive_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a local Docker image tar archive.",
)
@click.option("--pdf", is_flag=True, help="Generate a PDF report alongside JSON.")
@click.option(
    "--out",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output JSON file path. Defaults to a unique scan report path.",
)
@click.option("--registry-user", help="Username for a private registry.")
@click.option("--registry-password", hide_input=True, help="Password for a private registry.")
@click.option("--scan-id", help="Custom scan ID; generated automatically when omitted.")
def scan(image_ref, archive_path, pdf, output_path, registry_user, registry_password, scan_id):
    """Scan a registry image or local Docker archive."""
    if bool(image_ref) == bool(archive_path):
        raise click.UsageError("Provide exactly one IMAGE_REF or --archive PATH.")
    if scan_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", scan_id):
        raise click.UsageError(
            "SCAN_ID may contain only letters, numbers, dots, underscores, and hyphens."
        )

    scan_id = scan_id or f"scan-{datetime.now(timezone.utc):%Y%m%dT%H%M%S}-{uuid4().hex[:8]}"
    output_path = output_path or Path("scan_reports") / "json" / f"{scan_id}.json"
    ingestion = IngestionManager()
    with scan_logging(scan_id) as log_path:
        with quiet_console_logging():
            try:
                image_target = str(archive_path) if archive_path else image_ref
                _print_scan_header(scan_id, image_target)
                if archive_path:
                    _stage("INGEST", "Loading local image archive")
                    rootfs = ingestion.ingest_from_archive(str(archive_path))
                else:
                    _stage("INGEST", "Pulling image layers from registry")
                    rootfs = ingestion.ingest_from_registry(
                        image_ref,
                        registry_username=registry_user,
                        registry_password=registry_password,
                    )

                _stage("DISCOVERY", "Finding installed packages")
                sbom_data = DiscoveryManager(rootfs).generate_sbom().to_json()
                _stage("MATCHING", "Checking vulnerability intelligence")
                vulnerabilities = MatchingEngine().scan_sbom(sbom_data)
                report_data = generate_json_report(image_target, sbom_data, vulnerabilities, scan_id=scan_id)

                _stage("REPORT", "Writing JSON report")
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with output_path.open("w", encoding="utf-8") as handle:
                    json.dump(report_data, handle, indent=2)
                generated_pdf_path = None
                if pdf:
                    _stage("REPORT", "Rendering PDF report")
                    pdf_path = output_path.parent.parent / "pdf" / f"{output_path.stem}.pdf"
                    pdf_path.parent.mkdir(parents=True, exist_ok=True)
                    generated_pdf_path = generate_pdf(report_data, output_path=pdf_path)
                _print_summary(report_data, output_path, log_path, generated_pdf_path)
            except ScannerBaseException as exc:
                logger.error("Scan failed: %s", exc)
                raise click.ClickException(str(exc)) from exc
            except KeyboardInterrupt:
                raise click.Abort() from None
            finally:
                ingestion.cleanup()


def main():
    cli()


if __name__ == "__main__":
    main()
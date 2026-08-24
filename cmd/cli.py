import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.discovery.manager import DiscoveryManager
from src.ingestion.manager import IngestionManager
from src.matching.engine import MatchingEngine
from src.reporting.json_formatter import generate_json_report
from src.reporting.pdf_generator import generate_pdf
from src.exceptions import ScannerBaseException
from src.logger import logger, quiet_console_logging, scan_logging


def _run_stage(console: Console, label: str, detail: str, operation):
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}[/cyan]"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task(f"{label}  {detail}", total=None)
        result = operation()
        progress.update(task, description=f"[green]Done[/green]  {label}  {detail}")
    return result


def _print_scan_header(console: Console, scan_id: str, target: str):
    details = Table.grid(padding=(0, 2))
    details.add_column(style="dim", width=10)
    details.add_column()
    details.add_row("Scan ID", scan_id)
    details.add_row("Target", target)
    console.print(Panel(details, title="[bold cyan]PYTHIA / SECURITY SCAN[/bold cyan]", border_style="cyan"))


def _file_link(path: str | Path) -> str:
    resolved = Path(path).resolve()
    return f"[link={resolved.as_uri()}][cyan]{resolved}[/cyan][/link]"


def _print_summary(console: Console, report_data: dict, output_path: Path,
                   log_path: Path, pdf_path: str | None, duration: float):
    summary = report_data["summary"]
    breakdown = summary["breakdown"]
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column(style="dim", width=20)
    summary_table.add_column(justify="right")
    summary_table.add_row("Packages scanned", str(summary["total_packages_scanned"]))
    summary_table.add_row("Vulnerabilities", str(summary["total_vulnerabilities"]))
    summary_table.add_row("Scan duration", f"{duration:.1f}s")
    summary_table.add_row("CRITICAL", f"[red]{breakdown['critical']}[/red]")
    summary_table.add_row("HIGH", f"[yellow]{breakdown['high']}[/yellow]")
    summary_table.add_row("MEDIUM", f"[bright_yellow]{breakdown['medium']}[/bright_yellow]")
    summary_table.add_row("LOW", f"[green]{breakdown['low']}[/green]")
    console.print(Panel(summary_table, title="[bold green]SCAN COMPLETE[/bold green]", border_style="green"))

    artifacts = Table(show_header=False, box=None, padding=(0, 2))
    artifacts.add_column(style="dim", width=10)
    artifacts.add_column()
    artifacts.add_row("JSON", _file_link(output_path))
    if pdf_path:
        artifacts.add_row("PDF", _file_link(pdf_path))
    artifacts.add_row("Log", _file_link(log_path))
    console.print(Panel(artifacts, title="[bold]ARTIFACTS[/bold]", border_style="blue"))

    total_critical = breakdown["critical"]
    if total_critical:
        console.print(
            f"[bold red]Action required:[/bold red] {total_critical} Critical "
            "vulnerability found. Review the PDF report for remediation steps."
            if pdf_path else
            f"[bold red]Action required:[/bold red] {total_critical} Critical "
            "vulnerability found. Review the JSON report for remediation steps."
        )
    elif summary["total_vulnerabilities"]:
        console.print("[yellow]Review the vulnerability findings before deploying this image.[/yellow]")


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
@click.option("--verbose", is_flag=True, help="Show INFO logs in the terminal.")
@click.option("--debug", is_flag=True, help="Show DEBUG logs in the terminal.")
def scan(image_ref, archive_path, pdf, output_path, registry_user, registry_password,
         scan_id, verbose, debug):
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
    console = Console()
    started_at = datetime.now().timestamp()
    with scan_logging(scan_id) as log_path:
        console_level =  logging.DEBUG if debug else logging.INFO if verbose else logging.ERROR
        with quiet_console_logging(console_level):
            try:
                image_target = str(archive_path) if archive_path else image_ref
                _print_scan_header(console, scan_id, image_target)
                if archive_path:
                    rootfs = _run_stage(console, "INGEST", "Loading local image archive",
                                        lambda: ingestion.ingest_from_archive(str(archive_path)))
                else:
                    rootfs = _run_stage(
                        console, "INGEST", "Pulling image layers from registry",
                        lambda: ingestion.ingest_from_registry(
                            image_ref,
                            registry_username=registry_user,
                            registry_password=registry_password,
                        ),
                    )

                sbom_data = _run_stage(
                    console, "DISCOVERY", "Finding installed packages",
                    lambda: DiscoveryManager(rootfs).generate_sbom().to_json(),
                )
                vulnerabilities = _run_stage(
                    console, "MATCHING", "Checking vulnerability intelligence",
                    lambda: MatchingEngine().scan_sbom(sbom_data),
                )
                report_data = generate_json_report(image_target, sbom_data, vulnerabilities, scan_id=scan_id)

                def write_json_report():
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    with output_path.open("w", encoding="utf-8") as handle:
                        json.dump(report_data, handle, indent=2)

                _run_stage(console, "REPORT", "Writing JSON report", write_json_report)
                generated_pdf_path = None
                if pdf:
                    pdf_path = output_path.parent.parent / "pdf" / f"{output_path.stem}.pdf"
                    pdf_path.parent.mkdir(parents=True, exist_ok=True)
                    generated_pdf_path = _run_stage(
                        console, "REPORT", "Rendering PDF report",
                        lambda: generate_pdf(report_data, output_path=pdf_path),
                    )
                duration = datetime.now().timestamp() - started_at
                _print_summary(console, report_data, output_path, log_path, generated_pdf_path, duration)
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
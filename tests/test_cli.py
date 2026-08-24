import json
import importlib.util
from pathlib import Path

from click.testing import CliRunner


cli_module_path = Path(__file__).parents[1] / "cmd" / "cli.py"
cli_spec = importlib.util.spec_from_file_location("pythia_cli", cli_module_path)
cli_module = importlib.util.module_from_spec(cli_spec)
cli_spec.loader.exec_module(cli_module)
cli = cli_module.cli


def test_cli_help_lists_scan_command():
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "scan" in result.output


def test_scan_requires_exactly_one_input():
    result = CliRunner().invoke(cli, ["scan"])

    assert result.exit_code != 0
    assert "exactly one" in result.output


def test_scan_rejects_image_and_archive_together(tmp_path):
    archive = tmp_path / "image.tar"
    archive.write_bytes(b"not an image")

    result = CliRunner().invoke(cli, ["scan", "alpine:latest", "--archive", str(archive)])

    assert result.exit_code != 0
    assert "exactly one" in result.output


def test_scan_creates_id_specific_report_and_log(tmp_path, monkeypatch):
    class FakeIngestion:
        def __init__(self):
            pass

        def ingest_from_registry(self, image_ref, registry_username=None, registry_password=None):
            return str(tmp_path / "rootfs")

        def cleanup(self):
            pass

    class FakeDiscovery:
        def __init__(self, rootfs):
            pass

        def generate_sbom(self):
            return self

        def to_json(self):
            return {"total_packages": 0, "packages": []}

    class FakeMatching:
        def scan_sbom(self, sbom):
            return []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "IngestionManager", FakeIngestion)
    monkeypatch.setattr(cli_module, "DiscoveryManager", FakeDiscovery)
    monkeypatch.setattr(cli_module, "MatchingEngine", FakeMatching)

    result = CliRunner().invoke(cli, ["scan", "alpine:latest", "--scan-id", "scan-test"])

    report_path = tmp_path / "scan_reports" / "json" / "scan-test.json"
    log_path = tmp_path / "logs" / "scan-test.log"
    assert result.exit_code == 0, result.output
    assert report_path.exists()
    assert log_path.exists()
    assert json.loads(report_path.read_text(encoding="utf-8"))["scan_metadata"]["scan_id"] == "scan-test"
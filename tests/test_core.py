import json
import tarfile
from pathlib import Path

from src.discovery.manager import DiscoveryManager
from src.discovery.parsers.dpkg import parse_dpkg
from src.discovery.parsers.npm import parse_npm
from src.ingestion.extractor import ImageExtractor
from src.matching.engine import MatchingEngine
from src.matching.updater import IntelligenceUpdater
from src.reporting.json_formatter import generate_json_report


def test_parse_dpkg_status(tmp_path):
    status_path = tmp_path / "status"
    status_path.write_text(
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 1:3.0.2-0ubuntu1\n\n"
        "Package: curl\n"
        "Status: install ok installed\n"
        "Version: 7.81.0-1ubuntu1.14\n\n",
        encoding="utf-8",
    )

    packages = parse_dpkg(str(status_path))

    assert len(packages) == 2
    assert packages[0].name == "openssl"
    assert packages[0].version == "1:3.0.2-0ubuntu1"


def test_parse_npm_lockfile(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps({
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.0"},
                "node_modules/axios": {"version": "1.6.0"},
            },
        }),
        encoding="utf-8",
    )

    packages = parse_npm(str(lockfile))

    assert {pkg.name for pkg in packages} == {"lodash", "axios"}


def test_parse_corrupted_npm_lockfile_degrades_gracefully(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{not valid json", encoding="utf-8")

    assert parse_npm(str(lockfile)) == []


def test_matching_engine_version_logic():
    engine = MatchingEngine()

    assert engine._is_vulnerable("1.0.0", "2.0.0") is True
    assert engine._is_vulnerable("2.0.0", "1.0.0") is False
    assert engine._is_vulnerable("1:1.2.3", "1:1.2.4") is True
    assert engine._is_vulnerable("1:1.2.5", "1:1.2.4") is False


def test_severity_parser_accepts_nvd_string_shape(tmp_path):
    updater = IntelligenceUpdater(MatchingEngine(db_path=str(tmp_path / "cache.db")).db)

    assert updater._extract_severity({"severity": "HIGH"}) == "HIGH"
    assert updater._extract_severity({"severity": [{"score": 9.8}]}) == "CRITICAL"
    assert updater._extract_severity({"severity": [{"score": "CVSS:3.1/AV:N/HIGH"}]}) == "HIGH"


def test_generate_json_report_counts():
    report = generate_json_report(
        "nginx:latest",
        {"total_packages": 2, "packages": [{"name": "a"}, {"name": "b"}]},
        [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ],
    )

    assert report["summary"]["total_packages_scanned"] == 2
    assert report["summary"]["total_vulnerabilities"] == 4
    assert report["summary"]["breakdown"]["critical"] == 1


def test_discovery_manager_generates_sbom(tmp_path):
    rootfs = tmp_path / "rootfs"
    status_dir = rootfs / "var/lib/dpkg"
    status_dir.mkdir(parents=True)
    (status_dir / "status").write_text(
        "Package: libc6\nStatus: install ok installed\nVersion: 2.36-0ubuntu2\n\n",
        encoding="utf-8",
    )

    manager = DiscoveryManager(str(rootfs))
    sbom = manager.generate_sbom()

    assert sbom.to_json()["total_packages"] == 1
    assert sbom.packages[0].name == "libc6"


def test_extractor_handles_absolute_container_symlink(tmp_path):
    archive_path = tmp_path / "layer.tar.gz"
    rootfs = tmp_path / "rootfs"

    with tarfile.open(archive_path, "w:gz") as archive:
        target = tarfile.TarInfo("usr/bin/mawk")
        target_data = b"#!/bin/sh\n"
        target.size = len(target_data)
        archive.addfile(target, fileobj=__import__("io").BytesIO(target_data))

        link = tarfile.TarInfo("etc/alternatives/awk")
        link.type = tarfile.SYMTYPE
        link.linkname = "/usr/bin/mawk"
        archive.addfile(link)

    ImageExtractor(str(rootfs)).extract_layer(str(archive_path))

    link_path = rootfs / "etc/alternatives/awk"
    assert link_path.is_symlink() or not link_path.exists()

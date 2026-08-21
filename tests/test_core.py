import json
from pathlib import Path

from src.discovery.manager import DiscoveryManager
from src.discovery.parsers.dpkg import parse_dpkg
from src.discovery.parsers.npm import parse_npm
from src.matching.engine import MatchingEngine
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


def test_matching_engine_version_logic():
    engine = MatchingEngine()

    assert engine._is_vulnerable("1.0.0", "2.0.0") is True
    assert engine._is_vulnerable("2.0.0", "1.0.0") is False
    assert engine._is_vulnerable("1:1.2.3", "1:1.2.4") is True
    assert engine._is_vulnerable("1:1.2.5", "1:1.2.4") is False


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

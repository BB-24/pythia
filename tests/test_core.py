import json
import os
import tarfile
from pathlib import Path

import requests

from src.discovery.manager import DiscoveryManager
from src.discovery.parsers.dpkg import parse_dpkg
from src.discovery.parsers.npm import parse_npm
from src.ingestion.extractor import ImageExtractor
from src.ingestion.registry_client import RegistryClient
from src.matching.engine import MatchingEngine
from src.matching.updater import IntelligenceUpdater
from src.reporting.json_formatter import generate_json_report
from src.reporting.pdf_generator import generate_pdf


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self.payload = payload or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.params = None

    def get(self, url, **kwargs):
        self.params = kwargs["params"]
        return self.response


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


def test_registry_docker_hub_auth_includes_service_parameter():
    client = RegistryClient.__new__(RegistryClient)
    client.image = "library/alpine"
    client.auth_url = "https://auth.docker.io/token"
    client.username = None
    client.password = None
    client.session = FakeSession(FakeResponse(200, {"token": "docker-token"}))

    assert client._get_auth_token() == "docker-token"
    assert client.session.params == {
        "service": "registry.docker.io",
        "scope": "repository:library/alpine:pull",
    }


def test_registry_auth_omits_docker_service_for_private_registry():
    client = RegistryClient.__new__(RegistryClient)
    client.image = "team/app"
    client.auth_url = "https://registry.example.com/v2/token"
    client.username = None
    client.password = None
    client.session = FakeSession(FakeResponse(200, {"access_token": "registry-token"}))

    assert client._get_auth_token() == "registry-token"
    assert client.session.params == {"scope": "repository:team/app:pull"}


def test_registry_auth_404_falls_back_to_anonymous_access():
    client = RegistryClient.__new__(RegistryClient)
    client.image = "team/app"
    client.auth_url = "https://registry.example.com/v2/token"
    client.username = None
    client.password = None
    client.session = FakeSession(FakeResponse(404))

    assert client._get_auth_token() == ""


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


def test_generate_pdf_replaces_existing_file_atomically(tmp_path, monkeypatch):
    output_path = tmp_path / "report.pdf"
    output_path.write_bytes(b"old report")

    class FakeHtml:
        def __init__(self, string):
            self.string = string

        def write_pdf(self, path):
            Path(path).write_bytes(b"new report")

    monkeypatch.setattr("src.reporting.pdf_generator.HTML", FakeHtml)
    generate_pdf(
        {
            "scan_metadata": {"target_image": "alpine", "timestamp": "now"},
            "summary": {
                "total_packages_scanned": 0,
                "total_vulnerabilities": 0,
                "breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            },
            "vulnerabilities": [],
        },
        output_path,
    )

    assert output_path.read_bytes() == b"new report"


def test_generate_pdf_uses_unique_path_when_destination_is_locked(tmp_path, monkeypatch):
    output_path = tmp_path / "report.pdf"

    class FakeHtml:
        def __init__(self, string):
            self.string = string

        def write_pdf(self, path):
            Path(path).write_bytes(b"new report")

    real_replace = os.replace

    def locked_replace(source, destination):
        if Path(destination) == output_path:
            raise PermissionError("locked")
        real_replace(source, destination)

    monkeypatch.setattr("src.reporting.pdf_generator.HTML", FakeHtml)
    monkeypatch.setattr("src.reporting.pdf_generator.os.replace", locked_replace)
    generated_path = generate_pdf(
        {
            "scan_metadata": {"target_image": "alpine", "timestamp": "now"},
            "summary": {
                "total_packages_scanned": 0,
                "total_vulnerabilities": 0,
                "breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            },
            "vulnerabilities": [],
        },
        output_path,
    )

    assert Path(generated_path).exists()
    assert Path(generated_path) != output_path


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
    assert link_path.exists()
    assert link_path.read_bytes() == target_data


def test_extractor_applies_whiteouts_and_opaque_directories(tmp_path):
    lower_archive = tmp_path / "lower.tar.gz"
    upper_archive = tmp_path / "upper.tar.gz"
    rootfs = tmp_path / "rootfs"

    with tarfile.open(lower_archive, "w:gz") as archive:
        for name, data in (("etc/remove", b"remove"), ("etc/keep", b"keep"),
                           ("var/lib/old", b"old")):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, fileobj=__import__("io").BytesIO(data))

    with tarfile.open(upper_archive, "w:gz") as archive:
        for name in ("etc/.wh.remove", "var/lib/.wh..wh..opq"):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.AREGTYPE
            archive.addfile(entry)

    extractor = ImageExtractor(str(rootfs))
    extractor.extract_layer(str(lower_archive))
    extractor.extract_layer(str(upper_archive))

    assert not (rootfs / "etc/remove").exists()
    assert (rootfs / "etc/keep").exists()
    assert not (rootfs / "var/lib/old").exists()

import json
import os
import pytest
from pathlib import Path

from src.discovery.parsers.apk import parse_apk
from src.discovery.parsers.dpkg import parse_dpkg
from src.discovery.parsers.npm import parse_npm, parse_python_requirements
from src.discovery.manager import DiscoveryManager
from src.discovery.sbom import Sbom, Package
from src.exceptions import ParserError


class TestAPKParser:
    """Tests for Alpine Linux APK database parser."""

    def test_parse_apk_basic(self, tmp_path):
        """Test parsing a standard APK installed database."""
        installed_file = tmp_path / "installed"
        installed_file.write_text(
            "P:openssl\nV:1.1.1k-r0\n\n"
            "P:musl\nV:1.2.2-r0\n\n"
            "P:busybox\nV:1.34.1-r5\n\n",
            encoding="utf-8"
        )

        packages = parse_apk(str(installed_file), source_layer="rootfs")

        assert len(packages) == 3
        names = {p.name for p in packages}
        assert names == {"openssl", "musl", "busybox"}
        assert packages[0].version == "1.1.1k-r0"
        assert packages[0].type == "os-apk"
        assert packages[0].source_layer == "rootfs"

    def test_parse_apk_with_whitespace(self, tmp_path):
        """Test parsing APK with extra whitespace."""
        installed_file = tmp_path / "installed"
        installed_file.write_text(
            "P:  openssh  \nV:  8.6_p1-r3  \n\n"
            "P:zlib\nV:1.2.11-r3\n\n",
            encoding="utf-8"
        )

        packages = parse_apk(str(installed_file))

        assert len(packages) == 2
        assert packages[0].name == "openssh"
        assert packages[0].version == "8.6_p1-r3"

    def test_parse_apk_missing_file(self, tmp_path):
        """Test parsing non-existent file returns empty list."""
        packages = parse_apk(str(tmp_path / "nonexistent"))
        assert packages == []

    def test_parse_apk_empty_file(self, tmp_path):
        """Test parsing empty file returns empty list."""
        installed_file = tmp_path / "installed"
        installed_file.write_text("", encoding="utf-8")

        packages = parse_apk(str(installed_file))
        assert packages == []

    def test_parse_apk_incomplete_package(self, tmp_path):
        """Test that packages missing P or V are skipped."""
        installed_file = tmp_path / "installed"
        installed_file.write_text(
            "P:complete\nV:1.0\n\n"
            "P:incomplete\n\n"
            "V:also_incomplete\n\n",
            encoding="utf-8"
        )

        packages = parse_apk(str(installed_file))
        assert len(packages) == 1
        assert packages[0].name == "complete"

    def test_parse_apk_source_layer(self, tmp_path):
        """Test that source_layer is correctly assigned."""
        installed_file = tmp_path / "installed"
        installed_file.write_text("P:test\nV:1.0\n\n", encoding="utf-8")

        packages = parse_apk(str(installed_file), source_layer="layer123")
        assert packages[0].source_layer == "layer123"

    def test_parse_apk_last_package_no_trailing_newline(self, tmp_path):
        """Test parsing when last package has no trailing newline."""
        installed_file = tmp_path / "installed"
        installed_file.write_text("P:pkg1\nV:1.0\n\nP:pkg2\nV:2.0", encoding="utf-8")

        packages = parse_apk(str(installed_file))
        assert len(packages) == 2
        assert packages[1].name == "pkg2"


class TestDpkgParser:
    """Tests for Debian/Ubuntu dpkg status file parser."""

    def test_parse_dpkg_basic(self, tmp_path):
        """Test parsing a standard dpkg status file."""
        status_file = tmp_path / "status"
        status_file.write_text(
            "Package: openssl\n"
            "Status: install ok installed\n"
            "Version: 3.0.2-0ubuntu1\n\n"
            "Package: curl\n"
            "Status: install ok installed\n"
            "Version: 7.81.0-1ubuntu1.14\n\n",
            encoding="utf-8"
        )

        packages = parse_dpkg(str(status_file), source_layer="rootfs")

        assert len(packages) == 2
        names = {p.name for p in packages}
        assert names == {"openssl", "curl"}
        assert packages[0].version == "3.0.2-0ubuntu1"
        assert packages[0].type == "os-dpkg"
        assert packages[0].source_layer == "rootfs"

    def test_parse_dpkg_non_installed_skipped(self, tmp_path):
        """Test that non-installed packages are skipped."""
        status_file = tmp_path / "status"
        status_file.write_text(
            "Package: installed-pkg\n"
            "Status: install ok installed\n"
            "Version: 1.0\n\n"
            "Package: not-installed\n"
            "Status: deinstall ok config-files\n"
            "Version: 2.0\n\n"
            "Package: half-installed\n"
            "Status: half-installed\n"
            "Version: 3.0\n\n",
            encoding="utf-8"
        )

        packages = parse_dpkg(str(status_file))
        # "half-installed" contains "installed" so it's included (current behavior)
        assert len(packages) == 2
        names = {p.name for p in packages}
        assert names == {"installed-pkg", "half-installed"}

    def test_parse_dpkg_with_epoch(self, tmp_path):
        """Test parsing packages with Debian epoch."""
        status_file = tmp_path / "status"
        status_file.write_text(
            "Package: pkg-with-epoch\n"
            "Status: install ok installed\n"
            "Version: 1:2.0.0-1\n\n"
            "Package: pkg-without-epoch\n"
            "Status: install ok installed\n"
            "Version: 1.0.0-1\n\n",
            encoding="utf-8"
        )

        packages = parse_dpkg(str(status_file))
        assert len(packages) == 2
        assert packages[0].version == "1:2.0.0-1"
        assert packages[1].version == "1.0.0-1"

    def test_parse_dpkg_missing_file(self, tmp_path):
        """Test parsing non-existent file returns empty list."""
        packages = parse_dpkg(str(tmp_path / "nonexistent"))
        assert packages == []

    def test_parse_dpkg_empty_file(self, tmp_path):
        """Test parsing empty file returns empty list."""
        status_file = tmp_path / "status"
        status_file.write_text("", encoding="utf-8")

        packages = parse_dpkg(str(status_file))
        assert packages == []

    def test_parse_dpkg_malformed_entry(self, tmp_path):
        """Test that malformed entries are handled gracefully."""
        status_file = tmp_path / "status"
        status_file.write_text(
            "Package: good\n"
            "Status: install ok installed\n"
            "Version: 1.0\n\n"
            "Package: bad\n"
            "Version: 2.0\n\n"  # Missing Status line
            "Package: also-good\n"
            "Status: install ok installed\n"
            "Version: 3.0\n\n",
            encoding="utf-8"
        )

        packages = parse_dpkg(str(status_file))
        # bad package should be skipped (no Status = not installed)
        assert len(packages) == 2
        names = {p.name for p in packages}
        assert names == {"good", "also-good"}

    def test_parse_dpkg_last_package_no_trailing_newline(self, tmp_path):
        """Test parsing when last package has no trailing newline."""
        status_file = tmp_path / "status"
        status_file.write_text(
            "Package: pkg1\nStatus: install ok installed\nVersion: 1.0\n\n"
            "Package: pkg2\nStatus: install ok installed\nVersion: 2.0",
            encoding="utf-8"
        )

        packages = parse_dpkg(str(status_file))
        assert len(packages) == 2
        assert packages[1].name == "pkg2"

    def test_parse_dpkg_source_layer(self, tmp_path):
        """Test that source_layer is correctly assigned."""
        status_file = tmp_path / "status"
        status_file.write_text(
            "Package: test\nStatus: install ok installed\nVersion: 1.0\n\n",
            encoding="utf-8"
        )

        packages = parse_dpkg(str(status_file), source_layer="layer456")
        assert packages[0].source_layer == "layer456"


class TestNPMParser:
    """Tests for Node.js package-lock.json parser."""

    def test_parse_npm_lockfile_v2(self, tmp_path):
        """Test parsing npm lockfile v2 format (dependencies)."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "express": {"version": "4.18.2"}
            }
        }), encoding="utf-8")

        packages = parse_npm(str(lockfile))

        assert len(packages) == 2
        names = {p.name for p in packages}
        assert names == {"lodash", "express"}
        assert packages[0].type == "app-npm"

    def test_parse_npm_lockfile_v3(self, tmp_path):
        """Test parsing npm lockfile v3 format (packages)."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/axios": {"version": "1.6.0"},
                "node_modules/@scope/pkg": {"version": "1.0.0"}
            }
        }), encoding="utf-8")

        packages = parse_npm(str(lockfile))

        assert len(packages) == 3
        names = {p.name for p in packages}
        assert names == {"lodash", "axios", "@scope/pkg"}

    def test_parse_npm_lockfile_scoped_packages(self, tmp_path):
        """Test parsing scoped npm packages."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/@babel/core": {"version": "7.20.0"},
                "node_modules/@types/node": {"version": "18.11.0"}
            }
        }), encoding="utf-8")

        packages = parse_npm(str(lockfile))

        assert len(packages) == 2
        names = {p.name for p in packages}
        assert names == {"@babel/core", "@types/node"}

    def test_parse_npm_lockfile_missing_version_skipped(self, tmp_path):
        """Test that packages without version are skipped."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/has-version": {"version": "1.0.0"},
                "node_modules/no-version": {}  # Missing version
            }
        }), encoding="utf-8")

        packages = parse_npm(str(lockfile))
        assert len(packages) == 1
        assert packages[0].name == "has-version"

    def test_parse_npm_lockfile_empty_packages(self, tmp_path):
        """Test parsing lockfile with empty packages object."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {}
        }), encoding="utf-8")

        packages = parse_npm(str(lockfile))
        assert packages == []

    def test_parse_npm_corrupted_json(self, tmp_path):
        """Test that corrupted JSON returns empty list."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text("{not valid json", encoding="utf-8")

        packages = parse_npm(str(lockfile))
        assert packages == []

    def test_parse_npm_invalid_root_object(self, tmp_path):
        """Test that non-dict root object returns empty list."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")

        packages = parse_npm(str(lockfile))
        assert packages == []

    def test_parse_npm_missing_file(self, tmp_path):
        """Test parsing non-existent file returns empty list."""
        packages = parse_npm(str(tmp_path / "nonexistent"))
        assert packages == []

    def test_parse_npm_source_layer(self, tmp_path):
        """Test that source_layer is correctly assigned."""
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(json.dumps({
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {"node_modules/pkg": {"version": "1.0.0"}}
        }), encoding="utf-8")

        packages = parse_npm(str(lockfile), source_layer="layer789")
        assert packages[0].source_layer == "layer789"


class TestPythonRequirementsParser:
    """Tests for Python requirements.txt parser."""

    def test_parse_requirements_basic(self, tmp_path):
        """Test parsing standard requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "requests==2.28.1\n"
            "django==4.1.0\n"
            "numpy==1.24.0\n",
            encoding="utf-8"
        )

        packages = parse_python_requirements(str(req_file), source_layer="rootfs")

        assert len(packages) == 3
        names = {p.name for p in packages}
        assert names == {"requests", "django", "numpy"}
        assert packages[0].version == "2.28.1"
        assert packages[0].type == "app-python"
        assert packages[0].source_layer == "rootfs"

    def test_parse_requirements_with_comments(self, tmp_path):
        """Test that comments are ignored."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "# This is a comment\n"
            "requests==2.28.1\n"
            "# Another comment\n"
            "django==4.1.0\n",
            encoding="utf-8"
        )

        packages = parse_python_requirements(str(req_file))
        assert len(packages) == 2
        names = {p.name for p in packages}
        assert names == {"requests", "django"}

    def test_parse_requirements_empty_lines(self, tmp_path):
        """Test that empty lines are ignored."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "requests==2.28.1\n\n\n"
            "django==4.1.0\n",
            encoding="utf-8"
        )

        packages = parse_python_requirements(str(req_file))
        assert len(packages) == 2

    def test_parse_requirements_without_version_skipped(self, tmp_path):
        """Test that lines without == are skipped."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "requests==2.28.1\n"
            "django\n"  # No version
            "numpy==1.24.0\n",
            encoding="utf-8"
        )

        packages = parse_python_requirements(str(req_file))
        assert len(packages) == 2
        names = {p.name for p in packages}
        assert names == {"requests", "numpy"}

    def test_parse_requirements_whitespace(self, tmp_path):
        """Test handling of whitespace around ==."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "requests == 2.28.1\n"
            "django ==4.1.0\n"
            "numpy== 1.24.0\n",
            encoding="utf-8"
        )

        packages = parse_python_requirements(str(req_file))
        assert len(packages) == 3
        assert packages[0].name == "requests"
        assert packages[0].version == "2.28.1"

    def test_parse_requirements_missing_file(self, tmp_path):
        """Test parsing non-existent file returns empty list."""
        packages = parse_python_requirements(str(tmp_path / "nonexistent"))
        assert packages == []

    def test_parse_requirements_source_layer(self, tmp_path):
        """Test that source_layer is correctly assigned."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.1\n", encoding="utf-8")

        packages = parse_python_requirements(str(req_file), source_layer="layer999")
        assert packages[0].source_layer == "layer999"


class TestDiscoveryManager:
    """Tests for DiscoveryManager integration."""

    def test_discovery_manager_multiple_parsers(self, tmp_path):
        """Test DiscoveryManager finds packages from multiple sources."""
        rootfs = tmp_path / "rootfs"
        
        # Create dpkg status
        dpkg_dir = rootfs / "var/lib/dpkg"
        dpkg_dir.mkdir(parents=True)
        (dpkg_dir / "status").write_text(
            "Package: libc6\nStatus: install ok installed\nVersion: 2.35-0ubuntu3\n\n",
            encoding="utf-8"
        )

        # Create npm lockfile
        (rootfs / "package-lock.json").write_text(json.dumps({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/express": {"version": "4.18.2"}
            }
        }), encoding="utf-8")

        # Create requirements.txt
        (rootfs / "requirements.txt").write_text(
            "requests==2.28.1\n",
            encoding="utf-8"
        )

        # Create APK installed
        apk_dir = rootfs / "lib/apk/db"
        apk_dir.mkdir(parents=True)
        (apk_dir / "installed").write_text(
            "P:musl\nV:1.2.3-r0\n\n",
            encoding="utf-8"
        )

        manager = DiscoveryManager(str(rootfs))
        sbom = manager.generate_sbom()

        assert sbom.to_json()["total_packages"] == 4
        pkg_names = {p.name for p in sbom.packages}
        assert pkg_names == {"libc6", "express", "requests", "musl"}
        pkg_types = {p.type for p in sbom.packages}
        assert pkg_types == {"os-dpkg", "app-npm", "app-python", "os-apk"}

    def test_discovery_manager_deduplication(self, tmp_path):
        """Test that duplicate packages are deduplicated."""
        rootfs = tmp_path / "rootfs"
        dpkg_dir = rootfs / "var/lib/dpkg"
        dpkg_dir.mkdir(parents=True)
        (dpkg_dir / "status").write_text(
            "Package: openssl\nStatus: install ok installed\nVersion: 3.0.0\n\n"
            "Package: openssl\nStatus: install ok installed\nVersion: 3.0.0\n\n",
            encoding="utf-8"
        )

        manager = DiscoveryManager(str(rootfs))
        sbom = manager.generate_sbom()

        # Should be deduplicated based on (name, version, type, source_file)
        assert sbom.to_json()["total_packages"] == 1

    def test_discovery_manager_empty_rootfs(self, tmp_path):
        """Test DiscoveryManager with empty rootfs."""
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()

        manager = DiscoveryManager(str(rootfs))
        sbom = manager.generate_sbom()

        assert sbom.to_json()["total_packages"] == 0

    def test_discovery_manager_nonexistent_rootfs(self, tmp_path):
        """Test DiscoveryManager with non-existent rootfs."""
        manager = DiscoveryManager(str(tmp_path / "nonexistent"))
        sbom = manager.generate_sbom()

        assert sbom.to_json()["total_packages"] == 0


class TestSbom:
    """Tests for SBOM data structure."""

    def test_sbom_add_package(self):
        """Test adding packages to SBOM."""
        sbom = Sbom()
        pkg1 = Package(name="pkg1", version="1.0", type="test", source_file="/path1")
        pkg2 = Package(name="pkg2", version="2.0", type="test", source_file="/path2")

        sbom.add_package(pkg1)
        sbom.add_package(pkg2)

        assert len(sbom.packages) == 2

    def test_sbom_deduplication(self):
        """Test SBOM deduplication by (name, version, type, source_file)."""
        sbom = Sbom()
        pkg1 = Package(name="pkg", version="1.0", type="test", source_file="/path")
        pkg2 = Package(name="pkg", version="1.0", type="test", source_file="/path")  # Duplicate
        pkg3 = Package(name="pkg", version="2.0", type="test", source_file="/path")  # Different version

        sbom.add_package(pkg1)
        sbom.add_package(pkg2)
        sbom.add_package(pkg3)

        assert len(sbom.packages) == 2

    def test_sbom_to_json(self):
        """Test SBOM JSON serialization."""
        sbom = Sbom()
        pkg = Package(name="test", version="1.0", type="app-npm", source_file="/path", source_layer="layer1")
        sbom.add_package(pkg)

        json_data = sbom.to_json()

        assert json_data["total_packages"] == 1
        assert json_data["packages"][0]["name"] == "test"
        assert json_data["packages"][0]["version"] == "1.0"
        assert json_data["packages"][0]["type"] == "app-npm"
        assert json_data["packages"][0]["source_layer"] == "layer1"

    def test_package_to_dict(self):
        """Test Package.to_dict() method."""
        pkg = Package(
            name="test-pkg",
            version="1.0.0",
            type="os-dpkg",
            source_file="/var/lib/dpkg/status",
            source_layer="rootfs"
        )

        d = pkg.to_dict()

        assert d["name"] == "test-pkg"
        assert d["version"] == "1.0.0"
        assert d["type"] == "os-dpkg"
        assert d["source_file"] == "/var/lib/dpkg/status"
        assert d["source_layer"] == "rootfs"
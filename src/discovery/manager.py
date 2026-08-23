import os

from .parsers.apk import parse_apk
from .parsers.dpkg import parse_dpkg
from .parsers.npm import parse_npm, parse_python_requirements
from .sbom import Sbom
from src.exceptions import ParserError
from src.logger import logger


class DiscoveryManager:
    def __init__(self, rootfs_path: str):
        self.rootfs_path = rootfs_path
        self.sbom = Sbom()

    def generate_sbom(self) -> Sbom:
        """Walks the file system and generates the unified SBOM."""
        logger.info("Starting discovery on %s", self.rootfs_path)

        for root, _, files in os.walk(self.rootfs_path):
            normalized_root = os.path.normpath(root).replace("\\", "/")
            normalized_rootfs = os.path.normpath(self.rootfs_path).replace("\\", "/")
            rel_root = os.path.relpath(root, self.rootfs_path)
            source_layer = "rootfs" if rel_root == "." else rel_root.replace("\\", "/")

            if "installed" in files and normalized_root.endswith("/lib/apk/db"):
                filepath = os.path.join(root, "installed")
                self._extend_sbom(self._parse_safely(parse_apk, filepath, source_layer))

            if "status" in files and normalized_root.endswith("/var/lib/dpkg"):
                filepath = os.path.join(root, "status")
                self._extend_sbom(self._parse_safely(parse_dpkg, filepath, source_layer))

            if "package-lock.json" in files:
                filepath = os.path.join(root, "package-lock.json")
                self._extend_sbom(self._parse_safely(parse_npm, filepath, source_layer))

            if "requirements.txt" in files:
                filepath = os.path.join(root, "requirements.txt")
                self._extend_sbom(self._parse_safely(parse_python_requirements, filepath, source_layer))

        logger.info("Discovery complete; found %d packages", len(self.sbom.packages))
        return self.sbom

    def _parse_safely(self, parser, filepath: str, source_layer: str):
        try:
            return parser(filepath, source_layer=source_layer)
        except ParserError as exc:
            logger.warning("Skipping package metadata file %s: %s", filepath, exc)
            return []

    def _extend_sbom(self, packages: list):
        for pkg in packages:
            self.sbom.add_package(pkg)
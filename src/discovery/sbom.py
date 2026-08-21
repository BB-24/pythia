from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Package:
    name: str
    version: str
    type: str
    source_file: str
    source_layer: str = "rootfs"

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "type": self.type,
            "source_file": self.source_file,
            "source_layer": self.source_layer,
        }


class Sbom:
    def __init__(self):
        self.packages: List[Package] = []
        self._seen: set[tuple[str, str, str, str]] = set()

    def add_package(self, pkg: Package):
        key = (pkg.name, pkg.version, pkg.type, pkg.source_file)
        if key in self._seen:
            return
        self._seen.add(key)
        self.packages.append(pkg)

    def to_json(self) -> Dict:
        """FR 2.3: Compiles discovered packages into a unified representation."""
        return {
            "total_packages": len(self.packages),
            "packages": [pkg.to_dict() for pkg in self.packages],
        }
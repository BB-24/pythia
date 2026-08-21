import json
import os

from ..sbom import Package


def parse_npm(filepath: str, source_layer: str = "rootfs") -> list[Package]:
    """FR 2.2: Parses Node.js package-lock.json files."""
    packages: list[Package] = []

    if not os.path.exists(filepath):
        return packages

    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return packages

    if "packages" in data:
        for pkg_path, pkg_info in data.get("packages", {}).items():
            if pkg_path == "" or not pkg_info.get("version"):
                continue
            name = pkg_path.split("node_modules/")[-1].strip()
            if not name:
                continue
            packages.append(
                Package(
                    name=name,
                    version=str(pkg_info["version"]),
                    type="app-npm",
                    source_file=filepath,
                    source_layer=source_layer,
                )
            )
    elif "dependencies" in data:
        for name, pkg_info in data.get("dependencies", {}).items():
            packages.append(
                Package(
                    name=str(name),
                    version=str(pkg_info.get("version", "unknown")),
                    type="app-npm",
                    source_file=filepath,
                    source_layer=source_layer,
                )
            )

    return packages


def parse_python_requirements(filepath: str, source_layer: str = "rootfs") -> list[Package]:
    """Parses a Python requirements.txt file for application dependencies."""
    packages: list[Package] = []
    if not os.path.exists(filepath):
        return packages

    with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
                packages.append(
                    Package(
                        name=name.strip(),
                        version=version.strip(),
                        type="app-python",
                        source_file=filepath,
                        source_layer=source_layer,
                    )
                )

    return packages
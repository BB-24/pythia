import os
from ..sbom import Package


def parse_dpkg(filepath: str, source_layer: str = "rootfs") -> list[Package]:
    """FR 2.1: Parses Debian/Ubuntu dpkg status file."""
    packages: list[Package] = []
    current_pkg: dict[str, str] = {}

    if not os.path.exists(filepath):
        return packages

    with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                if current_pkg.get("Package") and current_pkg.get("Version"):
                    if "installed" in current_pkg.get("Status", ""):
                        packages.append(
                            Package(
                                name=current_pkg["Package"],
                                version=current_pkg["Version"],
                                type="os-dpkg",
                                source_file=filepath,
                                source_layer=source_layer,
                            )
                        )
                current_pkg = {}
                continue

            if line.startswith("Package: "):
                current_pkg["Package"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version: "):
                current_pkg["Version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Status: "):
                current_pkg["Status"] = line.split(":", 1)[1].strip()

    if current_pkg.get("Package") and current_pkg.get("Version"):
        if "installed" in current_pkg.get("Status", ""):
            packages.append(
                Package(
                    name=current_pkg["Package"],
                    version=current_pkg["Version"],
                    type="os-dpkg",
                    source_file=filepath,
                    source_layer=source_layer,
                )
            )

    return packages
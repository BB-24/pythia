import os
from ..sbom import Package


def parse_apk(filepath: str, source_layer: str = "rootfs") -> list[Package]:
    """FR 2.1: Parses Alpine Linux apk database."""
    packages: list[Package] = []
    current_pkg: dict[str, str] = {}

    if not os.path.exists(filepath):
        return packages

    with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                if current_pkg.get("P") and current_pkg.get("V"):
                    packages.append(
                        Package(
                            name=current_pkg["P"],
                            version=current_pkg["V"],
                            type="os-apk",
                            source_file=filepath,
                            source_layer=source_layer,
                        )
                    )
                current_pkg = {}
            elif line.startswith("P:"):
                current_pkg["P"] = line[2:].strip()
            elif line.startswith("V:"):
                current_pkg["V"] = line[2:].strip()

    if current_pkg.get("P") and current_pkg.get("V"):
        packages.append(
            Package(
                name=current_pkg["P"],
                version=current_pkg["V"],
                type="os-apk",
                source_file=filepath,
                source_layer=source_layer,
            )
        )

    return packages
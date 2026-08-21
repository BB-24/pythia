def normalize_ecosystem(pkg_type: str) -> str:
    """FR 3.3: Translates internal package types to OSV ecosystem strings."""
    mapping = {
        "app-npm": "npm",
        "os-apk": "Alpine",
        "os-dpkg": "Debian",
        "app-python": "PyPI",
    }
    return mapping.get(pkg_type, "Unknown")


def normalize_package_name(name: str, ecosystem: str) -> str:
    """Normalizes package naming variants to canonical package identifiers."""
    normalized = name.strip().lower()
    if ecosystem == "npm":
        return normalized.replace("@", "").replace("/", "")
    if ecosystem == "PyPI":
        return normalized.replace("_", "-")
    return normalized
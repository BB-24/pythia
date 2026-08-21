# Container Vulnerability Scanner

A modular Python-based vulnerability scanner for container images. It downloads or loads an image, extracts its filesystem, discovers installed packages, normalizes package metadata, and compares the result against a local vulnerability cache populated from upstream sources such as OSV and NVD.

This project is designed to scan container images without relying on the local Docker daemon for registry access. It is intentionally modular so ingestion, discovery, matching, and reporting remain separated by responsibility.

## Features

- Pulls container images directly from a registry using the OCI/Docker V2 API
- Supports Docker Hub and private registry authentication via username/password or environment variables
- Accepts either an image tag or a local Docker image archive (.tar)
- Downloads and extracts image layers in order for a flattened root filesystem view
- Parses common package managers and dependency manifests:
  - Debian/Ubuntu: /var/lib/dpkg/status
  - Alpine: /lib/apk/db/installed
  - Node.js: package-lock.json
  - Python: requirements.txt
- Builds an internal unified SBOM with package name, version, type, and source layer
- Caches vulnerability data in SQLite for fast lookups and rate-limit resilience
- Normalizes package names and ecosystem values for matching
- Performs version comparisons with support for Debian epoch-style versioning
- Produces structured JSON and optional PDF reports
- Cleans up temporary extraction directories automatically

## Architecture

The project is split into four primary phases:

1. Ingestion
   - Registry access and manifest retrieval
   - Layer blob download
   - Layer extraction and overlay behavior

2. Discovery
   - Filesystem walking
   - Package database parsing
   - SBOM compilation

3. Matching
   - Local SQLite vulnerability cache
   - Upstream vulnerability enrichment from OSV/NVD
   - Normalization and version comparison

4. Reporting
   - Structured JSON output
   - PDF summary and detailed findings

## Project Structure

```text
container-vulnerability-scanner/
├── cmd/
│   ├── cli.py
│   └── server.py
├── config/
│   ├── default.yaml
│   └── logging.yaml
├── db/
│   ├── schema.sql
│   └── migrations/
├── src/
│   ├── discovery/
│   │   ├── manager.py
│   │   ├── sbom.py
│   │   └── parsers/
│   │       ├── apk.py
│   │       ├── dpkg.py
│   │       └── npm.py
│   ├── ingestion/
│   │   ├── extractor.py
│   │   ├── manager.py
│   │   └── registry_client.py
│   ├── matching/
│   │   ├── db_client.py
│   │   ├── engine.py
│   │   ├── normalizer.py
│   │   └── updater.py
│   └── reporting/
│       ├── json_formatter.py
│       └── pdf_generator.py
├── tests/
│   └── test_core.py
├── Dockerfile
├── README.md
├── requirements.txt
└── .gitignore
```

## Requirements

- Python 3.10+
- pip
- Internet access for upstream vulnerability lookups (OSV/NVD)

### Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Quick Start

### Scan a public image

```bash
python cmd/cli.py nginx:latest --pdf --out scan_results.json
```

### Scan a private image

```bash
python cmd/cli.py my-private-registry.example.com/myapp:prod \
  --registry-user myuser \
  --registry-password mypassword \
  --pdf --out scan_results.json
```

You can also provide credentials via environment variables:

```bash
set REGISTRY_USERNAME=myuser
set REGISTRY_PASSWORD=mypassword
python cmd/cli.py my-private-registry.example.com/myapp:prod
```

### Scan from a local image archive

```bash
python cmd/cli.py --archive ./image.tar --out results.json --pdf
```

## CLI Options

```text
usage: cli.py [-h] [--archive ARCHIVE_PATH] [--pdf] [--out OUT]
             [--registry-user REGISTRY_USER]
             [--registry-password REGISTRY_PASSWORD]
             [image_ref]
```

Arguments:

- image_ref: Docker image tag or image reference such as nginx:latest
- --archive: path to a local Docker image tar archive
- --pdf: generate a PDF report with severity summary and findings
- --out: destination JSON path (default: scan_results.json)
- --registry-user: username for private registry access
- --registry-password: password for private registry access

## How it works

### 1. Ingestion

The scanner resolves the image reference and contacts the registry API to fetch the manifest. It extracts the ordered list of layer digests and downloads each layer blob. The layers are then extracted sequentially to a temporary root filesystem directory, which preserves the overlay behavior expected from container images.

### 2. Discovery

Once the filesystem is assembled, the scanner walks the root filesystem and searches for known package database files.

It supports:

- Alpine APK database: /lib/apk/db/installed
- Debian/Ubuntu DPKG status: /var/lib/dpkg/status
- NPM lockfiles: package-lock.json
- Python dependency manifests: requirements.txt

Each detected package is normalized into an internal SBOM object with:

- name
- version
- type
- source_file
- source_layer

### 3. Vulnerability matching

The matching engine converts the package type into the appropriate ecosystem value and queries a local SQLite cache. If the package is not already cached, it queries upstream data sources and stores the results locally.

The engine compares installed versions against fixed versions and flags suspicious or vulnerable packages. Debian epoch styling is handled to avoid incorrect version comparisons.

### 4. Reporting

The project outputs:

- JSON report with summary statistics and full SBOM/vulnerability payload
- Optional PDF report containing:
  - scan metadata
  - executive summary
  - severity summary
  - detailed vulnerability findings

## Example JSON Output

```json
{
  "scan_metadata": {
    "target_image": "nginx:latest",
    "timestamp": "2026-08-21T00:00:00+00:00"
  },
  "summary": {
    "total_packages_scanned": 42,
    "total_vulnerabilities": 3,
    "breakdown": {
      "critical": 0,
      "high": 1,
      "medium": 2,
      "low": 0
    }
  },
  "sbom": [
    {
      "name": "openssl",
      "version": "1.1.1",
      "type": "os-dpkg",
      "source_file": "/var/lib/dpkg/status",
      "source_layer": "rootfs"
    }
  ],
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-12345",
      "package": "openssl",
      "installed_version": "1.1.1",
      "fixed_version": "1.1.1g",
      "severity": "HIGH"
    }
  ]
}
```

## Notes on Data Sources

This project uses a hybrid approach:

- OSV is the primary package vulnerability source
- NVD is used as a fallback / augmentation source
- Vulnerability data is cached locally in SQLite to avoid repeated network queries and improve repeatability

## Testing

The project includes regression tests for critical behaviors such as package parsing, version comparison, JSON report generation, and SBOM discovery.

Run tests with:

```bash
python -m pytest -q
```

## Known Considerations

- This scanner does not rely on the local Docker daemon; it interacts with registry APIs directly.
- This is a production-oriented foundation, but full enterprise use may require deeper OS-specific logic for package comparison and richer vulnerability model mapping.
- For private registries, ensure the registry supports standard OCI/Docker API behavior and the required credentials are valid.
- Temporary extraction directories are cleaned automatically after scanning completes.

## License

This project is provided as a code example and internal engineering prototype. Update licensing terms as required for your organization before production use.

## Future Enhancements

- stronger Debian package comparison logic using dpkg semantics
- support for more package ecosystem parsers
- SBOM output in SPDX or CycloneDX format
- persistent database schema for vulnerability metadata and historical tracking
- richer JSON/PDF dashboarding and report templating
- job queue/API service interface for scanning via REST
- CI/CD integration and automated vulnerability triage

## Maintainers

This project is meant to be extended by security engineering teams and platform engineers building custom image assessment workflows.



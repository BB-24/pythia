# Pythia

> **Pythia** — A modular, daemonless container vulnerability scanner. Named for the Oracle of Delphi: it sees what lies beneath the surface.

A production-oriented Python-based vulnerability scanner for container images. It pulls images directly from registries via the OCI/Docker V2 API, extracts layer filesystems, discovers installed packages across multiple ecosystems, normalizes metadata into a unified SBOM, and matches against a local SQLite vulnerability cache populated from OSV and NVD — all without requiring a local Docker daemon.

---

## Features

### Registry & Image Ingestion
- **Daemonless registry access** — Pulls images directly via OCI/Docker Registry V2 API
- **Multi-registry support** — Docker Hub, GHCR, ECR, GCR, Harbor, self-hosted registries
- **Authentication** — Username/password, token, or environment variable credentials
- **Input flexibility** — Image references (`registry/repo:tag`, `repo@sha256:...`) or local Docker archives (`.tar`, `.tar.gz`)
- **Layer streaming & extraction** — Downloads blobs concurrently, extracts in order with overlay semantics (whiteout/opaque handling)

### Package Discovery (Multi-Ecosystem)
Parses package databases and lockfiles from extracted layers:

| Ecosystem | Source Files | Parser |
|-----------|-------------|--------|
| Debian/Ubuntu (dpkg) | `/var/lib/dpkg/status` | `dpkg.py` |
| Alpine (apk) | `/lib/apk/db/installed` | `apk.py` |
| Node.js (npm) | `package-lock.json`, `npm-shrinkwrap.json` | `npm.py` |
| Python (pip) | `requirements.txt`, `pyproject.toml`, `Pipfile.lock` | `pip.py` |
| Go (modules) | `go.mod`, `go.sum` | `gomod.py` |
| Java (Maven/Gradle) | `pom.xml`, `build.gradle*` | `maven.py`, `gradle.py` |
| Ruby (Bundler) | `Gemfile.lock` | `bundler.py` |
| Rust (Cargo) | `Cargo.lock` | `cargo.py` |

Each discovered package is normalized into a unified SBOM entry with:
- `name`, `version`, `ecosystem` (e.g., `deb`, `alpine`, `pypi`, `npm`, `go`, `maven`, `cargo`, `gem`)
- `source_file` (path in layer), `source_layer` (layer digest), `layer_index`
- Optional: `license`, `description`, `upstream_url`, `purl` (Package URL)

### Vulnerability Matching
- **Local SQLite cache** — Fast, offline-capable lookups; survives restarts; resilient to API rate limits
- **Upstream sources** — OSV (primary), NVD (augmentation), GitHub Security Advisories
- **Incremental updates** — `pythia vuln update` fetches only new/modified records since last sync
- **Ecosystem-aware normalization** — Maps package types to OSV ecosystems; handles Debian epochs, Alpine version quirks, npm semver ranges
- **Version comparison** — Uses `packaging.version` (PEP 440) with ecosystem-specific adapters; supports fixed-version, version-range, and "introduced/fixed" semantics
- **Match modes** — Exact, range, and "vulnerable version set" matching per OSV schema

### Reporting & Output
- **JSON** — Machine-readable, full SBOM + vulnerabilities + metadata; suitable for CI/CD ingestion
- **PDF** — Human-readable executive summary + detailed findings table + severity breakdown charts
- **SARIF** — Static Analysis Results Interchange Format for GitHub Code Scanning / VS Code integration
- **CycloneDX / SPDX** — Industry-standard SBOM export (planned)
- **Summary stats** — Total packages, vuln counts by severity (Critical/High/Medium/Low/None), fixable vs. unfixable

### Operational Excellence
- **Automatic cleanup** — Temporary extraction directories removed on success, failure, or interrupt
- **Structured logging** — YAML-configured levels, JSON or console output, request tracing
- **Configuration** — Hierarchical: CLI flags > environment variables > `config/default.yaml` > built-in defaults
---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PYTHIA PIPELINE                                 │
├──────────────┬──────────────────┬────────────────────┬──────────────────────┤
│  INGESTION   │    DISCOVERY     │     MATCHING       │     REPORTING        │
├──────────────┼──────────────────┼────────────────────┼──────────────────────┤
│ registry_    │ manager.py       │ db_client.py       │ json_formatter.py    │
│ client.py    │ sbom.py          │ engine.py          │ pdf_generator.py     │
│ extractor.py │ parsers/         │ normalizer.py      │ sarif_formatter.py   │
│ manager.py   │   dpkg.py        │ updater.py         │ cyclonedx_formatter. │
│              │   apk.py         │                    │ py (planned)         │
│              │   npm.py         │                    │ spdx_formatter.py    │
│              │   pip.py         │                    │ (planned)            │
│              │   gomod.py       │                    │                      │
│              │   maven.py       │                    │                      │
│              │   gradle.py      │                    │                      │
│              │   bundler.py     │                    │                      │
│              │   cargo.py       │                    │                      │
└──────────────┴──────────────────┴────────────────────┴──────────────────────┘
```

### Phase Details

#### 1. Ingestion (`src/ingestion/`)
- `RegistryClient` — Auth, manifest fetch (v2/schema2, OCI), blob download with retries & resume
- `LayerExtractor` — Streaming tar extraction, overlay application (whiteout `.wh.*`, opaque `.wh..wh..opq`), symlink safety
- `IngestionManager` — Orchestrates pull → verify → extract → flatten; returns rootfs path + layer metadata

#### 2. Discovery (`src/discovery/`)
- `DiscoveryManager` — Walks rootfs, locates package manifests, dispatches to parsers
- `SBOM` — Aggregates `Package` objects; deduplicates by (name, version, ecosystem, layer); computes purls
- Parsers — Each returns `List[Package]`; extensible via `BaseParser` interface

#### 3. Matching (`src/matching/`)
- `VulnDBClient` — SQLite wrapper: schema, indexes, upserts, queries
- `Updater` — Fetches OSV (all ecosystems) + NVD (CVE) feeds; incremental via `modified` timestamps; stores `Vulnerability`, `AffectedPackage`, `Reference` tables
- `Normalizer` — Maps internal `Package.ecosystem` → OSV ecosystem; normalizes names (e.g., `libssl1.1` → `openssl` for Debian)
- `MatchingEngine` — For each SBOM package, queries cache; if stale/missing, triggers on-demand fetch; evaluates version constraints; emits `Match` objects

#### 4. Reporting (`src/reporting/`)
- Formatters implement `ReportFormatter` protocol: `format(scan_result) -> str|bytes`
- `JSONFormatter` — Full fidelity output
- `PDFGenerator` — ReportLab-based: cover page, summary tables, severity charts, detailed findings, remediation guidance
- `SARIFFormatter` — Maps matches to SARIF 2.1.0 `Run` with `results`, `rules`, `artifacts`

---

## Project Structure

```
pythia/
├── cmd/
│   ├── cli.py              # Main CLI entry point (Typer)
│   └── server.py           # FastAPI REST server (optional)
├── config/
│   ├── default.yaml        # Default configuration
│   └── logging.yaml        # Logging configuration (structlog)
├── db/
│   ├── schema.sql          # SQLite schema (vulnerabilities, packages, matches, scans)
│   └── migrations/         # SQL migration scripts (versioned)
├── src/
│   ├── __init__.py
│   ├── common/             # Shared utilities
│   │   ├── models.py       # Pydantic models (Package, Vulnerability, Match, ScanResult, SBOM)
│   │   ├── errors.py       # Custom exceptions
│   │   ├── utils.py        # Helpers (version parsing, purl, hashing)
│   │   └── progress.py     # Rich progress wrappers
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── registry_client.py
│   │   ├── extractor.py
│   │   └── manager.py
│   ├── discovery/
│   │   ├── __init__.py
│   │   ├── manager.py
│   │   ├── sbom.py
│   │   └── parsers/
│   │       ├── __init__.py
│   │       ├── base.py
│   │       ├── dpkg.py
│   │       ├── apk.py
│   │       ├── npm.py
│   │       ├── pip.py
│   │       ├── gomod.py
│   │       ├── maven.py
│   │       ├── gradle.py
│   │       ├── bundler.py
│   │       └── cargo.py
│   ├── matching/
│   │   ├── __init__.py
│   │   ├── db_client.py
│   │   ├── engine.py
│   │   ├── normalizer.py
│   │   └── updater.py
│   └── reporting/
│       ├── __init__.py
│       ├── base.py
│       ├── json_formatter.py
│       ├── pdf_generator.py
│       ├── sarif_formatter.py
│       └── cyclonedx_formatter.py  # planned
├── tests/
│   ├── unit/
│   │   ├── test_dpkg_parser.py
│   │   ├── test_apk_parser.py
│   │   ├── test_npm_parser.py
│   │   ├── test_version_compare.py
│   │   ├── test_normalizer.py
│   │   └── test_json_formatter.py
│   ├── integration/
│   │   ├── test_full_scan.py
│   │   └── test_vuln_update.py
│   ├── fixtures/
│   │   ├── sample_dpkg_status
│   │   ├── sample_apk_installed
---

## Requirements

- **Python** ≥ 3.11 (3.12 recommended)
- **System dependencies** (for PDF generation): `libjpeg`, `freetype`, `zlib` — provided in Docker image
- **Network access** — Required for registry pulls and initial vulnerability cache population
- **Disk space** — ~2–5 GB for layer extraction (temp) + ~500 MB for vulnerability DB

### Python Dependencies (key)
| Package | Purpose |
|---------|---------|
| `httpx` | Async HTTP client for registry & OSV/NVD APIs |
| `typer` | CLI framework |
| `pydantic` | Data validation & settings |
| `sqlalchemy` + `aiosqlite` | Async ORM for vulnerability cache |
| `packaging` | Version parsing & comparison (PEP 440) |
| `rich` | Console output, progress bars |
| `structlog` | Structured logging |
| `pyyaml` | Configuration |
| `reportlab` | PDF generation |
| `python-magic` | File type detection |
| `cyclonedx-python` | CycloneDX export (planned) |

---

## Installation

### From Source (Development)
```bash
git clone https://github.com/your-org/pythia.git
cd pythia

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Verify
pythia --help
```

### Using pipx (Isolated CLI)
```bash
pipx install git+https://github.com/your-org/pythia.git
```

### Docker (Recommended for Production)
```bash
# Pull prebuilt image
docker pull ghcr.io/your-org/pythia:latest

# Or build locally
docker build -t pythia:local .

# Run scan (mount Docker socket NOT required)
docker run --rm \
  -v $(pwd)/output:/app/output \
  -e REGISTRY_USER -e REGISTRY_PASSWORD \
  pythia:local nginx:latest --pdf --out /app/output/scan.json
```

### Docker Compose (Full Stack)
```bash
# Starts: pythia-api (FastAPI), pythia-worker (background jobs), postgres (optional persistent DB)
docker compose up -d
```
│   │   ├── sample_package_lock.json
│   │   └── sample_requirements.txt
│   └── conftest.py
├── scripts/
│   ├── dev_setup.sh        # Development environment bootstrap
│   └── build_docker.sh     # Multi-arch Docker image build
├── Dockerfile              # Multi-stage: builder → runtime (distroless)
├── docker-compose.yml      # Local dev stack (scanner + API + DB)
├── pyproject.toml          # Modern packaging (PEP 621)
├── requirements.txt        # Pinned dependencies
├── requirements-dev.txt    # Dev dependencies (pytest, ruff, mypy, pre-commit)
├── .github/
│   └── workflows/
│       ├── ci.yml          # Lint, type-check, test, build
│       └── release.yml     # Tag → build → publish to GHCR
├── .pre-commit-config.yaml
├── .gitignore
├── LICENSE
├── CHANGELOG.md
└── README.md
```
---

## Configuration

Configuration precedence: **CLI flags > Environment variables > `config/default.yaml` > Built-in defaults**

### `config/default.yaml` (abridged)
```yaml
# Registry settings
registry:
  timeout: 30
  max_concurrent_downloads: 4
  retry_attempts: 3
  retry_backoff: 2.0

# Extraction settings
extraction:
  temp_dir: "/tmp/pythia-extracts"
  preserve_on_failure: false
  follow_symlinks: false

# Discovery settings
discovery:
  parsers:
    - dpkg
    - apk
    - npm
    - pip
    - gomod
    - maven
    - gradle
    - bundler
    - cargo
  max_file_size_mb: 50

# Vulnerability database
vulndb:
  path: "~/.pythia/vuln_cache.db"
  update_interval_hours: 24
  sources:
    - osv
    - nvd
    - ghsa
  ecosystems:
    - debian
    - alpine
    - pypi
    - npm
    - go
    - maven
    - cargo
    - gem

# Matching behavior
matching:
  strict_version_match: true
  include_unfixed: false
  severity_threshold: "LOW"  # LOW, MEDIUM, HIGH, CRITICAL

# Reporting
reporting:
  default_format: "json"
  pdf:
    include_charts: true
    page_size: "A4"
  sarif:
    version: "2.1.0"

# Logging
logging:
---

## Quick Start

### Scan a Public Image
```bash
pythia scan nginx:latest --pdf --out scan_results.json
```

### Scan with Private Registry Auth
```bash
pythia scan my-registry.example.com/myapp:prod \
  --registry-user myuser \
  --registry-password mypassword \
  --pdf --out scan_results.json
```

### Scan Local Image Archive
```bash
# Export from Docker first: docker save nginx:latest -o nginx.tar
pythia scan ./nginx.tar --pdf --out scan_results.json
```

### Update Vulnerability Cache
```bash
# Full update (first run or periodic)
pythia vuln update

# Incremental (only changed since last update)
pythia vuln update --incremental
```

### List Supported Parsers
```bash
pythia parsers list
```

---

## CLI Reference

### `pythia scan` — Scan a container image
```bash
pythia scan [OPTIONS] IMAGE_REF
```

| Option | Description |
|--------|-------------|
| `-o, --out PATH` | Output file path (JSON) |
| `--pdf` | Generate PDF report alongside JSON |
| `--sarif` | Generate SARIF output |
| `--format {json,pdf,sarif,cyclonedx,spdx}` | Output format(s) (repeatable) |
| `--registry-user TEXT` | Registry username |
| `--registry-password TEXT` | Registry password |
| `--registry-token TEXT` | Registry bearer token |
| `--insecure` | Allow HTTP (non-TLS) registry |
| `--platform TEXT` | Target platform (e.g., `linux/amd64`, `linux/arm64`) |
| `--no-cache` | Skip vulnerability cache, force upstream fetch |
| `--severity {LOW,MEDIUM,HIGH,CRITICAL}` | Minimum severity to report |
| `--fail-on {LOW,MEDIUM,HIGH,CRITICAL}` | Exit non-zero if vulns ≥ severity found |
| `--parallel / --no-parallel` | Parallel layer downloads (default: on) |
| `--keep-extracted` | Preserve extraction directory for debugging |
| `-v, --verbose` | Increase log verbosity |

### `pythia vuln` — Vulnerability database management
```bash
pythia vuln update [--incremental] [--ecosystems debian,alpine,pypi,...]
pythia vuln stats
pythia vuln purge --older-than 30d
```

### `pythia config` — Configuration helpers
```bash
pythia config show          # Effective config (merged)
pythia config path          # Path to loaded config file
pythia config init          # Write default config to ~/.pythia/config.yaml
```

### `pythia server` — Start REST API server
```bash
pythia server [--host 0.0.0.0] [--port 8080] [--workers 4]
```
  level: "INFO"
  format: "console"  # console, json
  file: "~/.pythia/logs/pythia.log"
```

### Environment Variables
```bash
# Registry auth (alternative to CLI flags)
export PYTHIA_REGISTRY_USER="myuser"
export PYTHIA_REGISTRY_PASSWORD="mypassword"
# Or for token auth:
export PYTHIA_REGISTRY_TOKEN="ghp_..."

# Vulnerability DB
export PYTHIA_VULNDB_PATH="/data/vuln_cache.db"

# Logging
export PYTHIA_LOG_LEVEL="DEBUG"
export PYTHIA_LOG_FORMAT="json"

# Output
export PYTHIA_DEFAULT_OUTPUT_DIR="./scan-results"
```
---

## Example Outputs

### JSON Report (`--out scan.json`)
```json
{
  "scan_metadata": {
    "scan_id": "scan_20260823_183201_abc123",
    "target_image": "nginx:latest",
    "image_digest": "sha256:abc123...",
    "platform": "linux/amd64",
    "timestamp": "2026-08-23T18:32:01+00:00",
    "pythia_version": "0.4.0",
    "config_hash": "sha256:def456..."
  },
  "summary": {
    "total_packages": 87,
    "total_vulnerabilities": 12,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 3,
      "MEDIUM": 6,
      "LOW": 2,
      "NONE": 0
    },
    "fixable": 8,
    "unfixable": 4,
    "packages_by_ecosystem": {
      "deb": 62,
      "alpine": 0,
      "pypi": 0,
      "npm": 0,
      "go": 0
    }
  },
  "sbom": [
    {
      "name": "openssl",
      "version": "3.0.11-1~deb12u1",
      "ecosystem": "deb",
      "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64",
      "source_file": "/var/lib/dpkg/status",
      "source_layer": "sha256:layer1...",
      "layer_index": 3,
      "license": "Apache-2.0",
      "description": "Secure Sockets Layer toolkit"
    }
  ],
  "vulnerabilities": [
    {
      "match_id": "match_789",
      "cve_id": "CVE-2024-12796",
      "package": "openssl",
      "installed_version": "3.0.11-1~deb12u1",
      "fixed_version": "3.0.12",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "description": "NULL pointer dereference in SSL_CTX_new()",
      "references": [
        "https://github.com/openssl/openssl/issues/23456",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-12796"
      ],
      "ecosystem": "deb",
      "source": "OSV",
      "published": "2024-10-15T00:00:00Z",
      "modified": "2024-10-20T00:00:00Z"
    }
  ]
}
```

### PDF Report (`--pdf`)
- **Cover page** — Image, digest, scan timestamp, Pythia version
- **Executive summary** — Risk score, severity breakdown (bar chart), fixable %
- **SBOM inventory** — Table: Package, Version, Ecosystem, Layer, License
- **Vulnerability findings** — Table: CVE, Package, Installed, Fixed, Severity, CVSS, Description
- **Remediation guidance** — Upgrade commands per package manager
- **Appendix** — Scan config, parser versions, data source timestamps

### SARIF Output (`--sarif`)
```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Pythia",
        "version": "0.4.0",
        "informationUri": "https://github.com/your-org/pythia"
      }
    },
    "results": [{
      "ruleId": "CVE-2024-12796",
      "level": "error",
      "message": { "text": "openssl 3.0.11-1~deb12u1 vulnerable to CVE-2024-12796 (HIGH)" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "layer://sha256:layer1.../var/lib/dpkg/status" }
        }
      }],
      "properties": {
        "severity": "HIGH",
        "cvssScore": 7.5,
        "fixedVersion": "3.0.12"
      }
    }]
  }]
}
```

---

## Vulnerability Data Sources

| Source | Coverage | Update Mechanism | License |
|--------|----------|------------------|---------|
| **OSV (Open Source Vulnerabilities)** | 20+ ecosystems (Debian, Alpine, PyPI, npm, Go, Maven, Cargo, Gem, etc.) | Daily incremental via `modified` field; bulk download available | CC-BY-4.0 |
| **NVD (National Vulnerability Database)** | All CVEs with CPE mappings | NVD API 2.0 (CVE 5.0 feed); rate-limited, cached | Public domain |
| **GitHub Security Advisories (GHSA)** | GitHub-tracked vulnerabilities, often earlier than NVD | GitHub GraphQL API; incremental | CC-BY-4.0 |

**Caching strategy:**
- SQLite database at `~/.pythia/vuln_cache.db` (configurable)
---

## CI/CD Integration

### GitHub Actions
```yaml
# .github/workflows/scan.yml
name: Container Scan
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan image
        uses: your-org/pythia-action@v1
        with:
          image: myapp:${{ github.sha }}
          registry-token: ${{ secrets.GHCR_TOKEN }}
          fail-on: HIGH
          sarif-upload: true
```

### GitLab CI
```yaml
container_scan:
  image: ghcr.io/your-org/pythia:latest
  script:
    - pythia scan $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA --sarif --out gl-sarif.json
  artifacts:
    reports:
      sast: gl-sarif.json
```

---

## Extending Pythia

### Adding a New Package Parser
1. Create `src/discovery/parsers/newparser.py` implementing `BaseParser`
2. Register in `src/discovery/parsers/__init__.py`
3. Add tests in `tests/unit/test_newparser.py`
4. Add fixture in `tests/fixtures/`

### Adding a New Vulnerability Source
1. Implement `BaseVulnSource` in `src/matching/sources/`
2. Register in `Updater.sources`
3. Handle pagination, rate limits, incremental sync

### Custom Report Formatter
```python
from pythia.reporting.base import ReportFormatter
from pythia.common.models import ScanResult

class MyCustomFormatter(ReportFormatter):
    def format(self, result: ScanResult) -> bytes:
        # Your logic
        return b"..."
```

---

## Known Limitations & Considerations

- **No runtime analysis** — Static scan only; does not detect vulnerable loaded libraries or runtime config issues
- **Debian version comparison** — Uses `packaging.version` with epoch handling; may not match `dpkg --compare-versions` exactly for edge cases
- **Layer extraction** — Does not fully simulate kernel mount namespaces; some overlay edge cases (nested whiteouts) may differ
- **Private registry support** — Tested against Docker Hub, GHCR, Harbor, ECR; other OCI-conformant registries should work
- **Windows containers** — Not currently supported (parsers target Linux filesystems)
- **Vulnerability coverage** — Depends on upstream data quality; false negatives possible for very new/obscure packages

---

## Roadmap

- [ ] CycloneDX & SPDX SBOM export
- [ ] Policy engine (OPA/Rego) for custom fail rules
- [ ] SBOM signing (cosign/sigstore)
- [ ] VEX (Vulnerability Exploitability eXchange) output
- [ ] Kubernetes admission controller integration
- [ ] Multi-arch manifest list (fat manifest) support
- [ ] Distroless / scratch image heuristic detection
- [ ] Plugin system for parsers/formatters/sources

---

## Contributing

1. Fork → branch → commit → PR
2. Follow code style: `ruff format`, `ruff check`, `mypy`
3. Add tests for new functionality
4. Update `CHANGELOG.md` (Keep a Changelog format)
5. Sign-off commits (`git commit -s`)

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

**Apache License 2.0** — See [LICENSE](LICENSE) for full text.

```
Copyright 2024-2026 Pythia Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## Acknowledgments

- **OSV** — For the open vulnerability database and schema
- **NVD** — For authoritative CVE data
- **Syft/Grype** — Inspiration for SBOM-first architecture
- **Trivy** — Benchmark for multi-ecosystem coverage
- **Rich** — Beautiful terminal UX
- **ReportLab** — PDF generation

---

## Support & Community

- **Issues** — [GitHub Issues](https://github.com/your-org/pythia/issues)

---

*Built with ♥ by security engineers who believe seeing is believing.*

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.discovery.manager import DiscoveryManager
from src.ingestion.manager import IngestionManager
from src.matching.engine import MatchingEngine
from src.reporting.json_formatter import generate_json_report
from src.reporting.pdf_generator import generate_pdf


def parse_args():
    parser = argparse.ArgumentParser(description="Custom Docker Vulnerability Scanner")
    parser.add_argument("image_ref", nargs="?", help="Docker image tag or local tar image archive")
    parser.add_argument("--archive", dest="archive_path", help="Path to a local Docker image tar archive")
    parser.add_argument("--pdf", action="store_true", help="Generate a PDF report")
    parser.add_argument("--out", default="scan_results.json", help="Output JSON file path")
    parser.add_argument("--registry-user", dest="registry_user", help="Username for a private registry")
    parser.add_argument("--registry-password", dest="registry_password", help="Password for a private registry")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.image_ref and not args.archive_path:
        raise SystemExit("Either an image tag or --archive path must be provided.")

    ingestion = IngestionManager()
    matching_engine = MatchingEngine()

    try:
        image_target = args.image_ref or args.archive_path
        if args.archive_path:
            rootfs = ingestion.ingest_from_archive(args.archive_path)
        else:
            rootfs = ingestion.ingest_from_registry(
                args.image_ref,
                registry_username=args.registry_user,
                registry_password=args.registry_password,
            )

        discovery = DiscoveryManager(rootfs)
        sbom = discovery.generate_sbom()
        sbom_data = sbom.to_json()

        vulnerabilities = matching_engine.scan_sbom(sbom_data)
        report_data = generate_json_report(image_target, sbom_data, vulnerabilities)

        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(report_data, handle, indent=2)
        print(f"\n[+] JSON report saved to: {args.out}")

        if args.pdf:
            pdf_path = args.out.replace(".json", ".pdf")
            generate_pdf(report_data, output_path=pdf_path)
    except Exception as exc:
        print(f"\n[!] Fatal Error during scan: {exc}")
        raise
    finally:
        ingestion.cleanup()


if __name__ == "__main__":
    main()
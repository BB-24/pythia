import os
import json
import tarfile
import tempfile
import shutil

from .extractor import ImageExtractor
from .registry_client import RegistryClient
from src.exceptions import ExtractionError
from src.logger import logger


class IngestionManager:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="scanner_fs_")
        self.download_dir = os.path.join(self.temp_dir, "downloads")
        self.rootfs_dir = os.path.join(self.temp_dir, "rootfs")

        os.makedirs(self.download_dir, exist_ok=True)
        os.makedirs(self.rootfs_dir, exist_ok=True)
        self.extraction_stats = {}
        self.virtual_symlinks = {}

    def ingest_from_registry(self, image_tag: str, registry_username: str | None = None,
                            registry_password: str | None = None) -> str:
        """FR 1.1: Orchestrates fetching and unpacking an image."""
        logger.info("Starting registry ingestion for %s", image_tag)

        client = RegistryClient(
            image_ref=image_tag,
            username=registry_username,
            password=registry_password,
        )
        extractor = ImageExtractor(self.rootfs_dir)

        layer_digests = client.fetch_manifest()
        for digest in layer_digests:
            tar_path = client.download_layer(digest, self.download_dir)
            extractor.extract_layer(tar_path)
            os.remove(tar_path)

        self.extraction_stats = {
            **dict(extractor.symlink_stats),
            "skipped_symlinks": dict(extractor.skipped_symlinks),
        }
        self.virtual_symlinks = dict(extractor.virtual_symlinks)

        logger.info("Registry ingestion complete; root filesystem is %s", self.rootfs_dir)
        return self.rootfs_dir

    def ingest_from_archive(self, archive_path: str) -> str:
        """Loads a local Docker image tarball into the flattened root filesystem."""
        if not os.path.exists(archive_path):
            raise ExtractionError(f"Archive not found: {archive_path}")

        logger.info("Loading local image archive %s", archive_path)

        try:
            with tarfile.open(archive_path, "r:*") as archive:
                manifest_member = next(
                    (member for member in archive.getmembers() if member.name == "manifest.json"),
                    None,
                )
                if manifest_member is None:
                    raise ExtractionError("Archive does not contain manifest.json")
                manifest = json.load(archive.extractfile(manifest_member))
                extractor = ImageExtractor(self.rootfs_dir)
                for layer_name in manifest[0].get("Layers", []):
                    layer_member = archive.getmember(layer_name)
                    layer_path = os.path.join(self.download_dir, os.path.basename(layer_name))
                    with archive.extractfile(layer_member) as source, open(layer_path, "wb") as target:
                        shutil.copyfileobj(source, target)
                    extractor.extract_layer(layer_path)
                    os.remove(layer_path)
                self.extraction_stats = {
                    **dict(extractor.symlink_stats),
                    "skipped_symlinks": dict(extractor.skipped_symlinks),
                }
                self.virtual_symlinks = dict(extractor.virtual_symlinks)
        except (OSError, tarfile.TarError) as exc:
            logger.error("Local image archive extraction failed: %s", exc, exc_info=True)
            raise ExtractionError(f"Unable to extract archive: {archive_path}") from exc

        logger.info("Local archive extraction complete; root filesystem is %s", self.rootfs_dir)
        return self.rootfs_dir

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup()
        return False

    def cleanup(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.debug("Removed temporary scanner directory %s", self.temp_dir)
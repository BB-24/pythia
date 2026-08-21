import os
import tarfile
import tempfile

from .extractor import ImageExtractor
from .registry_client import RegistryClient


class IngestionManager:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="scanner_fs_")
        self.download_dir = os.path.join(self.temp_dir, "downloads")
        self.rootfs_dir = os.path.join(self.temp_dir, "rootfs")

        os.makedirs(self.download_dir, exist_ok=True)
        os.makedirs(self.rootfs_dir, exist_ok=True)

    def ingest_from_registry(self, image_tag: str, registry_username: str | None = None,
                            registry_password: str | None = None) -> str:
        """FR 1.1: Orchestrates fetching and unpacking an image."""
        print(f"=== Starting Ingestion for {image_tag} ===")

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

        print(f"=== Ingestion Complete. RootFS ready at: {self.rootfs_dir} ===")
        return self.rootfs_dir

    def ingest_from_archive(self, archive_path: str) -> str:
        """Loads a local Docker image tarball into the flattened root filesystem."""
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"Archive not found: {archive_path}")

        print(f"=== Loading local image archive: {archive_path} ===")
        extractor = ImageExtractor(self.rootfs_dir)

        with tarfile.open(archive_path, "r:*") as archive:
            for member in archive.getmembers():
                if member.name.endswith("/manifest.json"):
                    continue
                if member.isdir():
                    target = os.path.join(self.rootfs_dir, member.name)
                    os.makedirs(target, exist_ok=True)
                    continue
                if member.isfile() or member.isreg():
                    archive.extract(member, path=self.rootfs_dir)

        print(f"=== Local archive extraction complete. RootFS ready at: {self.rootfs_dir} ===")
        return self.rootfs_dir

    def cleanup(self):
        if os.path.exists(self.temp_dir):
            try:
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass
import os
import shutil
import tarfile
from pathlib import Path, PurePosixPath

from src.exceptions import ExtractionError
from src.logger import logger


class ImageExtractor:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)

    def extract_layer(self, tar_path: str):
        """FR 1.4: Extract a layer, correctly overlaying it and handling whiteouts."""
        logger.info("Extracting %s", os.path.basename(tar_path))

        try:
            with tarfile.open(tar_path, "r:*") as tar:
                members = tar.getmembers()
                for member in members:
                    if ".wh." in PurePosixPath(member.name).name:
                        self._handle_whiteout(member.name)
                        continue

                    resolved_target = self._safe_destination(member.name)
                    if resolved_target is None:
                        logger.warning("Skipping unsafe archive member %s", member.name)
                        continue

                    if member.issym():
                        self._extract_symlink(member, resolved_target)
                        continue

                    tar.extract(member, path=self.target_dir, filter="data")
        except (OSError, tarfile.TarError) as exc:
            logger.error("Layer extraction failed for %s: %s", tar_path, exc, exc_info=True)
            raise ExtractionError(f"Unable to extract layer: {tar_path}") from exc

    def _extract_symlink(self, member: tarfile.TarInfo, destination: Path):
        """Create a host-safe symlink for a link stored in the container rootfs."""
        link_name = member.linkname
        if not link_name:
            logger.warning("Skipping symlink with empty target %s", member.name)
            return

        if link_name.startswith("/"):
            target = self._safe_destination(link_name.lstrip("/"))
            if target is None:
                logger.warning("Skipping unsafe absolute symlink %s -> %s", member.name, link_name)
                return
            link_name = os.path.relpath(target, destination.parent).replace(os.sep, "/")
        else:
            link_target = PurePosixPath(member.name).parent / PurePosixPath(link_name)
            if self._safe_destination(str(link_target)) is None:
                logger.warning("Skipping unsafe symlink %s -> %s", member.name, link_name)
                return

        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                if destination.is_dir() and not destination.is_symlink():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()
            os.symlink(link_name, destination)
        except (OSError, NotImplementedError) as exc:
            logger.warning("Skipping symlink %s -> %s: %s", member.name, member.linkname, exc)

    def _safe_destination(self, member_name: str):
        normalized = PurePosixPath(member_name)
        if normalized.is_absolute() or ".." in normalized.parts:
            return None

        destination = (self.target_dir / normalized).resolve()
        root = self.target_dir.resolve()
        if root not in destination.parents and destination != root:
            return None
        return destination

    def _handle_whiteout(self, whiteout_filename: str):
        """Deletes files/directories marked for deletion by upper layers."""
        target_name = whiteout_filename.split(".wh.", 1)[-1]
        if target_name.startswith("."):
            target_name = target_name[1:]

        target_path = self._safe_destination(target_name)
        if target_path is None:
            return

        if target_path.exists():
            if target_path.is_dir() and not target_path.is_symlink():
                shutil.rmtree(target_path)
            else:
                target_path.unlink()

    def cleanup(self):
        """FR 4.2: Wipes the temporary extracted file system."""
        logger.info("Cleaning up temporary directory %s", self.target_dir)
        shutil.rmtree(self.target_dir, ignore_errors=True)
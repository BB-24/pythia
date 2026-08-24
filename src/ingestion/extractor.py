import os
import shutil
import tarfile
from collections import Counter
from pathlib import Path, PurePosixPath

from src.exceptions import ExtractionError
from src.logger import logger


class ImageExtractor:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.symlink_stats = Counter()
        self.skipped_symlinks = Counter()
        self.virtual_symlinks = {}

    def _tar_filter(self, member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
        """Allow links for manual handling while rejecting unsafe archive paths."""
        normalized = PurePosixPath(member.name)
        if normalized.is_absolute() or ".." in normalized.parts:
            return None
        return member

    def extract_layer(self, tar_path: str):
        """FR 1.4: Extract a layer, correctly overlaying it and handling whiteouts."""
        logger.info("Extracting %s", os.path.basename(tar_path))

        try:
            with tarfile.open(tar_path, "r:*") as tar:
                members = tar.getmembers()
                for member in members:
                    member_name = PurePosixPath(member.name)
                    if member_name.name == ".wh..wh..opq":
                        self._handle_opaque_whiteout(member.name)
                        continue
                    if member_name.name.startswith(".wh."):
                        self._handle_whiteout(member.name)
                        continue

                    resolved_target = self._safe_destination(member.name)
                    if resolved_target is None:
                        logger.warning("Skipping unsafe archive member %s", member.name)
                        continue

                    if member.issym():
                        self._extract_symlink(member, resolved_target)
                        continue
                    if member.islnk():
                        self._extract_hardlink(member, resolved_target)
                        continue

                    tar.extract(member, path=self.target_dir, filter=self._tar_filter)
                self._refresh_virtual_symlinks()
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
            self.symlink_stats["created"] += 1
        except (OSError, NotImplementedError) as exc:
            category = self._symlink_category(member.name)
            self.symlink_stats[f"skipped_{category.lower()}"] += 1
            self.skipped_symlinks[category] += 1
            self._materialize_virtual_symlink(member, destination, link_name)
            logger.warning("Using virtual symlink for %s -> %s: %s", member.name, member.linkname, exc)

    def _extract_hardlink(self, member: tarfile.TarInfo, destination: Path):
        """Materialize a hardlink without relying on host filesystem link privileges."""
        target = self._safe_destination(member.linkname)
        if target is None:
            logger.warning("Skipping unsafe hardlink %s -> %s", member.name, member.linkname)
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        if target.is_file():
            shutil.copy2(target, destination)
        else:
            logger.warning("Skipping hardlink with unavailable target %s -> %s", member.name, member.linkname)

    def _materialize_virtual_symlink(self, member: tarfile.TarInfo, destination: Path,
                                     link_name: str):
        """Keep link paths usable on hosts where creating symlinks is denied."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        target = destination.parent / link_name
        if destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()

        if target.is_file():
            shutil.copy2(target, destination)
        elif target.is_dir():
            shutil.copytree(target, destination)
        else:
            destination.touch()
        self.virtual_symlinks[member.name] = member.linkname

    def _refresh_virtual_symlinks(self):
        for member_name, link_name in self.virtual_symlinks.items():
            destination = self._safe_destination(member_name)
            if destination is None:
                continue
            if link_name.startswith("/"):
                target = self._safe_destination(link_name.lstrip("/"))
                if target is None:
                    continue
            else:
                target_name = PurePosixPath(member_name).parent / PurePosixPath(link_name)
                target = self._safe_destination(str(target_name))
            if target is None or not target.exists():
                continue
            if target.is_file():
                if destination.is_dir() and not destination.is_symlink():
                    shutil.rmtree(destination)
                shutil.copy2(target, destination)
            elif target.is_dir():
                if destination.exists():
                    if destination.is_dir() and not destination.is_symlink():
                        shutil.rmtree(destination)
                    else:
                        destination.unlink()
                shutil.copytree(target, destination)

    @staticmethod
    def _symlink_category(member_name: str) -> str:
        normalized = str(PurePosixPath(member_name))
        critical = {"bin", "sbin", "lib", "lib64", "usr/bin", "usr/sbin", "usr/lib",
                    "etc/os-release"}
        if normalized in critical or any(normalized.startswith(item + "/") for item in critical):
            return "CRITICAL"
        if normalized.startswith(("etc/", "var/lib/", "usr/local/", "opt/")):
            return "IMPORTANT"
        return "OPTIONAL"

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
        whiteout_path = PurePosixPath(whiteout_filename)
        target_path = self._safe_destination(str(whiteout_path.parent / whiteout_path.name[4:]))
        if target_path is None:
            return

        if target_path.exists() or target_path.is_symlink():
            if target_path.is_dir() and not target_path.is_symlink():
                shutil.rmtree(target_path)
            else:
                target_path.unlink()

    def _handle_opaque_whiteout(self, whiteout_filename: str):
        whiteout_path = PurePosixPath(whiteout_filename)
        directory = self._safe_destination(str(whiteout_path.parent))
        if directory is None or not directory.is_dir():
            return
        for child in directory.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()

    def cleanup(self):
        """FR 4.2: Wipes the temporary extracted file system."""
        logger.info("Cleaning up temporary directory %s", self.target_dir)
        shutil.rmtree(self.target_dir, ignore_errors=True)
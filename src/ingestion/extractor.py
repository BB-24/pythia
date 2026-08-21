import os
import shutil
import tarfile
from pathlib import Path, PurePosixPath


class ImageExtractor:
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)

    def extract_layer(self, tar_path: str):
        """FR 1.4: Extract a layer, correctly overlaying it and handling whiteouts."""
        print(f"[~] Extracting {os.path.basename(tar_path)}...")

        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            for member in members:
                if ".wh." in PurePosixPath(member.name).name:
                    self._handle_whiteout(member.name)
                    continue

                resolved_target = self._safe_destination(member.name)
                if resolved_target is None:
                    continue

                try:
                    tar.extract(member, path=self.target_dir, filter="data")
                except Exception:
                    if member.isdir():
                        resolved_target.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        resolved_target.parent.mkdir(parents=True, exist_ok=True)
                        extracted = tar.extractfile(member)
                        if extracted is not None:
                            with extracted, open(resolved_target, "wb") as file_handle:
                                file_handle.write(extracted.read())

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
        print(f"[-] Cleaning up temporary directory: {self.target_dir}")
        shutil.rmtree(self.target_dir, ignore_errors=True)
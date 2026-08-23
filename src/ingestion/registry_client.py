import os
from typing import List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.exceptions import ImageNotFoundError, RegistryAuthError, UpstreamAPIError
from src.logger import logger


class RegistryClient:
    def __init__(self, image_ref: str, username: str | None = None, password: str | None = None):
        self.username = username or os.getenv("REGISTRY_USERNAME")
        self.password = password or os.getenv("REGISTRY_PASSWORD")

        self.image, self.tag, self.registry_url, self.auth_url = self._parse_image_reference(image_ref)
        self.session = requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.5,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.token = self._get_auth_token()

    def _parse_image_reference(self, image_ref: str):
        ref = image_ref.strip()
        if not ref:
            raise ValueError("A Docker image reference is required.")

        if "@" in ref:
            image_name, digest = ref.rsplit("@", 1)
            tag = digest
        else:
            image_name = ref
            tag = "latest"
            if ":" in ref.rsplit("/", 1)[-1]:
                image_name, tag = ref.rsplit(":", 1)

        registry_host = "registry-1.docker.io"
        repository = image_name
        if "/" in image_name and image_name.split("/", 1)[0].count(".") or ":" in image_name.split("/", 1)[0]:
            registry_host, repository = image_name.split("/", 1)
            repository = repository.strip("/")
        else:
            if "/" not in image_name:
                repository = f"library/{image_name}"
            registry_host = "registry-1.docker.io"

        if registry_host in {"docker.io", "index.docker.io", "registry-1.docker.io"}:
            registry_url = "https://registry-1.docker.io/v2"
            auth_url = "https://auth.docker.io/token"
        else:
            registry_url = f"https://{registry_host}/v2"
            auth_url = f"https://{registry_host}/v2/token"

        return repository, tag, registry_url, auth_url

    def _get_auth_token(self) -> str:
        """FR 1.2: Authenticate and retrieve a Bearer token."""
        if self.username and self.password:
            return "basic-auth"

        params = {"service": "registry.docker.io", "scope": f"repository:{self.image}:pull"}
        if self.registry_url.startswith("https://") and "/v2" in self.registry_url and self.registry_url != "https://registry-1.docker.io/v2":
            params = {"scope": f"repository:{self.image}:pull"}

        try:
            response = self.session.get(self.auth_url, params=params, timeout=10)
            if response.status_code in (401, 403):
                raise RegistryAuthError("Registry authentication failed or the repository is private.")
            response.raise_for_status()
            payload = response.json()
        except RegistryAuthError:
            raise
        except requests.RequestException as exc:
            logger.error("Registry token request failed for %s: %s", self.image, exc, exc_info=True)
            raise UpstreamAPIError("Registry token request failed") from exc
        token = payload.get("token")
        if not token and payload.get("access_token"):
            token = payload["access_token"]
        return token or ""

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"}
        if self.username and self.password:
            headers["Authorization"] = "Basic " + requests.auth._basic_auth_str(self.username, self.password)
        elif self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def fetch_manifest(self) -> List[str]:
        """FR 1.3: Download and parse the OCI image manifest to get layer digests."""
        url = f"{self.registry_url}/{self.image}/manifests/{self.tag}"
        try:
            response = self.session.get(url, headers=self._headers(), timeout=10)
            if response.status_code in (401, 403):
                raise RegistryAuthError("Authentication required to access the image manifest.")
            if response.status_code == 404:
                raise ImageNotFoundError(f"Image manifest not found: {self.image}:{self.tag}")
            response.raise_for_status()
        except (RegistryAuthError, ImageNotFoundError):
            raise
        except requests.RequestException as exc:
            logger.error("Manifest request failed for %s:%s: %s", self.image, self.tag, exc, exc_info=True)
            raise UpstreamAPIError("Image manifest request failed") from exc

        manifest = response.json()
        if "manifests" in manifest:
            manifest = next(
                (item for item in manifest["manifests"] if item.get("platform", {}).get("os") == "linux"),
                manifest["manifests"][0],
            )
            digest = manifest["digest"]
            try:
                response = self.session.get(
                    f"{self.registry_url}/{self.image}/manifests/{digest}",
                    headers=self._headers(),
                    timeout=10,
                )
                response.raise_for_status()
            except requests.RequestException as exc:
                logger.error("Platform manifest request failed for %s: %s", self.image, exc, exc_info=True)
                raise UpstreamAPIError("Platform manifest request failed") from exc
            manifest = response.json()

        layers = [layer["digest"] for layer in manifest.get("layers", [])]
        logger.info("Parsed manifest for %s:%s; found %d layers", self.image, self.tag, len(layers))
        return layers

    def download_layer(self, digest: str, dest_dir: str) -> str:
        """Downloads a single .tar.gz layer blob from the registry."""
        headers = self._headers()
        url = f"{self.registry_url}/{self.image}/blobs/{digest}"
        tar_path = os.path.join(dest_dir, f"{digest.replace('sha256:', '')}.tar.gz")

        logger.info("Downloading layer %s...", digest[:15])
        try:
            with self.session.get(url, headers=headers, stream=True, timeout=10) as response:
                if response.status_code == 404:
                    raise ImageNotFoundError(f"Image layer not found: {digest}")
                response.raise_for_status()
                with open(tar_path, "wb") as handle:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            handle.write(chunk)
        except ImageNotFoundError:
            raise
        except requests.RequestException as exc:
            logger.error("Layer download failed for %s: %s", digest, exc, exc_info=True)
            raise UpstreamAPIError(f"Layer download failed: {digest}") from exc

        return tar_path
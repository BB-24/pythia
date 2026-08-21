import os
from typing import List

import requests


class RegistryClient:
    def __init__(self, image_ref: str, username: str | None = None, password: str | None = None):
        self.username = username or os.getenv("REGISTRY_USERNAME")
        self.password = password or os.getenv("REGISTRY_PASSWORD")

        self.image, self.tag, self.registry_url, self.auth_url = self._parse_image_reference(image_ref)
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

        if registry_host in {"docker.io", "index.docker.io"}:
            registry_url = "https://registry-1.docker.io/v2"
            auth_url = "https://auth.docker.io/token"
            registry_scope = f"repository:{repository}:pull"
        else:
            registry_url = f"https://{registry_host}/v2"
            auth_url = f"https://{registry_host}/v2/token"
            registry_scope = f"repository:{repository}:pull"

        return repository, tag, registry_url, auth_url

    def _get_auth_token(self) -> str:
        """FR 1.2: Authenticate and retrieve a Bearer token."""
        if self.username and self.password:
            return "basic-auth"

        params = {"service": "registry.docker.io", "scope": f"repository:{self.image}:pull"}
        if self.registry_url.startswith("https://") and "/v2" in self.registry_url and self.registry_url != "https://registry-1.docker.io/v2":
            params = {"scope": f"repository:{self.image}:pull"}

        response = requests.get(self.auth_url, params=params, timeout=20)
        if response.status_code == 401:
            raise PermissionError("Registry authentication failed or the repository is private.")
        response.raise_for_status()
        payload = response.json()
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
        response = requests.get(url, headers=self._headers(), timeout=30)
        if response.status_code == 401:
            raise PermissionError("Authentication required to access the image manifest.")
        response.raise_for_status()

        manifest = response.json()
        if "manifests" in manifest:
            manifest = next(
                (item for item in manifest["manifests"] if item.get("platform", {}).get("os") == "linux"),
                manifest["manifests"][0],
            )
            digest = manifest["digest"]
            response = requests.get(f"{self.registry_url}/{self.image}/manifests/{digest}", headers=self._headers(), timeout=30)
            response.raise_for_status()
            manifest = response.json()

        layers = [layer["digest"] for layer in manifest.get("layers", [])]
        print(f"[+] Parsed manifest for {self.image}:{self.tag}. Found {len(layers)} layers.")
        return layers

    def download_layer(self, digest: str, dest_dir: str) -> str:
        """Downloads a single .tar.gz layer blob from the registry."""
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        url = f"{self.registry_url}/{self.image}/blobs/{digest}"
        tar_path = os.path.join(dest_dir, f"{digest.replace('sha256:', '')}.tar.gz")

        print(f"[~] Downloading layer {digest[:15]}...")
        with requests.get(url, headers=headers, stream=True, timeout=60) as response:
            response.raise_for_status()
            with open(tar_path, "wb") as handle:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        handle.write(chunk)

        return tar_path
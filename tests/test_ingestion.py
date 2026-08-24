import json
import os
import tarfile
import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.ingestion.extractor import ImageExtractor
from src.ingestion.manager import IngestionManager
from src.ingestion.registry_client import RegistryClient
from src.exceptions import ExtractionError, ImageNotFoundError, RegistryAuthError, UpstreamAPIError


class TestRegistryClientParseImageReference:
    """Tests for _parse_image_reference method."""

    def setup_method(self):
        self.patcher = patch.object(RegistryClient, '_get_auth_token', return_value='dummy-token')
        self.mock_get_auth_token = self.patcher.start()

    def teardown_method(self):
        self.patcher.stop()

    def test_parse_simple_image(self):
        """Test parsing a simple image name."""
        client = RegistryClient("nginx")
        assert client.image == "library/nginx"
        assert client.tag == "latest"

    def test_parse_image_with_tag(self):
        """Test parsing image with tag."""
        client = RegistryClient("nginx:1.19")
        assert client.image == "library/nginx"
        assert client.tag == "1.19"

    def test_parse_image_with_digest(self):
        """Test parsing image with digest."""
        client = RegistryClient("alpine@sha256:abc123")
        assert client.image == "library/alpine"
        assert client.tag == "sha256:abc123"

    def test_parse_official_image_with_slash(self):
        """Test parsing official image with slash (library/)."""
        client = RegistryClient("nginx:latest")
        assert client.image == "library/nginx"
        assert client.tag == "latest"

    def test_parse_private_registry(self):
        """Test parsing private registry URL."""
        client = RegistryClient("myregistry.com/myimage:tag")
        assert client.image == "myimage"
        assert client.tag == "tag"

    def test_parse_private_registry_with_port(self):
        """Test parsing private registry with port."""
        client = RegistryClient("myregistry.com:5000/myimage:tag")
        assert client.image == "myimage"
        assert client.tag == "tag"

    def test_parse_docker_io_aliases(self):
        """Test parsing docker.io and index.docker.io aliases."""
        for host in ["docker.io", "index.docker.io", "registry-1.docker.io"]:
            client = RegistryClient(f"{host}/library/alpine:latest")
            assert client.registry_url == "https://registry-1.docker.io/v2"
            assert client.auth_url == "https://auth.docker.io/token"
class TestRegistryClientFetchManifest:
    """Tests for fetch_manifest method."""

    def test_fetch_manifest_success(self):
        """Test successful manifest fetch."""
        client = RegistryClient("library/alpine:latest")
        # Override the session to avoid real network calls
        client.session = MagicMock()
        client.session.get.return_value.status_code = 200
        client.session.get.return_value.json.return_value = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 1469,
                "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
            },
            "layers": [
                {
                    "digest": "sha256:abc123",
                    "size": 1234
                }
            ]
        }

        layers = client.fetch_manifest()

        assert layers == ["sha256:abc123"]

    def test_fetch_manifest_multi_arch(self):
        """Test fetching manifest for multi-arch image."""
        client = RegistryClient("library/alpine:latest")
        client.session = MagicMock()
        # First call returns manifest list
        manifest_list_response = MagicMock()
        manifest_list_response.status_code = 200
        manifest_list_response.json.return_value = {
            "manifests": [
                {
                    "digest": "sha256:amd64",
                    "platform": {"architecture": "amd64", "os": "linux"}
                },
                {
                    "digest": "sha256:arm64",
                    "platform": {"architecture": "arm64", "os": "linux"}
                }
            ]
        }
        # Second call returns actual manifest for amd64 (first linux platform)
        manifest_response = MagicMock()
        manifest_response.status_code = 200
        manifest_response.json.return_value = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "layers": [
                {"digest": "sha256:layer1", "size": 100},
                {"digest": "sha256:layer2", "size": 200}
            ]
        }
        client.session.get.side_effect = [manifest_list_response, manifest_response]

        layers = client.fetch_manifest()

        assert layers == ["sha256:layer1", "sha256:layer2"]

    def test_fetch_manifest_404_raises(self):
        """Test that 404 raises ImageNotFoundError."""
        client = RegistryClient("nonexistent:latest")
        client.session = MagicMock()
        client.session.get.return_value.status_code = 404

        with pytest.raises(ImageNotFoundError):
            client.fetch_manifest()

    def test_fetch_manifest_401_raises(self):
        """Test that 401 raises RegistryAuthError."""
        client = RegistryClient("private:latest")
        client.session = MagicMock()
        client.session.get.return_value.status_code = 401

        with pytest.raises(RegistryAuthError):
            client.fetch_manifest()

    def test_fetch_manifest_network_error_raises(self):
        """Test that network error raises UpstreamAPIError."""
        client = RegistryClient("test:latest")
        client.session = MagicMock()
        client.session.get.side_effect = requests.RequestException("Network error")

        with pytest.raises(UpstreamAPIError):
            client.fetch_manifest()
class TestRegistryClientDownloadLayer:
    """Tests for download_layer method."""

    def setup_method(self):
        self.patcher = patch.object(RegistryClient, '_get_auth_token', return_value='dummy-token')
        self.mock_get_auth_token = self.patcher.start()

    def teardown_method(self):
        self.patcher.stop()

    def test_download_layer_success(self):
        """Test successful layer download."""
        client = RegistryClient("library/alpine:latest")
        client.session = MagicMock()
        response_mock = MagicMock()
        response_mock.status_code = 200
        response_mock.iter_content.return_value = [b"data1", b"data2"]
        client.session.get.return_value.__enter__.return_value = response_mock

        tar_path = client.download_layer("sha256:abc123", "/tmp")

        assert tar_path == os.path.join("/tmp", "abc123.tar.gz")
        # Verify file was written
        with open(tar_path, "rb") as f:
            assert f.read() == b"data1data2"

    def test_download_layer_404_raises(self):
        """Test that 404 raises ImageNotFoundError."""
        client = RegistryClient("test:latest")
        client.session = MagicMock()
        response_mock = MagicMock()
        response_mock.status_code = 404
        client.session.get.return_value.__enter__.return_value = response_mock


        with pytest.raises(ImageNotFoundError):
            client.download_layer("sha256:abc123", "/tmp")

    def test_download_layer_network_error_raises(self):
        """Test that network error raises UpstreamAPIError."""
        client = RegistryClient("test:latest")
        client.session = MagicMock()
        client.session.get.side_effect = requests.RequestException("Network error")

        with pytest.raises(UpstreamAPIError):
            client.download_layer("sha256:abc123", "/tmp")
class TestImageExtractor:
    """Tests for ImageExtractor class."""

    def test_extract_tar_gz_success(self, tmp_path):
        """Test successful tar.gz extraction."""
        target_dir = tmp_path / "rootfs"
        extractor = ImageExtractor(str(target_dir))

        # Create a test tar.gz file
        tar_path = tmp_path / "layer.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            # Add a simple file
            file_content = b"Hello, World!"
            tarinfo = tarfile.TarInfo(name="test.txt")
            tarinfo.size = len(file_content)
            tar.addfile(tarinfo, fileobj=io.BytesIO(file_content))

        # Extract the layer
        extractor.extract_layer(str(tar_path))

        # Verify file was extracted
        extracted_file = target_dir / "test.txt"
        assert extracted_file.exists()
        assert extracted_file.read_bytes() == file_content

    def test_extract_tar_gz_with_symlinks(self, tmp_path):
        """Test extraction with symlinks."""
        target_dir = tmp_path / "rootfs"
        extractor = ImageExtractor(str(target_dir))

        # Create a test tar.gz file with symlink
        tar_path = tmp_path / "layer.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            # Add a target file
            target_content = b"Target content"
            target_info = tarfile.TarInfo(name="target.txt")
            target_info.size = len(target_content)
            tar.addfile(target_info, fileobj=io.BytesIO(target_content))
            
            # Add a symlink
            symlink_info = tarfile.TarInfo(name="link.txt")
            symlink_info.type = tarfile.SYMTYPE
            symlink_info.linkname = "target.txt"
            tar.addfile(symlink_info)

        # Extract the layer
        extractor.extract_layer(str(tar_path))

        # Verify both files exist and symlink points to target
        target_file = target_dir / "target.txt"
        link_file = target_dir / "link.txt"
        assert target_file.exists()
        assert link_file.exists()
        assert link_file.is_symlink()
        assert link_file.readlink() == "target.txt"
        assert target_file.read_bytes() == target_content

    def test_extract_tar_gz_invalid_file_raises(self):
        """Test that invalid tar file raises ExtractionError."""
        extractor = ImageExtractor("/tmp")

        with pytest.raises(ExtractionError):
            extractor.extract_layer("/nonexistent/file.tar.gz")

    def test_extract_tar_gz_nonexistent_raises(self):
        """Test that nonexistent file raises ExtractionError."""
        extractor = ImageExtractor("/tmp")

        with pytest.raises(ExtractionError):
            extractor.extract_layer("/nonexistent/file.tar.gz")

    def test_extract_tar_gz_directory_traversal_protection(self, tmp_path):
        """Test that directory traversal attempts are blocked."""
        target_dir = tmp_path / "rootfs"
        extractor = ImageExtractor(str(target_dir))

        # Create a tar with dangerous path
        tar_path = tmp_path / "layer.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            # Try to escape via absolute path
            bad_info = tarfile.TarInfo(name="/etc/passwd")
            bad_info.size = 0
            tar.addfile(bad_info, fileobj=io.BytesIO(b""))
            
            # Try to escape via .. 
            bad_info2 = tarfile.TarInfo(name="../../../etc/passwd")
            bad_info2.size = 0
            tar.addfile(bad_info2, fileobj=io.BytesIO(b""))

        # Extract should skip dangerous paths
        extractor.extract_layer(str(tar_path))

        # Verify no files were extracted outside target_dir
        assert not (target_dir.parent / "etc" / "passwd").exists()
class TestIngestionManager:
    """Tests for IngestionManager class."""

    def test_ingest_from_registry(self, tmp_path):
        """Test ingesting from registry."""
        with patch('src.ingestion.registry_client.RegistryClient') as mock_client_class, \
             patch('src.ingestion.extractor.ImageExtractor') as mock_extractor_class:
            
            # Setup mocks
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.fetch_manifest.return_value = ["sha256:abc123"]
            mock_client.download_layer.return_value = "/tmp/layer.tar.gz"
            
            mock_extractor = MagicMock()
            mock_extractor_class.return_value = mock_extractor
            
            # Create manager and ingest
            manager = IngestionManager()
            rootfs = manager.ingest_from_registry("test/image:latest")
            
            # Verify calls
            mock_client_class.assert_called_once_with(
                image_ref="test/image:latest",
                username=None,
                password=None
            )
            mock_client.fetch_manifest.assert_called_once()
            mock_client.download_layer.assert_called_once_with("sha256:abc123", manager.download_dir)
            mock_extractor.extract_layer.assert_called_once_with("/tmp/layer.tar.gz")
            assert rootfs == manager.rootfs_dir

    def test_ingest_from_registry_with_credentials(self, tmp_path):
        """Test ingesting from registry with credentials."""
        with patch('src.ingestion.registry_client.RegistryClient') as mock_client_class, \
             patch('src.ingestion.extractor.ImageExtractor'):
            
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.fetch_manifest.return_value = []
            
            manager = IngestionManager()
            manager.ingest_from_registry(
                "test/image:latest",
                registry_username="user",
                registry_password="pass"
            )
            
            mock_client_class.assert_called_once_with(
                image_ref="test/image:latest",
                username="user",
                password="pass"
            )

    def test_ingest_from_archive(self, tmp_path):
        """Test ingesting from a tar file."""
        # Create a test tar file
        tar_file = tmp_path / "image.tar"
        with tarfile.open(tar_file, "w") as tar:
            # Add manifest.json
            manifest = [{"Layers": ["layer1.tar.gz"]}]
            manifest_info = tarfile.TarInfo(name="manifest.json")
            manifest_info.size = len(json.dumps(manifest))
            tar.addfile(manifest_info, fileobj=io.BytesIO(json.dumps(manifest).encode()))
            
            # Add layer
            layer_info = tarfile.TarInfo(name="layer1.tar.gz")
            layer_info.size = 0
            tar.addfile(layer_info, fileobj=io.BytesIO(b""))
        
        with patch('src.ingestion.extractor.ImageExtractor') as mock_extractor_class:
            mock_extractor = MagicMock()
            mock_extractor_class.return_value = mock_extractor
            
            manager = IngestionManager()
            rootfs = manager.ingest_from_archive(str(tar_file))
            
            # Verify extractor was called
            mock_extractor.extract_layer.assert_called_once()
            assert rootfs == manager.rootfs_dir

    def test_ingest_from_archive_nonexistent_raises(self):
        """Test that nonexistent tar file raises ExtractionError."""
        manager = IngestionManager()
        
        with pytest.raises(ExtractionError):
            manager.ingest_from_archive("/nonexistent/image.tar")

    def test_cleanup(self):
        """Test cleanup removes temporary directory."""
        manager = IngestionManager()
        temp_dir = manager.temp_dir
        
        # Verify directory exists
        assert os.path.exists(temp_dir)
        
        # Cleanup
        manager.cleanup()
        
        # Verify directory is removed
        assert not os.path.exists(temp_dir)

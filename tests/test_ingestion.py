from src.ingestion.manager import IngestionManager

if __name__ == "__main__":
    manager = IngestionManager()
    try:
        # We'll use a small image for testing
        rootfs_path = manager.ingest_from_registry("alpine:3.18")
        
        # List the top level directories of the extracted container
        import os
        assert isinstance(os.listdir(rootfs_path), list)
        
    finally:
        # Automatically clean up
        manager.cleanup()
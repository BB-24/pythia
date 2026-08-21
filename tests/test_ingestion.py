from src.ingestion.manager import IngestionManager

if __name__ == "__main__":
    manager = IngestionManager()
    try:
        # We'll use a small image for testing
        rootfs_path = manager.ingest_from_registry("alpine:3.18")
        
        print("\n[SUCCESS] Extracted Filesystem preview:")
        # List the top level directories of the extracted container
        import os
        print(os.listdir(rootfs_path))
        
    finally:
        # Automatically clean up
        manager.cleanup()
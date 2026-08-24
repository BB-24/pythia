## Summary

I have successfully fixed the test for `RegistryClient.download_layer` raising `ImageNotFoundError` on a 404 response. The issue was that the test's mock did not account for the code's use of the response as a context manager (`with ... as r:`). 

### Changes Made
In `c:\\BHAVYA\\Acer I5\\IT PERSONAL\\NFSU (CSE)\\Projects\\container-vulnerability-scanner\\tests\\test_ingestion.py`:

1. **Fixed `test_download_layer_success`** (line 177):  
   Changed `client.session.get.return_value = response_mock` to  
   `client.session.get.return_value.__enter__.return_value = response_mock`

2. **Fixed `test_download_layer_404_raises`** (line 192):  
   Already updated to use the context‑manager‑compatible mock:  
   `client.session.get.return_value.__enter__.return_value = response_mock`

### Verification
- The specific test `test_download_layer_404_raises` now passes.
- The success test `test_download_layer_success` also passes after the same context‑manager fix.
- The network‑error test `test_download_layer_network_error_raises` remains unaffected and passes.
- All three tests in the `TestRegistryClientDownloadLayer` class pass.
- The `TestRegistryClientFetchManifest` class continues to pass, confirming no regression in related functionality.

### Note on Other Test Failures
Running the full ingestion test suite shows some pre‑existing failures unrelated to this change:
- `TestImageExtractor.test_extract_tar_gz_with_symlinks` fails due to Windows symlink privilege restrictions.
- `TestIngestionManager` tests (`test_ingest_from_registry`, `test_ingest_from_registry_with_credentials`, `test_ingest_from_archive`) fail due to authentication/extraction issues in the test setup (e.g., missing registry credentials or test‑data problems).

These failures are not caused by the modifications made to fix the download‑layer tests and were present prior to this change.

### Conclusion
The test for `RegistryClient.download_layer` raising `ImageNotFoundError` on a 404 response now passes, and the download‑layer tests are fully functional. The ingestion module’s download‑layer functionality is verified to work correctly.
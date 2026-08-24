from src.matching.db_client import CVEClient
from src.matching.updater import IntelligenceUpdater


class FakeResponse:
	def __init__(self, status_code, payload=None, headers=None):
		self.status_code = status_code
		self.payload = payload or {}
		self.headers = headers or {}

	def json(self):
		return self.payload

	def raise_for_status(self):
		if self.status_code >= 400:
			raise RuntimeError(self.status_code)


def test_empty_upstream_result_is_cached(tmp_path, monkeypatch):
	db = CVEClient(str(tmp_path / "cache.db"))
	updater = IntelligenceUpdater(db)
	calls = []

	monkeypatch.setattr(updater, "_fetch_osv", lambda package, ecosystem: calls.append("osv") or [])
	monkeypatch.setattr(updater, "_fetch_nvd", lambda package: calls.append("nvd") or [])

	updater.fetch_and_cache("missing", "Debian")
	updater.fetch_and_cache("missing", "Debian")

	assert calls == ["osv", "nvd"]
	assert db.is_package_cached("missing", "Debian", 60)
	assert db.get_vulnerabilities("missing", "Debian") == []


def test_nvd_429_retries_with_backoff(tmp_path, monkeypatch):
	db = CVEClient(str(tmp_path / "cache.db"))
	updater = IntelligenceUpdater(db)
	responses = [FakeResponse(429), FakeResponse(200, {"vulnerabilities": []})]
	sleeps = []

	class Session:
		def get(self, url, **kwargs):
			return responses.pop(0)

	updater.session = Session()
	monkeypatch.setattr("src.matching.updater.time.sleep", lambda delay: sleeps.append(delay))

	response = updater._request("GET", updater.nvd_url)

	assert response.status_code == 200
	assert len(sleeps) >= 1

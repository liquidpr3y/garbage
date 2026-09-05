"""AI endpoints and the credential probe."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from necropsy.ai.client import credential_source, have_credentials
from necropsy.api.router import router

PREFIX = "/api/v1/necropsy"


@pytest.fixture
def client(database, host):  # type: ignore[no-untyped-def]
    app = FastAPI()
    app.include_router(router, prefix=PREFIX)
    with TestClient(app) as c:
        yield c


def test_credential_probe_reports_absence(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Constructing the SDK client proves nothing -- it fails only at request time."""
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path / "nonexistent"))
    from necropsy.config import get_settings

    get_settings.cache_clear()
    assert credential_source() is None
    assert have_credentials() is False


def test_credential_probe_finds_each_source(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from necropsy.config import get_settings

    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path / "none"))

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    get_settings.cache_clear()
    assert credential_source() == "ANTHROPIC_API_KEY"

    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok")
    get_settings.cache_clear()
    assert credential_source() == "ANTHROPIC_AUTH_TOKEN"

    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN")
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "config.json").write_text("{}")
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(profile))
    get_settings.cache_clear()
    assert "ant profile" in (credential_source() or "")


def test_status_endpoint(client: TestClient) -> None:
    status = client.get(f"{PREFIX}/ai/status").json()
    assert status["sdk_installed"] is True
    assert status["model"] == "claude-opus-5"
    assert isinstance(status["credentials"], bool)
    # A missing goodware corpus is surfaced, not hidden.
    assert status["goodware_configured"] is False


def test_report_and_rules_are_404_before_they_exist(client: TestClient) -> None:
    case = client.post(f"{PREFIX}/cases", json={"name": "Empty"}).json()
    response = client.get(f"{PREFIX}/cases/{case['id']}/report")
    assert response.status_code == 404
    assert "ai_report" in response.json()["detail"]

    assert client.get(f"{PREFIX}/cases/{case['id']}/yara").json()["rules"] == []
    assert client.get(f"{PREFIX}/cases/nope/report").status_code == 404

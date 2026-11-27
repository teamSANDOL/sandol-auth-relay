import pytest
from fastapi.testclient import TestClient

import main
from app.config.config import parse_issue_link_auth_mode


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "warn"),
        ("", "warn"),
        ("   ", "warn"),
        (" Enforce ", "enforce"),
        ("OFF", "off"),
        ("enfoce", "enfoce"),
    ],
)
def test_parse_issue_link_auth_mode(raw: str | None, expected: str) -> None:
    assert parse_issue_link_auth_mode(raw) == expected


def test_invalid_auth_mode_fails_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.Config, "ISSUE_LINK_AUTH_MODE", "enfoce")
    with pytest.raises(RuntimeError, match="ISSUE_LINK_AUTH_MODE"):
        with TestClient(main.app):
            pass

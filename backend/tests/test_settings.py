"""CORS_ORIGINS has to survive the ways people actually write env vars.

pydantic-settings parses a list[str] field as JSON, so the obvious spellings
(one bare origin, a comma-separated list) crash the process at import time
rather than failing at the request that needs them.
"""

import pytest

from app.settings import Settings


def from_env(monkeypatch, value: str) -> list[str]:
    """Build Settings the way the container does: through the environment.

    Passing the value to the constructor takes a different code path and skips
    the settings source that does the JSON decoding, so a constructor-only test
    passes while the deployed app still fails to start.
    """
    monkeypatch.setenv("CORS_ORIGINS", value)
    return Settings(_env_file=None).cors_origins


def test_bare_origin_from_the_environment(monkeypatch):
    assert from_env(monkeypatch, "http://localhost:8011") == ["http://localhost:8011"]


def test_comma_separated_from_the_environment(monkeypatch):
    assert from_env(monkeypatch, "http://a.test,http://b.test") == [
        "http://a.test",
        "http://b.test",
    ]


def test_json_from_the_environment(monkeypatch):
    assert from_env(monkeypatch, '["http://a.test"]') == ["http://a.test"]


def test_bad_origin_from_the_environment_is_rejected(monkeypatch):
    with pytest.raises(ValueError, match="scheme://host"):
        from_env(monkeypatch, "localhost:8011")


def test_json_list_still_works():
    assert Settings(cors_origins='["http://a.test","http://b.test"]').cors_origins == [
        "http://a.test",
        "http://b.test",
    ]


def test_single_bare_origin():
    assert Settings(cors_origins="http://localhost:8011").cors_origins == ["http://localhost:8011"]


def test_comma_separated_origins():
    assert Settings(cors_origins="http://a.test, http://b.test").cors_origins == [
        "http://a.test",
        "http://b.test",
    ]


def test_trailing_slashes_are_dropped():
    """Browsers send the Origin header without a path, so a stored slash never matches."""
    assert Settings(cors_origins="http://a.test/").cors_origins == ["http://a.test"]


def test_empty_entries_are_dropped():
    assert Settings(cors_origins="http://a.test,,  ,http://b.test").cors_origins == [
        "http://a.test",
        "http://b.test",
    ]


def test_wildcard_is_kept_as_is():
    assert Settings(cors_origins="*").cors_origins == ["*"]


def test_empty_value_means_no_origin_allowed():
    assert Settings(cors_origins="").cors_origins == []


def test_a_list_passed_directly_is_still_accepted():
    assert Settings(cors_origins=["http://a.test"]).cors_origins == ["http://a.test"]


def test_origin_with_a_path_is_rejected_rather_than_silently_ignored():
    with pytest.raises(ValueError, match="scheme://host"):
        Settings(cors_origins="http://a.test/some/path")


def test_origin_without_a_scheme_is_rejected():
    with pytest.raises(ValueError, match="scheme://host"):
        Settings(cors_origins="localhost:8011")

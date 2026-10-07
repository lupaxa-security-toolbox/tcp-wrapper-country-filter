"""Allow and deny behaviour of the country filter."""

from __future__ import annotations

import pytest

import country_filter


class _Reader:
    def __init__(self, record: dict[str, str] | None) -> None:
        self.record = record
        self.seen: list[str] = []

    def __enter__(self) -> _Reader:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def get(self, ip_address: str) -> dict[str, str] | None:
        self.seen.append(ip_address)
        return self.record


def _patch_database(
    monkeypatch: pytest.MonkeyPatch,
    record: dict[str, str] | None,
) -> _Reader:
    reader = _Reader(record)

    def open_database(path: object) -> _Reader:
        assert path == country_filter.DATABASE
        return reader

    monkeypatch.setattr(country_filter.maxminddb, "open_database", open_database)
    return reader


@pytest.fixture(autouse=True)
def _quiet_syslog(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(country_filter.syslog, "syslog", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(country_filter, "BAN_LIST", "")
    monkeypatch.setattr(country_filter, "ACTION", country_filter.DENY_ACTION)
    monkeypatch.setattr(country_filter, "IP", "")
    monkeypatch.setattr(country_filter, "MUX", False)
    _patch_database(monkeypatch, {"country_code": "GB", "country": "United Kingdom"})


def _run(argv: list[str]) -> int | str | None:
    with pytest.raises(SystemExit) as exc:
        country_filter.main(argv)
    return exc.value.code


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(["--version"]) == 0
    assert _run(["-V"]) == 0
    captured = capsys.readouterr()
    assert captured.out == f"country-filter {country_filter.__version__}\n" * 2


def test_missing_address_allows() -> None:
    assert _run([]) == 0


def test_sample_lookup_allows() -> None:
    assert _run(["203.0.113.5"]) == 0


def test_deny_listed_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(country_filter, "BAN_LIST", "GB, other")
    assert _run(["203.0.113.5", "MUX"]) == 1
    assert country_filter.MUX is True
    assert country_filter.IP == "203.0.113.5"


def test_deny_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(country_filter, "BAN_LIST", "Gb")
    assert _run(["203.0.113.5"]) == 1


def test_allow_action_blocks_unknown_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(country_filter, "ACTION", country_filter.ALLOW_ACTION)
    assert _run(["203.0.113.5"]) == 1


def test_allow_action_permits_listed_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(country_filter, "ACTION", country_filter.ALLOW_ACTION)
    monkeypatch.setattr(country_filter, "BAN_LIST", "GB")
    assert _run(["203.0.113.5"]) == 0


def test_lookup_returns_iso_country_code(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _patch_database(
        monkeypatch,
        {"country_code": "GB", "country": "United Kingdom", "asn": "AS15169"},
    )

    assert country_filter.lookup("203.0.113.5") == "GB"
    assert reader.seen == ["203.0.113.5"]


def test_lookup_returns_empty_when_country_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_database(monkeypatch, None)
    assert country_filter.lookup("203.0.113.5") == ""


def test_lookup_returns_empty_when_country_code_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_database(monkeypatch, {"country": "United Kingdom"})
    assert country_filter.lookup("203.0.113.5") == ""


def test_lookup_returns_empty_for_non_text_code(monkeypatch: pytest.MonkeyPatch) -> None:
    class _OddReader:
        def __enter__(self) -> _OddReader:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, _ip_address: str) -> dict[str, int]:
            return {"country_code": 44}

    monkeypatch.setattr(country_filter.maxminddb, "open_database", lambda _path: _OddReader())
    assert country_filter.lookup("203.0.113.5") == ""


def test_lookup_returns_empty_when_database_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def open_database(path: object) -> _Reader:
        assert path == country_filter.DATABASE
        msg = f"IPinfo database not found: {country_filter.DATABASE}"
        raise FileNotFoundError(msg)

    monkeypatch.setattr(country_filter.maxminddb, "open_database", open_database)
    assert country_filter.lookup("203.0.113.5") == ""


def test_lookup_returns_empty_for_invalid_ip() -> None:
    assert country_filter.lookup("not-an-ip") == ""

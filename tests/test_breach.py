"""Tests for app.core.breach (no real network unless PYPASS_NETWORK_TESTS=1)."""
import os
import urllib.error

import pytest

from app.core import breach

PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


class _FakeResp:
    def __init__(self, body: str):
        self._body = body.encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture(autouse=True)
def _clear_cache():
    breach.clear_cache()
    yield
    breach.clear_cache()


@pytest.fixture
def fake_api(monkeypatch):
    """Patch urlopen; responses keyed by prefix. Records requests."""
    calls = []
    responses: dict[str, str] = {}

    def fake_urlopen(req, timeout=None):
        calls.append(req)
        prefix = req.full_url.rsplit("/", 1)[-1]
        if prefix not in responses:
            raise urllib.error.URLError("boom")
        return _FakeResp(responses[prefix])

    monkeypatch.setattr(breach.urllib.request, "urlopen", fake_urlopen)
    return calls, responses


def test_sha1_and_split():
    assert breach.sha1_hex("password") == PASSWORD_SHA1
    prefix, suffix = breach.split_hash("password")
    assert prefix == "5BAA6" and suffix == PASSWORD_SHA1[5:]
    assert len(suffix) == 35


def test_parse_ignores_padding_and_junk():
    body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\ngarbage\r\nbbb:x\n"
    assert breach.parse_range_response(body) == {"1E4C9B93F3F0682250B6CF8331B7EE68FD8": 42}


def test_pwned_count_sends_only_prefix(fake_api):
    calls, responses = fake_api
    responses["5BAA6"] = f"{PASSWORD_SHA1[5:]}:3861493\r\n{'0' * 35}:0"
    assert breach.pwned_count("password") == 3861493
    assert len(calls) == 1
    req = calls[0]
    assert req.full_url == "https://api.pwnedpasswords.com/range/5BAA6"
    assert PASSWORD_SHA1[5:] not in req.full_url
    assert req.get_header("Add-padding") == "true"
    assert req.get_header("User-agent") == "PyPassManager"
    assert req.data is None


def test_not_found_returns_zero(fake_api):
    _, responses = fake_api
    responses["5BAA6"] = f"{'0' * 35}:5"
    assert breach.pwned_count("password") == 0


def test_error_raises(fake_api):
    with pytest.raises(breach.BreachCheckError):
        breach.pwned_count("password")


def test_cache_avoids_second_request(fake_api):
    calls, responses = fake_api
    responses["5BAA6"] = f"{PASSWORD_SHA1[5:]}:10"
    assert breach.pwned_count("password") == 10
    assert breach.pwned_count("password") == 10
    assert len(calls) == 1


def test_cache_expires(fake_api, monkeypatch):
    calls, responses = fake_api
    responses["5BAA6"] = f"{PASSWORD_SHA1[5:]}:10"
    breach.pwned_count("password")
    monkeypatch.setattr(breach, "CACHE_TTL_SECONDS", -1)
    breach.pwned_count("password")
    assert len(calls) == 2


def test_check_many_groups_and_failures(fake_api):
    calls, responses = fake_api
    responses["5BAA6"] = f"{PASSWORD_SHA1[5:]}:7"
    other_prefix = breach.split_hash("hunter2")[0]
    assert other_prefix != "5BAA6"  # no response registered -> lookup fails
    progress = []
    result = breach.check_many(
        {1: "password", 2: "password", 3: "hunter2"},
        progress=lambda d, t: progress.append((d, t)),
    )
    assert result == {1: 7, 2: 7, 3: None}
    assert len(calls) == 2  # one per prefix
    assert progress == [(1, 2), (2, 2)]


def test_check_many_empty():
    assert breach.check_many({}) == {}


@pytest.mark.parametrize("n, expected", [
    (0, "0"), (7, "7"), (999, "999"), (1_000, "1K"), (1_500, "1.5K"),
    (12_345, "12K"), (3_200_000, "3.2M"), (52_000_000, "52M"), (2_000_000_000, "2B"),
])
def test_format_count(n, expected):
    assert breach.format_count(n) == expected


@pytest.mark.skipif(os.environ.get("PYPASS_NETWORK_TESTS") != "1",
                    reason="set PYPASS_NETWORK_TESTS=1 to hit the real HIBP API")
def test_real_api_password():
    assert breach.pwned_count("password") > 0

# password_manager/app/core/breach.py
"""
Breach check against Have I Been Pwned "Pwned Passwords" (range API).

Uses k-anonymity: only the first 5 hex characters of the password's SHA-1
digest ever leave the machine. The password and full hash are never sent or
logged. Responses are padded (``Add-Padding: true``) and cached in memory
per prefix for CACHE_TTL_SECONDS.
"""
import hashlib
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "PyPassManager"
TIMEOUT_SECONDS = 6
CACHE_TTL_SECONDS = 3600
PREFIX_LEN = 5

logger = logging.getLogger(__name__)

_cache: dict[str, tuple[float, dict[str, int]]] = {}
_cache_lock = threading.Lock()


class BreachCheckError(Exception):
    """Raised when the breach lookup fails (network / HTTP / bad response)."""


def sha1_hex(password: str) -> str:
    """Uppercase SHA-1 hex digest of the password.

    SHA-1 is mandated by the HIBP Pwned Passwords protocol; it is used only as
    a lookup key here, not for any security purpose.
    """
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def split_hash(password: str) -> tuple[str, str]:
    """Return (5-char prefix, 35-char suffix) of the password's SHA-1 hash."""
    digest = sha1_hex(password)
    return digest[:PREFIX_LEN], digest[PREFIX_LEN:]


def parse_range_response(body: str) -> dict[str, int]:
    """Parse ``SUFFIX:COUNT`` lines; padding entries (count 0) are dropped."""
    result: dict[str, int] = {}
    for line in body.splitlines():
        suffix, sep, count = line.strip().partition(":")
        if not sep:
            continue
        try:
            n = int(count)
        except ValueError:
            continue
        if n > 0:
            result[suffix.upper()] = n
    return result


def _fetch_range(prefix: str) -> str:
    """Download the range body for a 5-char prefix (the only data sent)."""
    req = urllib.request.Request(
        API_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("Breach range lookup failed for prefix %s: %s", prefix, exc)
        raise BreachCheckError(str(exc)) from exc


def _get_range(prefix: str) -> dict[str, int]:
    """Return suffix->count for prefix, using the TTL cache."""
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(prefix)
        if hit and now - hit[0] < CACHE_TTL_SECONDS:
            return hit[1]
    data = parse_range_response(_fetch_range(prefix))
    with _cache_lock:
        _cache[prefix] = (time.monotonic(), data)
    return data


def clear_cache() -> None:
    """Drop all cached range responses."""
    with _cache_lock:
        _cache.clear()


def pwned_count(password: str) -> int:
    """Number of times the password appears in breaches (0 = not found).

    Raises BreachCheckError on network/HTTP errors.
    """
    prefix, suffix = split_hash(password)
    return _get_range(prefix).get(suffix, 0)


def check_many(
    passwords: dict[int, str],
    progress: Optional[Callable[[int, int], None]] = None,
) -> dict[int, Optional[int]]:
    """Check many passwords, requesting each hash prefix only once.

    Keys are credential ids. A value of None means that lookup failed.
    ``progress(done, total)`` is called after each prefix is processed.
    Safe to call from a worker thread.
    """
    groups: dict[str, list[tuple[int, str]]] = {}
    for cred_id, pw in passwords.items():
        prefix, suffix = split_hash(pw)
        groups.setdefault(prefix, []).append((cred_id, suffix))

    results: dict[int, Optional[int]] = {}
    total = len(groups)
    for done, (prefix, items) in enumerate(groups.items(), start=1):
        try:
            data: Optional[dict[str, int]] = _get_range(prefix)
        except BreachCheckError:
            data = None
        for cred_id, suffix in items:
            results[cred_id] = None if data is None else data.get(suffix, 0)
        if progress is not None:
            progress(done, total)
    return results


def format_count(n: int) -> str:
    """Compact count: 3_200_000 -> '3.2M', 12_345 -> '12K', 7 -> '7'."""
    def _fmt(value: float, unit: str) -> str:
        text = f"{value:.1f}" if value < 10 else f"{value:.0f}"
        if text.endswith(".0"):
            text = text[:-2]
        return text + unit

    units = ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K"))
    for i, (scale, unit) in enumerate(units):
        if n >= scale:
            text = _fmt(n / scale, unit)
            if text == f"1000{unit}" and i > 0:    # 999_999 -> "1M", not "1000K"
                bigger_scale, bigger_unit = units[i - 1]
                return _fmt(n / bigger_scale, bigger_unit)
            return text
    return str(n)

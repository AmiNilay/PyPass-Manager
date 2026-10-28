"""Emergency Access: share encoding and trustee kit helpers.

A random 32-byte emergency secret is split with Shamir's Secret Sharing
(see :mod:`app.core.shamir`); each trustee gets one share as a
human-transcribable string::

    PYPASS-<ID>-<K>of<N>-<XX>-<payload in blocks of 4>-<CHECK>

* ``ID``     6-char base32 id of the emergency setup (older setups are rejected)
* ``K``/``N`` threshold and total number of shares
* ``XX``     two-digit share number (1..N)
* payload    base32 (no padding) of the share bytes, 52 chars for 32 bytes
* ``CHECK``  first 4 hex chars of SHA-256 over the canonical text before it

Parsing ignores case, whitespace and dashes, so ``pypass ab3def 3of5 02 ...``
is accepted too.
"""

import base64
import hashlib
import io
import logging
import re
import secrets
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

SECRET_SIZE = 32
ID_LENGTH = 6
MIN_TRUSTEES = 2
MAX_TRUSTEES = 10

_PREFIX = "PYPASS"
_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_PAYLOAD_CHARS = 52  # base32 length of 32 bytes without padding
_CHECK_CHARS = 4
_HEADER_RE = re.compile(r"^PYPASS([A-Z2-7]{6})(\d{1,2})OF(\d{3,4})$")


class ShareError(ValueError):
    """A share is malformed, mistyped, from another setup, or insufficient."""


@dataclass(frozen=True)
class Share:
    """A decoded emergency share."""

    setup_id: str
    threshold: int
    total: int
    index: int
    payload: bytes

    def __repr__(self) -> str:  # never show the payload
        return f"Share(setup_id={self.setup_id!r}, {self.threshold}of{self.total}, index={self.index})"


def new_setup_id() -> str:
    """Returns a short random base32 id for an emergency setup."""
    return "".join(secrets.choice(_B32_ALPHABET) for _ in range(ID_LENGTH))


def _checksum(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()[:_CHECK_CHARS].upper()


def _group(text: str, size: int = 4) -> str:
    return "-".join(text[i : i + size] for i in range(0, len(text), size))


def encode_share(setup_id: str, threshold: int, total: int, index: int, payload: bytes) -> str:
    """Encodes one share as ``PYPASS-ID-KofN-XX-<payload groups>-CHECK``."""
    if len(payload) != SECRET_SIZE:
        raise ValueError("Unexpected share payload size.")
    b32 = base64.b32encode(payload).decode("ascii").rstrip("=")
    canonical = f"{_PREFIX}{setup_id}{threshold}OF{total}{index:02d}{b32}"
    check = _checksum(canonical)
    return f"{_PREFIX}-{setup_id}-{threshold}of{total}-{index:02d}-{_group(b32)}-{check}"


def parse_share(text: str, label: str = "This share") -> Share:
    """Decodes a share string, tolerant of whitespace, case and missing dashes.

    ``label`` names the share in error messages (e.g. "Share 3").
    Raises ShareError with a user-friendly message.
    """
    canonical = re.sub(r"[\s\-]", "", text or "").upper()
    if not canonical:
        raise ShareError(f"{label} is empty.")
    if not canonical.startswith(_PREFIX):
        raise ShareError(f"{label} is not a PyPass emergency share (it should start with PYPASS).")
    body_len = _PAYLOAD_CHARS + _CHECK_CHARS
    if len(canonical) <= len(_PREFIX) + body_len:
        raise ShareError(f"{label} is too short - part of it may be missing.")
    check = canonical[-_CHECK_CHARS:]
    b32 = canonical[-body_len:-_CHECK_CHARS]
    header = canonical[:-body_len]
    match = _HEADER_RE.match(header)
    if not match or not re.fullmatch(r"[A-Z2-7]+", b32):
        raise ShareError(f"{label} has a typo (its format is not valid).")
    if _checksum(canonical[:-_CHECK_CHARS]) != check:
        raise ShareError(f"{label} has a typo - please check it character by character.")

    setup_id, k_text, tail = match.groups()
    threshold, total, index = int(k_text), int(tail[:-2]), int(tail[-2:])
    if not (2 <= threshold <= total <= 255 and 1 <= index <= total):
        raise ShareError(f"{label} has invalid share numbers.")
    try:
        payload = base64.b32decode(b32 + "====")
    except Exception as e:
        raise ShareError(f"{label} has a typo (payload could not be decoded).") from e
    return Share(setup_id, threshold, total, index, payload)


def share_qr_png(share_text: str) -> Optional[bytes]:
    """Renders the share as a QR code PNG, or returns None if ``qrcode`` isn't installed."""
    try:
        import qrcode  # type: ignore
    except ImportError:
        logger.info("qrcode package not available; QR rendering skipped.")
        return None
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4, box_size=8)
        qr.add_data(share_text)
        qr.make(fit=True)
        img = qr.make_image()  # default PyPNG backend, no Pillow needed
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue()
    except Exception as e:
        logger.error("QR rendering failed: %s", type(e).__name__)
        return None


def printable_kit_text(share_text: str, index: int, total: int, threshold: int, created_at: str) -> str:
    """Plain-text instructions for a trustee, including their share."""
    return (
        "PYPASS MANAGER - EMERGENCY ACCESS SHARE\n"
        "=======================================\n"
        "\n"
        f"Share {index} of {total}            Created: {created_at}\n"
        "\n"
        "What is this?\n"
        "  Someone you know trusts you with one piece of an emergency key for\n"
        "  their PyPass Manager password vault. On its own this piece is useless\n"
        "  and reveals nothing about their passwords.\n"
        "\n"
        "How does it work?\n"
        f"  {total} trusted people each hold one share. Any {threshold} of the {total} shares\n"
        f"  together can unlock the vault. Fewer than {threshold} cannot.\n"
        "\n"
        "How do I use it?\n"
        "  Only when the vault owner asks you to, or in a genuine emergency:\n"
        "  1. On the owner's computer, open PyPass Manager and choose\n"
        "     \"Use emergency kit\" on the login screen.\n"
        f"  2. Enter this share together with at least {threshold - 1} other trustee share(s).\n"
        "     Dashes, spaces and upper/lower case do not matter.\n"
        "  3. Set a new master password when prompted.\n"
        "\n"
        "Keep it private\n"
        "  - Store this page somewhere safe (e.g. with important documents).\n"
        "  - Do not share it, photograph it or send it by email or chat.\n"
        "  - Do not combine shares with other trustees unless an emergency\n"
        "    actually requires it.\n"
        "  - If the owner sets up emergency access again, this share stops working.\n"
        "\n"
        "YOUR SHARE\n"
        "----------\n"
        f"{share_text}\n"
    )

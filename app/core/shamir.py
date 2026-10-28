"""Shamir's Secret Sharing over GF(256).

The secret is split byte by byte. For each byte ``s`` a random polynomial

    f(x) = s + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)

of degree ``k - 1`` is chosen over the finite field GF(2^8) (the AES field,
reduction polynomial x^8 + x^4 + x^3 + x + 1 = 0x11B). Share ``i`` is the
point ``(i, f(i))`` for ``i = 1..n``. Any ``k`` points determine the
polynomial uniquely, so Lagrange interpolation at ``x = 0`` recovers ``s``:

    f(0) = sum_j  y_j * prod_{m != j}  x_m / (x_m - x_j)

(in GF(2^8) addition and subtraction are both XOR). With ``k - 1`` or fewer
points every value of ``s`` is equally likely, so they reveal nothing.

Coefficients come from :mod:`secrets`. Field multiplication uses log/exp
tables; the lookups for zero are avoided arithmetically rather than with a
branch on the operand value.
"""

import secrets
from typing import Dict, List, Sequence, Tuple

MIN_THRESHOLD = 2
MAX_SHARES = 255

# --- GF(256) log/exp tables, generator 3, polynomial 0x11B ---
_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # multiply by generator 3: x*2 ^ x
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x = x2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _mul(a: int, b: int) -> int:
    """Multiplication in GF(256). Zero operands handled with a mask, not a branch."""
    r = _EXP[_LOG[a] + _LOG[b]]
    nonzero = (-(a != 0)) & (-(b != 0)) & 0xFF  # 0xFF if both non-zero else 0
    return r & nonzero


def _inv(a: int) -> int:
    """Multiplicative inverse in GF(256); ``a`` must be non-zero (only used on public x values)."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(256)")
    return _EXP[255 - _LOG[a]]


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner evaluation; coeffs[0] is the constant term."""
    result = 0
    for c in reversed(coeffs):
        result = _mul(result, x) ^ c
    return result


def split_secret(secret: bytes, threshold: int, shares: int) -> List[Tuple[int, bytes]]:
    """Splits ``secret`` into ``shares`` points, any ``threshold`` of which recover it.

    Returns ``[(x, y_bytes), ...]`` with x = 1..shares.
    Raises ValueError on invalid parameters.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise ValueError("Secret must be non-empty bytes.")
    if not isinstance(threshold, int) or not isinstance(shares, int):
        raise ValueError("Threshold and share count must be integers.")
    if threshold < MIN_THRESHOLD or threshold > MAX_SHARES:
        raise ValueError(f"Threshold must be between {MIN_THRESHOLD} and {MAX_SHARES}.")
    if shares < threshold or shares > MAX_SHARES:
        raise ValueError(f"Share count must be between the threshold and {MAX_SHARES}.")

    outputs = [bytearray() for _ in range(shares)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for i in range(shares):
            outputs[i].append(_eval_poly(coeffs, i + 1))
        coeffs[:] = [0] * len(coeffs)
    return [(i + 1, bytes(out)) for i, out in enumerate(outputs)]


def combine_shares(shares: Sequence[Tuple[int, bytes]]) -> bytes:
    """Recovers the secret from shares via Lagrange interpolation at x = 0.

    Supplying fewer than the original threshold returns an unrelated value
    (that cannot be detected here). Raises ValueError on malformed input:
    fewer than 2 shares, duplicate or out-of-range x, mismatched lengths.
    """
    if len(shares) < MIN_THRESHOLD:
        raise ValueError(f"At least {MIN_THRESHOLD} shares are required.")
    seen: Dict[int, bool] = {}
    length = None
    for x, y in shares:
        if not isinstance(x, int) or not 1 <= x <= MAX_SHARES:
            raise ValueError(f"Share index must be between 1 and {MAX_SHARES}.")
        if x in seen:
            raise ValueError(f"Duplicate share index {x}.")
        seen[x] = True
        if length is None:
            length = len(y)
        elif len(y) != length:
            raise ValueError("Shares have different lengths.")
    if not length:
        raise ValueError("Shares are empty.")

    xs = [x for x, _ in shares]
    # Lagrange basis coefficients at 0 depend only on the (public) x values.
    basis = []
    for j, xj in enumerate(xs):
        num, den = 1, 1
        for m, xm in enumerate(xs):
            if m != j:
                num = _mul(num, xm)
                den = _mul(den, xm ^ xj)
        basis.append(_mul(num, _inv(den)))

    out = bytearray(length)
    for (_, y), lj in zip(shares, basis):
        for i in range(length):
            out[i] ^= _mul(y[i], lj)
    return bytes(out)

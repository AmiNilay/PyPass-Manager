import itertools
import os

import pytest

from app.core import shamir


@pytest.mark.parametrize("length", [1, 16, 32, 64])
def test_roundtrip_random_secrets(length):
    for _ in range(10):
        secret = os.urandom(length)
        shares = shamir.split_secret(secret, 3, 5)
        assert [x for x, _ in shares] == [1, 2, 3, 4, 5]
        assert shamir.combine_shares(shares) == secret


def test_all_k_subsets_reconstruct_and_k_minus_1_do_not():
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, 3, 5)
    for subset in itertools.combinations(shares, 3):
        assert shamir.combine_shares(list(subset)) == secret
    for subset in itertools.combinations(shares, 2):
        assert shamir.combine_shares(list(subset)) != secret


def test_order_independent():
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, 4, 6)
    assert shamir.combine_shares(list(reversed(shares[1:5]))) == secret


def test_edge_cases():
    for secret in (b"\x00" * 32, b"\xff" * 32):
        assert shamir.combine_shares(shamir.split_secret(secret, 2, 2)) == secret
    secret = os.urandom(8)
    shares = shamir.split_secret(secret, 255, 255)
    assert shamir.combine_shares(shares) == secret


def test_field_inverse():
    for a in range(1, 256):
        assert shamir._mul(a, shamir._inv(a)) == 1
    assert shamir._mul(0, 7) == 0 and shamir._mul(7, 0) == 0
    assert shamir._mul(0x57, 0x83) == 0xC1  # FIPS-197 example


@pytest.mark.parametrize(
    "secret,k,n",
    [(b"", 2, 3), (b"x", 1, 3), (b"x", 4, 3), (b"x", 2, 256), (b"x", 256, 256)],
)
def test_split_validation(secret, k, n):
    with pytest.raises(ValueError):
        shamir.split_secret(secret, k, n)


def test_combine_validation():
    shares = shamir.split_secret(os.urandom(4), 2, 3)
    with pytest.raises(ValueError):
        shamir.combine_shares(shares[:1])
    with pytest.raises(ValueError):
        shamir.combine_shares([shares[0], shares[0]])
    with pytest.raises(ValueError):
        shamir.combine_shares([shares[0], (2, shares[1][1][:3])])
    with pytest.raises(ValueError):
        shamir.combine_shares([shares[0], (0, shares[1][1])])

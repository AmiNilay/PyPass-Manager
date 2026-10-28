"""Encryption helpers, strength checker and password/passphrase generators."""

import pytest
from cryptography.fernet import InvalidToken

from app.core.encryption import (
    DECRYPTION_ERROR,
    decrypt_data,
    derive_key,
    encrypt_data,
    generate_salt,
    generate_vault_key,
    unwrap_key,
    wrap_key,
)
from app.core.password_utils import check_password_strength
from app.ui import password_generator as pg


# --- encryption ---

def test_encrypt_round_trip():
    key = generate_vault_key()
    token = encrypt_data("héllo wörld", key)
    assert "héllo".encode() not in token
    assert decrypt_data(token, key) == "héllo wörld"


def test_empty_values():
    key = generate_vault_key()
    assert encrypt_data("", key) == b""
    assert decrypt_data(b"", key) == ""


def test_wrong_key_returns_error_marker():
    token = encrypt_data("secret", generate_vault_key())
    assert decrypt_data(token, generate_vault_key()) == DECRYPTION_ERROR


def test_derive_key_deterministic():
    salt = generate_salt()
    assert len(salt) == 16
    assert derive_key("pw", salt) == derive_key(b"pw", salt)
    assert derive_key("pw", salt) != derive_key("pw", generate_salt())


def test_wrap_unwrap():
    vault_key = generate_vault_key()
    kek = derive_key("pw", generate_salt())
    wrapped = wrap_key(vault_key, kek)
    assert isinstance(wrapped, str)
    assert unwrap_key(wrapped, kek) == vault_key
    with pytest.raises(InvalidToken):
        unwrap_key(wrapped, generate_vault_key())


# --- strength checker ---

@pytest.mark.parametrize(
    "password, score, text",
    [
        ("", 0, "Empty"),
        ("abc", 0, "Very Weak"),
        ("abcdefgh", 0, "Very Weak"),
        ("abcdefgH", 1, "Weak"),
        ("abcdefH1", 2, "Moderate"),
        ("abcdefghijH1", 3, "Strong"),
        ("abcdefghiH1!", 4, "Very Strong"),
        ("abcdefghijklmnopqrstuvwxyz", 2, "Moderate"),
    ],
)
def test_check_password_strength(password, score, text):
    got_score, got_text, color = check_password_strength(password)
    assert (got_score, got_text) == (score, text)
    assert color.startswith("#")


# --- generators ---

def test_generate_strong_password():
    for length in (8, 12, 40):
        pw = pg.generate_strong_password(length)
        assert len(pw) == length
        assert any(c.isupper() for c in pw)
        assert any(c.islower() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(c in pg.SYMBOLS for c in pw)


def test_generate_password_clamps_length():
    assert len(pg.generate_password(1)) == pg.MIN_LENGTH
    assert len(pg.generate_password(10_000)) == pg.MAX_LENGTH


def test_generate_password_classes_and_ambiguous():
    pw = pg.generate_password(64, use_upper=False, use_lower=False, use_digits=True,
                              use_symbols=False, avoid_ambiguous=True)
    assert pw.isdigit()
    assert not set(pw) & pg.AMBIGUOUS
    # No classes enabled falls back to lowercase.
    assert pg.generate_password(20, False, False, False, False).islower()


def test_generate_passphrase():
    phrase = pg.generate_passphrase(words=4, capitalize=True, include_number=True, separator="-")
    parts = phrase.split("-")
    assert len(parts) == 4
    assert all(p[0].isupper() for p in parts)
    assert sum(p[-1].isdigit() for p in parts) == 1

    plain = pg.generate_passphrase(words=1, capitalize=False, include_number=False, separator=" ")
    assert len(plain.split(" ")) == pg.MIN_WORDS
    assert all(w in pg.WORDLIST for w in plain.split(" "))

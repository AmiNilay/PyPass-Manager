import itertools

import pytest

from app.core import emergency
from app.core.database import PasswordDatabase
from app.core.emergency import ShareError, parse_share
from app.core.encryption import decrypt_data, encrypt_data

MASTER = "correct horse battery"


@pytest.fixture
def vault(tmp_path):
    db = PasswordDatabase(str(tmp_path / "vault.db"))
    key = db.create_vault(MASTER)
    db.add_credential("example", "alice", encrypt_data("s3cret!", key))
    return db, key


def _flip_char(share: str) -> str:
    pos = 25
    c = share[pos]
    return share[:pos] + ("B" if c != "B" else "C") + share[pos + 1 :]


def test_share_format_roundtrip():
    payload = bytes(range(32))
    text = emergency.encode_share("AB3DEF", 3, 5, 2, payload)
    assert text.startswith("PYPASS-AB3DEF-3of5-02-")
    share = parse_share(text)
    assert (share.setup_id, share.threshold, share.total, share.index, share.payload) == (
        "AB3DEF", 3, 5, 2, payload,
    )
    messy = "  " + text.lower().replace("-", " ", 5).replace("-", "") + "\n"
    assert parse_share(messy) == share
    assert "payload" not in repr(share)


def test_share_format_ten_trustees():
    text = emergency.encode_share("AAAAAA", 2, 10, 10, bytes(32))
    s = parse_share(text)
    assert (s.threshold, s.total, s.index) == (2, 10, 10)


def test_typo_detected():
    text = emergency.encode_share("AB3DEF", 3, 5, 2, bytes(range(32)))
    with pytest.raises(ShareError, match="Share 3 has a typo"):
        parse_share(_flip_char(text), "Share 3")
    with pytest.raises(ShareError):
        parse_share(text[:-10])
    with pytest.raises(ShareError):
        parse_share("hello")


def test_enable_and_recover_with_any_k(vault):
    db, key = vault
    shares = db.enable_emergency_access(key, 3, 5)
    assert len(shares) == 5
    status = db.emergency_access_status()
    assert status["threshold"] == 3 and status["shares"] == 5 and status["id"] and status["created_at"]
    for subset in itertools.combinations(shares, 3):
        assert db.recover_with_shares(list(subset)) == key


def test_recover_then_change_master_password(vault):
    db, key = vault
    shares = db.enable_emergency_access(key, 2, 3)
    recovered = db.recover_with_shares([shares[2], shares[0]])
    db.change_master_password(recovered, "brand new password")
    unlocked = db.unlock_vault("brand new password")
    cred = db.get_all_credentials()[0]
    assert decrypt_data(cred["encrypted_password"], unlocked) == "s3cret!"


def test_fewer_than_k_and_duplicates(vault):
    db, key = vault
    shares = db.enable_emergency_access(key, 3, 4)
    with pytest.raises(ShareError, match="3 different shares"):
        db.recover_with_shares(shares[:2])
    with pytest.raises(ShareError):
        db.recover_with_shares([shares[0], shares[0], shares[1]])


def test_old_shares_rejected_after_reenable(vault):
    db, key = vault
    old = db.enable_emergency_access(key, 2, 3)
    new = db.enable_emergency_access(key, 2, 3)
    with pytest.raises(ShareError, match="older emergency setup"):
        db.recover_with_shares(old[:2])
    with pytest.raises(ShareError, match="different setups"):
        db.recover_with_shares([old[0], new[1]])
    assert db.recover_with_shares(new[:2]) == key


def test_typo_in_recovery(vault):
    db, key = vault
    shares = db.enable_emergency_access(key, 2, 3)
    with pytest.raises(ShareError, match="Share 2 has a typo"):
        db.recover_with_shares([shares[0], _flip_char(shares[1])])


def test_bad_combination_counts_failure_and_lockout(vault, monkeypatch):
    db, key = vault
    shares = db.enable_emergency_access(key, 2, 3)
    monkeypatch.setattr("app.core.shamir.combine_shares", lambda pts: bytes(32))
    for _ in range(db.FREE_ATTEMPTS):
        with pytest.raises(ShareError, match="could not unlock"):
            db.recover_with_shares(shares[:2])
    assert db.lockout_remaining() > 0
    with pytest.raises(ShareError, match="Too many failed attempts"):
        db.recover_with_shares(shares[:2])


def test_disable_and_wipe(vault):
    db, key = vault
    shares = db.enable_emergency_access(key, 2, 2)
    db.disable_emergency_access()
    assert db.emergency_access_status() is None
    with pytest.raises(ShareError, match="not set up"):
        db.recover_with_shares(shares)

    db.enable_emergency_access(key, 2, 2)
    db.wipe_vault()
    assert db.emergency_access_status() is None
    for k in ("vault_key_emergency", "emergency_salt", "emergency_id", "emergency_threshold"):
        assert db.get_setting(k) is None


def test_validation(vault):
    db, key = vault
    for k, n in [(1, 3), (4, 3), (2, 1), (2, 11)]:
        with pytest.raises(ValueError):
            db.enable_emergency_access(key, k, n)


def test_kit_and_qr():
    text = emergency.encode_share("AB3DEF", 3, 5, 1, bytes(32))
    kit = emergency.printable_kit_text(text, 1, 5, 3, "2026-01-01 10:00:00")
    assert text in kit and "Any 3 of the 5" in kit
    png = emergency.share_qr_png(text)
    assert png is None or png.startswith(b"\x89PNG")

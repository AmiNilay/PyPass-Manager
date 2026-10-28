"""Vault key lifecycle: create, unlock, change, recover, legacy migration, lockout, wipe."""

import base64

import pytest

from app.core.database import PasswordDatabase
from app.core.encryption import decrypt_data, derive_key, encrypt_data, generate_salt
from tests.conftest import QUESTIONS

MASTER = "masterpass1"


@pytest.fixture
def vault(db):
    key = db.create_vault(MASTER)
    db.set_security_questions(QUESTIONS, key)
    db.add_credential("gmail", "me", encrypt_data("Secret#123", key))
    return db, key


def _first_password(db, key):
    return decrypt_data(db.get_all_credentials()[0]["encrypted_password"], key)


def test_create_and_unlock(vault):
    db, key = vault
    assert db.is_master_password_set()
    assert db.are_security_questions_set()
    assert db.has_recovery_key()
    assert db.unlock_vault(MASTER) == key
    assert db.unlock_vault("wrong") is None


def test_create_vault_rejects_short_password(db):
    with pytest.raises(ValueError):
        db.create_vault("short")


def test_change_master_password_keeps_data(vault):
    db, key = vault
    db.change_master_password(key, "newmaster22")
    assert db.unlock_vault(MASTER) is None
    assert _first_password(db, db.unlock_vault("newmaster22")) == "Secret#123"


def test_recovery_is_case_and_space_insensitive(vault):
    db, key = vault
    recovered = db.recover_vault_key(["  answer 0", "ANSWER 1", "Answer   2"])
    assert recovered == key
    assert db.recover_vault_key(["x", "y", "z"]) is None
    db.change_master_password(recovered, "recovered33")
    assert _first_password(db, db.unlock_vault("recovered33")) == "Secret#123"
    assert len(db.get_security_questions()) == 3


def test_legacy_vault_migrates(db):
    master_salt = generate_salt()
    enc_salt = generate_salt()
    db.set_setting("master_salt", base64.b64encode(master_salt).decode())
    db.set_setting("master_hash", db._hash_password("oldmaster1", master_salt))
    db.set_setting("encryption_salt", base64.b64encode(enc_salt).decode())
    db.add_credential("old", "me", encrypt_data("OldPass!1", derive_key("oldmaster1", enc_salt)))

    key = db.unlock_vault("oldmaster1")
    assert _first_password(db, key) == "OldPass!1"
    assert db.get_setting("vault_key_master")
    assert not db.has_recovery_key()

    db.change_master_password(key, "changed123")
    assert _first_password(db, db.unlock_vault("changed123")) == "OldPass!1"


def test_lockout_persists_across_instances(vault):
    db, _ = vault
    for _ in range(PasswordDatabase.FREE_ATTEMPTS):
        db.verify_master_password("bad")
    assert db.lockout_remaining() > 0
    # Correct password refused while locked, even from a new instance.
    assert PasswordDatabase(db.db_path).unlock_vault(MASTER) is None

    db.set_setting("lockout_until", "0")
    assert db.unlock_vault(MASTER) is not None
    assert db.get_setting("failed_attempts") is None


def test_wipe(vault):
    db, _ = vault
    db.wipe_vault()
    assert not db.get_all_credentials()
    assert not db.is_master_password_set()
    assert not db.get_security_questions()


def test_clear_master_password_settings(vault):
    db, _ = vault
    db.clear_master_password_settings()
    assert not db.is_master_password_set()
    assert db.get_setting("vault_key_master") is None

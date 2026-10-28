"""Schema migrations, credential CRUD and security-answer checks."""

import base64
import sqlite3

import pytest

from app.core.database import PasswordDatabase
from app.core.encryption import generate_salt

OLD_SCHEMA = (
    "CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL, "
    "username TEXT NOT NULL, encrypted_password BLOB NOT NULL, notes TEXT, "
    "is_favorite INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
    "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
)
OLD_TRIGGER = (
    "CREATE TRIGGER update_credential_timestamp AFTER UPDATE ON credentials FOR EACH ROW "
    "BEGIN UPDATE credentials SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id; END;"
)


@pytest.fixture
def old_db(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.execute(OLD_SCHEMA)
    conn.execute(OLD_TRIGGER)
    conn.execute(
        "INSERT INTO credentials (service, username, encrypted_password, created_at, updated_at) "
        "VALUES ('s', 'u', x'01', '2020-01-01 00:00:00', '2021-01-01 00:00:00')"
    )
    conn.commit()
    conn.close()
    return PasswordDatabase(path)


def test_migration_backfills_and_drops_trigger(old_db):
    row = old_db.get_credential_by_id(1)
    assert row["password_changed_at"] == "2021-01-01 00:00:00"
    assert row["updated_at"] == "2021-01-01 00:00:00"
    assert row["url"] == ""
    conn = sqlite3.connect(old_db.db_path)
    try:
        assert not conn.execute("SELECT 1 FROM sqlite_master WHERE type='trigger'").fetchall()
    finally:
        conn.close()


def test_toggle_favorite_keeps_timestamps(old_db):
    before = old_db.get_credential_by_id(1)
    old_db.toggle_favorite_status(1)
    after = old_db.get_credential_by_id(1)
    assert after["is_favorite"] == 1
    assert after["updated_at"] == before["updated_at"]
    assert after["password_changed_at"] == before["password_changed_at"]
    old_db.toggle_favorite_status(1)
    assert old_db.get_credential_by_id(1)["is_favorite"] == 0


def test_update_without_password_keeps_password(old_db):
    before = old_db.get_credential_by_id(1)
    old_db.update_credential(1, "s2", "u", None, "note")
    after = old_db.get_credential_by_id(1)
    assert after["encrypted_password"] == b"\x01"
    assert after["service"] == "s2"
    assert after["password_changed_at"] == before["password_changed_at"]
    assert after["updated_at"] != before["updated_at"]


def test_update_with_password_bumps_age(old_db):
    before = old_db.get_credential_by_id(1)
    old_db.update_credential(1, "s2", "u", b"\x02", "note")
    after = old_db.get_credential_by_id(1)
    assert after["encrypted_password"] == b"\x02"
    assert after["password_changed_at"] != before["password_changed_at"]


def test_update_validation(db):
    db.add_credential("s", "u", b"\x01")
    with pytest.raises(ValueError):
        db.update_credential(1, "", "u", None, "")
    with pytest.raises(ValueError):
        db.update_credential(1, "s", "u", b"", "")


def test_add_validation(db):
    with pytest.raises(ValueError):
        db.add_credential("s", "", b"\x01")


def test_add_sets_password_changed_at(old_db):
    old_db.add_credential("n", "u", b"\x03")
    new = [r for r in old_db.get_all_credentials(sort_by="password_changed_at") if r["service"] == "n"][0]
    assert new["password_changed_at"]
    assert "created_at" in old_db.search_credentials("n")[0]


def test_sort_and_search(db):
    for service, user, url in [("beta", "x", ""), ("Alpha", "y", "example.com"), ("gamma", "z", "")]:
        db.add_credential(service, user, b"\x01", url=url)
    assert [r["service"] for r in db.get_all_credentials()] == ["Alpha", "beta", "gamma"]
    assert [r["service"] for r in db.get_all_credentials("service", "desc")] == ["gamma", "beta", "Alpha"]
    # Unknown sort column / order fall back to service ASC.
    assert [r["service"] for r in db.get_all_credentials("bogus; DROP", "sideways")] == ["Alpha", "beta", "gamma"]
    assert [r["service"] for r in db.search_credentials("example")] == ["Alpha"]
    assert [r["service"] for r in db.search_credentials("z")] == ["gamma"]
    assert len(db.search_credentials("")) == 3


def test_delete(db):
    db.add_credential("s", "u", b"\x01")
    db.delete_credential(1)
    assert db.get_credential_by_id(1) is None


def test_security_answer_case_insensitive(db):
    db.set_security_question("Q1?", "  Fluffy   Cat ")
    qid = db.get_security_questions()[0]["id"]
    assert db.verify_security_answer(qid, "fluffy cat")
    assert db.verify_security_answer(qid, "FLUFFY  CAT")


def test_security_answer_legacy_raw_hash(db):
    salt = generate_salt()
    with db._get_connection() as conn:
        conn.execute(
            "INSERT INTO security_questions (question_text, hashed_answer, salt) VALUES (?, ?, ?)",
            ("Q2?", db._hash_password("Rex Dog", salt), base64.b64encode(salt).decode()),
        )
    qid = db.get_security_questions()[0]["id"]
    assert db.verify_security_answer(qid, "Rex Dog")


def test_wrong_answer_records_single_failure(db):
    db.set_security_question("Q?", "right")
    qid = db.get_security_questions()[0]["id"]
    assert not db.verify_security_answer(qid, "Wrong Thing")
    assert db.get_setting("failed_attempts") == "1"


def test_normalize_answer():
    assert PasswordDatabase._normalize_answer("  Foo   BAR ") == "foo bar"


def test_settings_roundtrip(db):
    assert db.get_setting("missing") is None
    db.set_setting("k", "v")
    assert db.get_setting("k") == "v"

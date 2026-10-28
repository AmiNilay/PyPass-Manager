"""SQLite storage for the password manager.

The vault is protected by a random *vault key* (a Fernet key) that encrypts
every credential. The vault key itself is stored only in wrapped (encrypted)
form: once under a key derived from the master password and, optionally, once
under a key derived from the security-question answers (for recovery).
"""

import base64
import hmac
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.core import emergency, shamir
from app.core.encryption import (
    derive_key,
    generate_salt,
    generate_vault_key,
    unwrap_key,
    wrap_key,
)
from config import settings

# Logging is configured by main.py.
logger = logging.getLogger(__name__)

CREDENTIAL_COLUMNS = (
    "id, service, username, encrypted_password, notes, is_favorite, url, "
    "created_at, updated_at, password_changed_at"
)

# Whitelist of sortable columns (user value -> SQL column), prevents SQL injection.
SORT_COLUMNS = {
    "service": "service",
    "username": "username",
    "is_favorite": "is_favorite",
    "created_at": "created_at",
    "updated_at": "updated_at",
    "password_changed_at": "password_changed_at",
}

_SORT_ORDERS = {"ASC": "ASC", "DESC": "DESC"}
_TEXT_SORT_COLUMNS = ("service", "username")

# PBKDF2 iterations for the stored master-password / security-answer hashes.
_HASH_ITERATIONS = 600_000

# Settings keys that hold master-password key material.
_MASTER_KEYS = ("master_hash", "master_salt", "encryption_salt", "kek_salt", "vault_key_master")

# Settings keys that make up the emergency-access setup.
_EMERGENCY_KEYS = (
    "vault_key_emergency",
    "emergency_salt",
    "emergency_threshold",
    "emergency_shares",
    "emergency_created_at",
    "emergency_id",
)


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def _order_by_clause(sort_by: str, sort_order: str) -> str:
    """Builds a safe ORDER BY clause from whitelisted column/order values."""
    column = SORT_COLUMNS.get(sort_by, "service")
    order = _SORT_ORDERS.get(sort_order.upper(), "ASC")
    collate = "COLLATE NOCASE" if column in _TEXT_SORT_COLUMNS else ""
    return f"ORDER BY {column} {collate} {order}"


class PasswordDatabase:
    """Handles all database operations for the password manager."""

    # --- Brute-force protection ---
    FREE_ATTEMPTS = 5
    MAX_LOCKOUT_SECONDS = 15 * 60

    def __init__(self, db_path: str = settings.DATABASE_PATH) -> None:
        self.db_path = db_path
        logger.debug("PasswordDatabase initializing with path: %s", self.db_path)
        try:
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            self._create_tables()
            logger.info("Database initialized at %s", self.db_path)
        except Exception as e:
            logger.exception("Failed to initialize database structure at %s", self.db_path)
            raise RuntimeError(f"Failed to initialize database structure: {e}") from e

    # ------------------------------------------------------------------
    # Connection and schema
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        except sqlite3.Error as e:
            logger.error("Database connection error: %s", e)
            raise

    def _create_tables(self) -> None:
        logger.debug("Checking/creating database tables.")
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT NOT NULL,
                        username TEXT NOT NULL,
                        encrypted_password BLOB NOT NULL,
                        notes TEXT,
                        is_favorite INTEGER DEFAULT 0,
                        url TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )

                # updated_at is set explicitly in update_credential (favorite toggles
                # must not bump it). Dropped before migrations so the backfill below
                # doesn't fire it.
                cursor.execute("DROP TRIGGER IF EXISTS update_credential_timestamp")

                # Migrations for databases created by older versions.
                cursor.execute("PRAGMA table_info(credentials)")
                columns = [row[1] for row in cursor.fetchall()]
                if "url" not in columns:
                    cursor.execute("ALTER TABLE credentials ADD COLUMN url TEXT DEFAULT ''")
                if "password_changed_at" not in columns:
                    # ALTER TABLE can't use a CURRENT_TIMESTAMP default, so add plain and backfill.
                    cursor.execute("ALTER TABLE credentials ADD COLUMN password_changed_at TIMESTAMP")
                    cursor.execute(
                        "UPDATE credentials SET password_changed_at = "
                        "COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)"
                    )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_questions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        question_text TEXT NOT NULL UNIQUE,
                        hashed_answer TEXT NOT NULL,
                        salt TEXT NOT NULL
                    )
                    """
                )
                logger.info("DB tables checked/created/migrated.")
        except sqlite3.Error as e:
            logger.error("Error creating DB tables: %s", e)
            raise

    # ------------------------------------------------------------------
    # Generic settings
    # ------------------------------------------------------------------

    def set_setting(self, key: str, value: str) -> None:
        """Inserts or replaces a key/value pair in the settings table."""
        logger.debug("Setting database key='%s'", key)
        try:
            with self._get_connection() as conn:
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
            logger.debug("Setting '%s' updated.", key)
        except sqlite3.Error as e:
            logger.error("Error setting setting '%s': %s", key, e)
            raise

    def get_setting(self, key: str) -> Optional[str]:
        """Returns the stored value for ``key``, or None if missing or on error."""
        try:
            with self._get_connection() as conn:
                row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None
        except sqlite3.Error as e:
            logger.error("Error getting setting '%s': %s", key, e)
            return None

    # ------------------------------------------------------------------
    # Master password and vault key
    # ------------------------------------------------------------------

    def is_master_password_set(self) -> bool:
        """True if a master password hash is stored."""
        return self.get_setting("master_hash") is not None

    def _hash_password(self, password: str, salt: bytes) -> str:
        """PBKDF2-SHA256 hash of ``password``, base64-encoded."""
        try:
            hasher = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=_HASH_ITERATIONS,
                backend=default_backend(),
            )
            return _b64encode(hasher.derive(password.encode("utf-8")))
        except Exception:
            logger.exception("Error in _hash_password")
            raise

    def _validate_master_password(self, master_password: str) -> None:
        if not master_password or len(master_password) < settings.MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(f"Master pwd >= {settings.MIN_MASTER_PASSWORD_LENGTH} chars.")

    def _store_master_password(self, master_password: str, vault_key: bytes) -> None:
        """Stores the master hash and the vault key wrapped under a master-derived key."""
        master_salt = generate_salt()
        master_hash = self._hash_password(master_password, master_salt)
        kek_salt = generate_salt()
        wrapped = wrap_key(vault_key, derive_key(master_password, kek_salt))
        with self._get_connection() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                [
                    ("master_salt", _b64encode(master_salt)),
                    ("master_hash", master_hash),
                    ("kek_salt", _b64encode(kek_salt)),
                    ("vault_key_master", wrapped),
                ],
            )

    def create_vault(self, master_password: str) -> bytes:
        """First-run setup. Returns the new vault key.

        Raises ValueError if the password is too short or the settings can't be saved.
        """
        self._validate_master_password(master_password)
        vault_key = generate_vault_key()
        try:
            self._store_master_password(master_password, vault_key)
            logger.info("Vault created.")
            return vault_key
        except Exception as e:
            logger.error("Failed to store master password settings: %s", e)
            self.clear_master_password_settings()
            self.clear_security_questions()
            raise ValueError("Failed save master pwd settings.") from e

    def unlock_vault(self, master_password: str) -> Optional[bytes]:
        """Returns the vault key, or None if the password is wrong or attempts are locked out."""
        if not self.verify_master_password(master_password):
            return None
        wrapped = self.get_setting("vault_key_master")
        kek_salt_b64 = self.get_setting("kek_salt")
        if wrapped and kek_salt_b64:
            return unwrap_key(wrapped, derive_key(master_password, base64.b64decode(kek_salt_b64)))

        # Legacy vault: credentials were encrypted directly with a master-derived key.
        # Keep that key as the vault key and wrap it, so it survives master password changes.
        legacy_salt = self.get_encryption_salt()
        if not legacy_salt:
            raise ValueError("Encryption salt missing.")
        vault_key = derive_key(master_password, legacy_salt)
        self._store_master_password(master_password, vault_key)
        logger.info("Migrated legacy vault to wrapped vault key.")
        return vault_key

    def change_master_password(self, vault_key: bytes, new_master_password: str) -> None:
        """Re-wraps the vault key under a new master password. Credentials are untouched."""
        self._validate_master_password(new_master_password)
        self._store_master_password(new_master_password, vault_key)
        logger.info("Master password changed.")

    def has_recovery_key(self) -> bool:
        """True if the vault key is also wrapped under the security-question answers."""
        return self.get_setting("vault_key_recovery") is not None

    def wipe_vault(self) -> None:
        """Destroys all credentials, security questions and keys. Used when recovery is impossible."""
        logger.warning("Wiping vault.")
        with self._get_connection() as conn:
            conn.execute("DELETE FROM credentials")
            conn.execute("DELETE FROM security_questions")
            conn.execute("DELETE FROM settings")

    def lockout_remaining(self) -> int:
        """Seconds until another password / answer attempt is allowed (0 = allowed now)."""
        until = self.get_setting("lockout_until")
        return max(0, int(float(until) - time.time())) if until else 0

    def _record_failed_attempt(self) -> None:
        failures = int(self.get_setting("failed_attempts") or 0) + 1
        self.set_setting("failed_attempts", str(failures))
        if failures >= self.FREE_ATTEMPTS:
            delay = min(30 * 2 ** (failures - self.FREE_ATTEMPTS), self.MAX_LOCKOUT_SECONDS)
            self.set_setting("lockout_until", str(time.time() + delay))
            logger.warning("%d failed attempts; locked for %ds.", failures, delay)

    def _clear_failed_attempts(self) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM settings WHERE key IN ('failed_attempts', 'lockout_until')")

    def verify_master_password(self, master_password: str) -> bool:
        """Checks the master password, honouring and updating the lockout state."""
        stored_salt_b64 = self.get_setting("master_salt")
        stored_hash_b64 = self.get_setting("master_hash")
        if not stored_salt_b64 or not stored_hash_b64:
            logger.warning("Verification attempt, but settings missing.")
            return False
        if self.lockout_remaining() > 0:
            logger.warning("Verification refused: locked out.")
            return False
        try:
            provided_hash_b64 = self._hash_password(master_password, _b64decode(stored_salt_b64))
            ok = hmac.compare_digest(provided_hash_b64.encode("utf-8"), stored_hash_b64.encode("utf-8"))
        except Exception:
            logger.exception("Error during master password verification")
            return False
        if ok:
            self._clear_failed_attempts()
        else:
            self._record_failed_attempt()
        return ok

    def get_encryption_salt(self) -> Optional[bytes]:
        """Returns the legacy (pre vault-key) encryption salt, or None."""
        salt_b64 = self.get_setting("encryption_salt")
        if not salt_b64:
            logger.warning("Encryption salt not found in settings.")
            return None
        try:
            return _b64decode(salt_b64)
        except Exception as e:
            logger.error("Error decoding encryption salt: %s", e)
            return None

    def clear_master_password_settings(self) -> None:
        """Deletes the master hash, salts and master-wrapped vault key."""
        logger.warning("Clearing master password settings.")
        placeholders = ", ".join("?" for _ in _MASTER_KEYS)
        try:
            with self._get_connection() as conn:
                conn.execute(f"DELETE FROM settings WHERE key IN ({placeholders})", _MASTER_KEYS)
            logger.info("Master password settings cleared.")
        except sqlite3.Error as e:
            logger.error("Error clearing master password settings: %s", e)

    # ------------------------------------------------------------------
    # Security questions and recovery
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_answer(answer: str) -> str:
        """Lower-cases and collapses whitespace so answers match case/space-insensitively."""
        return " ".join(answer.lower().split())

    def _recovery_wrapping_key(self, answers: List[str], salt: bytes) -> bytes:
        return derive_key("\x1f".join(self._normalize_answer(a) for a in answers), salt)

    def set_security_question(self, question_text: str, answer: str) -> None:
        """Stores (or replaces) one question with a salted hash of its normalized answer."""
        if not question_text or not answer:
            raise ValueError("Question and answer cannot be empty.")
        salt = generate_salt()
        hashed_answer = self._hash_password(self._normalize_answer(answer), salt)
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO security_questions (question_text, hashed_answer, salt) "
                    "VALUES (?, ?, ?)",
                    (question_text, hashed_answer, _b64encode(salt)),
                )
            logger.info("Security question set: %s...", question_text[:30])
        except sqlite3.Error as e:
            logger.error("Error setting security question '%s...': %s", question_text[:30], e)
            raise

    def set_security_questions(self, items: List[Dict[str, str]], vault_key: bytes) -> None:
        """Replaces all security questions and wraps the vault key under their answers.

        ``items`` is a list of ``{"question_text": ..., "answer": ...}`` dicts.
        """
        self.clear_security_questions()
        for item in items:
            self.set_security_question(item["question_text"], item["answer"])

        # Wrap in stored-id order, which is the order the recovery dialog asks them in.
        answer_by_text = {item["question_text"]: item["answer"] for item in items}
        answers = [answer_by_text[q["question_text"]] for q in self.get_security_questions()]
        salt = generate_salt()
        self.set_setting("recovery_salt", _b64encode(salt))
        self.set_setting("vault_key_recovery", wrap_key(vault_key, self._recovery_wrapping_key(answers, salt)))
        logger.info("Security questions and recovery key saved.")

    def recover_vault_key(self, answers: List[str]) -> Optional[bytes]:
        """Answers in get_security_questions() order. Returns the vault key, or None if unavailable."""
        wrapped = self.get_setting("vault_key_recovery")
        salt_b64 = self.get_setting("recovery_salt")
        if not wrapped or not salt_b64:
            return None
        try:
            return unwrap_key(wrapped, self._recovery_wrapping_key(answers, base64.b64decode(salt_b64)))
        except Exception:
            logger.error("Recovery key could not be unwrapped.")
            return None

    def get_security_questions(self) -> List[Dict[str, Any]]:
        """Returns ``[{"id", "question_text"}, ...]`` ordered by id (empty on error)."""
        try:
            with self._get_connection() as conn:
                rows = conn.execute("SELECT id, question_text FROM security_questions ORDER BY id").fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error retrieving security questions: %s", e)
            return []

    def verify_security_answer(self, question_id: int, provided_answer: str) -> bool:
        """Checks one answer; a wrong answer counts towards the lockout."""
        if self.lockout_remaining() > 0:
            logger.warning("Answer refused: locked out.")
            return False
        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT hashed_answer, salt FROM security_questions WHERE id = ?", (question_id,)
                ).fetchone()
            if not row:
                logger.warning("No security question for ID: %s", question_id)
                return False
            stored = row["hashed_answer"].encode("utf-8")
            salt_bytes = _b64decode(row["salt"])
            # Normalized first; raw fallback covers hashes stored before normalization was added.
            candidates = [self._normalize_answer(provided_answer)]
            if provided_answer != candidates[0]:
                candidates.append(provided_answer)
            ok = any(
                hmac.compare_digest(self._hash_password(c, salt_bytes).encode("utf-8"), stored)
                for c in candidates
            )
        except Exception:
            logger.exception("Error verifying security answer ID %s", question_id)
            return False
        if not ok:
            self._record_failed_attempt()
        return ok

    def are_security_questions_set(self) -> bool:
        """True if at least NUMBER_OF_SECURITY_QUESTIONS_TO_SET questions are stored."""
        return len(self.get_security_questions()) >= settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET

    def clear_security_questions(self) -> None:
        """Deletes all security questions and the recovery-wrapped vault key."""
        logger.warning("Clearing ALL security questions from database.")
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM security_questions")
                conn.execute("DELETE FROM settings WHERE key IN ('vault_key_recovery', 'recovery_salt')")
            logger.info("All security questions cleared.")
        except sqlite3.Error as e:
            logger.error("Error clearing security questions: %s", e)

    # ------------------------------------------------------------------
    # Emergency access (Shamir shares held by trustees)
    # ------------------------------------------------------------------

    @staticmethod
    def _emergency_wrapping_key(secret: bytes, setup_id: str, salt: bytes) -> bytes:
        return derive_key(secret + setup_id.encode("ascii"), salt)

    def enable_emergency_access(self, vault_key: bytes, threshold: int, shares: int) -> List[str]:
        """Creates a new emergency setup and returns the encoded trustee shares.

        Any previous setup is replaced, so its shares stop working. The emergency
        secret and the shares themselves are never stored.
        """
        if not emergency.MIN_TRUSTEES <= shares <= emergency.MAX_TRUSTEES:
            raise ValueError(
                f"Number of trustees must be between {emergency.MIN_TRUSTEES} and {emergency.MAX_TRUSTEES}."
            )
        if not 2 <= threshold <= shares:
            raise ValueError("Threshold must be between 2 and the number of trustees.")

        secret = os.urandom(emergency.SECRET_SIZE)
        setup_id = emergency.new_setup_id()
        salt = generate_salt()
        wrapped = wrap_key(vault_key, self._emergency_wrapping_key(secret, setup_id, salt))
        points = shamir.split_secret(secret, threshold, shares)
        del secret
        created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                [
                    ("vault_key_emergency", wrapped),
                    ("emergency_salt", _b64encode(salt)),
                    ("emergency_threshold", str(threshold)),
                    ("emergency_shares", str(shares)),
                    ("emergency_created_at", created_at),
                    ("emergency_id", setup_id),
                ],
            )
        logger.info("Emergency access enabled (%d of %d).", threshold, shares)
        return [emergency.encode_share(setup_id, threshold, shares, x, y) for x, y in points]

    def emergency_access_status(self) -> Optional[Dict[str, Any]]:
        """Returns ``{threshold, shares, created_at, id}`` or None if not enabled."""
        if not self.get_setting("vault_key_emergency"):
            return None
        return {
            "threshold": int(self.get_setting("emergency_threshold") or 0),
            "shares": int(self.get_setting("emergency_shares") or 0),
            "created_at": self.get_setting("emergency_created_at") or "",
            "id": self.get_setting("emergency_id") or "",
        }

    def disable_emergency_access(self) -> None:
        """Removes the emergency setup; all issued shares stop working."""
        placeholders = ", ".join("?" for _ in _EMERGENCY_KEYS)
        with self._get_connection() as conn:
            conn.execute(f"DELETE FROM settings WHERE key IN ({placeholders})", _EMERGENCY_KEYS)
        logger.info("Emergency access disabled.")

    def recover_with_shares(self, share_texts: List[str]) -> bytes:
        """Combines trustee shares and returns the vault key.

        Raises ShareError on malformed, insufficient or mismatched shares, when
        locked out, or when the combined secret does not unlock the vault (which
        counts as a failed attempt).
        """
        remaining = self.lockout_remaining()
        if remaining > 0:
            raise emergency.ShareError(f"Too many failed attempts. Try again in {remaining} seconds.")
        status = self.emergency_access_status()
        if status is None:
            raise emergency.ShareError("Emergency access is not set up for this vault.")

        texts = [t for t in share_texts if t and t.strip()]
        parsed = [emergency.parse_share(t, f"Share {i}") for i, t in enumerate(texts, start=1)]
        if not parsed:
            raise emergency.ShareError("No shares were entered.")
        if len({s.setup_id for s in parsed}) > 1:
            raise emergency.ShareError("Shares are from different setups.")
        for i, s in enumerate(parsed, start=1):
            if (s.setup_id, s.threshold, s.total) != (status["id"], status["threshold"], status["shares"]):
                raise emergency.ShareError(f"Share {i} belongs to an older emergency setup.")
        unique = {}
        for s in parsed:
            unique.setdefault(s.index, s)
        threshold = status["threshold"]
        if len(unique) < threshold:
            raise emergency.ShareError(
                f"{threshold} different shares are needed; only {len(unique)} entered."
            )

        try:
            points = [(s.index, s.payload) for s in list(unique.values())[:threshold]]
            secret = shamir.combine_shares(points)
            salt = _b64decode(self.get_setting("emergency_salt") or "")
            wrapped = self.get_setting("vault_key_emergency") or ""
            vault_key = unwrap_key(wrapped, self._emergency_wrapping_key(secret, status["id"], salt))
        except Exception:
            logger.warning("Emergency recovery failed: shares did not unlock the vault.")
            self._record_failed_attempt()
            raise emergency.ShareError(
                "These shares could not unlock the vault. Check them for typos."
            ) from None
        self._clear_failed_attempts()
        logger.info("Vault key recovered with emergency shares.")
        return vault_key

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------

    def add_credential(
        self,
        service: str,
        username: str,
        encrypted_password: bytes,
        notes: str = "",
        url: str = "",
    ) -> None:
        """Inserts a new credential. Raises ValueError if a required field is empty."""
        if not service or not username or not encrypted_password:
            logger.error("Add credential validation failed.")
            raise ValueError("Service, username, password cannot be empty.")
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO credentials "
                    "(service, username, encrypted_password, notes, url, password_changed_at) "
                    "VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (service, username, encrypted_password, notes or "", url or ""),
                )
            logger.info("Credential added with ID %s.", cursor.lastrowid)
        except sqlite3.Error as e:
            logger.error("DB error adding credential: %s", e)
            raise

    def get_all_credentials(self, sort_by: str = "service", sort_order: str = "ASC") -> List[Dict]:
        """Returns all credentials sorted by a whitelisted column (empty list on error)."""
        query = f"SELECT {CREDENTIAL_COLUMNS} FROM credentials {_order_by_clause(sort_by, sort_order)}"
        try:
            with self._get_connection() as conn:
                return [dict(row) for row in conn.execute(query).fetchall()]
        except sqlite3.Error as e:
            logger.error("Error retrieving all credentials: %s", e)
            return []

    def get_credential_by_id(self, credential_id: int) -> Optional[Dict]:
        """Returns one credential as a dict, or None."""
        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    f"SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE id = ?", (credential_id,)
                ).fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error("Error retrieving credential ID %s: %s", credential_id, e)
            return None

    def update_credential(
        self,
        credential_id: int,
        service: str,
        username: str,
        encrypted_password: Optional[bytes],
        notes: str,
        url: str = "",
    ) -> None:
        """Updates a credential. encrypted_password=None keeps the stored password and its password_changed_at."""
        if not service or not username:
            raise ValueError("Service and username cannot be empty.")
        if encrypted_password is not None and not encrypted_password:
            raise ValueError("Password cannot be empty.")

        fields = "service = ?, username = ?, notes = ?, url = ?, updated_at = CURRENT_TIMESTAMP"
        params: List[Any] = [service, username, notes or "", url or ""]
        if encrypted_password is not None:
            fields += ", encrypted_password = ?, password_changed_at = CURRENT_TIMESTAMP"
            params.append(encrypted_password)
        try:
            with self._get_connection() as conn:
                conn.execute(f"UPDATE credentials SET {fields} WHERE id = ?", (*params, credential_id))
            logger.info("Credential updated ID: %s", credential_id)
        except sqlite3.Error as e:
            logger.error("Error updating credential ID %s: %s", credential_id, e)
            raise

    def delete_credential(self, credential_id: int) -> None:
        """Deletes a credential by id."""
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
            logger.info("Credential deleted ID: %s", credential_id)
        except sqlite3.Error as e:
            logger.error("Error deleting credential ID %s: %s", credential_id, e)
            raise

    def search_credentials(self, query: str, sort_by: str = "service", sort_order: str = "ASC") -> List[Dict]:
        """Substring search over service, username and url (empty query returns all)."""
        if not query:
            return self.get_all_credentials(sort_by=sort_by, sort_order=sort_order)
        search_term = f"%{query}%"
        sql = (
            f"SELECT {CREDENTIAL_COLUMNS} FROM credentials "
            f"WHERE service LIKE ? OR username LIKE ? OR url LIKE ? "
            f"{_order_by_clause(sort_by, sort_order)}"
        )
        try:
            with self._get_connection() as conn:
                rows = conn.execute(sql, (search_term, search_term, search_term)).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error searching credentials: %s", e)
            return []

    def toggle_favorite_status(self, credential_id: int) -> None:
        """Flips is_favorite without touching updated_at."""
        query = "UPDATE credentials SET is_favorite = CASE is_favorite WHEN 0 THEN 1 ELSE 0 END WHERE id = ?"
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(query, (credential_id,))
            if cursor.rowcount == 0:
                logger.warning("Toggle favorite failed, ID not found: %s", credential_id)
            else:
                logger.info("Toggled favorite status ID: %s", credential_id)
        except sqlite3.Error as e:
            logger.error("Error toggling favorite status ID %s: %s", credential_id, e)
            raise

    def close(self) -> None:
        """No-op: connections are opened per operation."""
        logger.debug("Database close method called (no persistent connection).")

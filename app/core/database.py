# password_manager/app/core/database.py
import sqlite3
import hashlib
import logging
import base64
import os
from typing import Optional, List, Tuple, Dict, Any

# Cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Local imports
from config import settings
from app.core.encryption import generate_salt

# Configure logging
try:
    log_dir = os.path.dirname(settings.LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(filename=settings.LOG_FILE, level=settings.LOG_LEVEL.upper(),
                        format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
                        encoding='utf-8')
except Exception as e:
    print(f"Warning: Could not configure logging in database.py: {e}")


class PasswordDatabase:
    """Handles all database operations for the password manager."""

    def __init__(self, db_path: str = settings.DATABASE_PATH):
        self.db_path = db_path; logging.debug(f"PasswordDatabase initializing with path: {self.db_path}")
        try:
            db_dir = os.path.dirname(self.db_path);
            if db_dir: os.makedirs(db_dir, exist_ok=True);
            self._create_tables(); logging.info(f"Database initialized at {self.db_path}")
        except Exception as e: logging.exception(f"Failed to initialize database structure at {self.db_path}"); raise RuntimeError(f"Failed to initialize database structure: {e}") from e

    def _get_connection(self) -> sqlite3.Connection:
        try: conn = sqlite3.connect(self.db_path, timeout=10); conn.row_factory = sqlite3.Row; conn.execute("PRAGMA foreign_keys = ON;"); return conn
        except sqlite3.Error as e: logging.error(f"Database connection error: {e}"); raise

    def _create_tables(self):
        logging.debug("Checking/creating database tables.")
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor(); cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                cursor.execute(""" CREATE TABLE IF NOT EXISTS credentials ( id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL, username TEXT NOT NULL, encrypted_password BLOB NOT NULL, notes TEXT, is_favorite INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP )""")
                cursor.execute(""" CREATE TRIGGER IF NOT EXISTS update_credential_timestamp AFTER UPDATE ON credentials FOR EACH ROW BEGIN UPDATE credentials SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id; END; """)
                cursor.execute(""" CREATE TABLE IF NOT EXISTS security_questions ( id INTEGER PRIMARY KEY AUTOINCREMENT, question_text TEXT NOT NULL UNIQUE, hashed_answer TEXT NOT NULL, salt TEXT NOT NULL ) """)
                logging.info("DB tables checked/created.")
        except sqlite3.Error as e: logging.error(f"Error creating DB tables: {e}"); raise

    def set_setting(self, key: str, value: str):
        logging.debug(f"Setting database key='{key}'")
        try:
            with self._get_connection() as conn: conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
            logging.info(f"Setting '{key}' updated.")
        except sqlite3.Error as e: logging.error(f"Error setting setting '{key}': {e}"); raise

    def get_setting(self, key: str) -> Optional[str]:
        logging.debug(f"Getting database setting for key='{key}'")
        try:
            with self._get_connection() as conn: cursor = conn.cursor(); cursor.execute("SELECT value FROM settings WHERE key = ?", (key,)); result = cursor.fetchone(); value = result['value'] if result else None; logging.debug(f"Setting '{key}' value: {'(Found)' if value else '(Not found)'}"); return value
        except sqlite3.Error as e: logging.error(f"Error getting setting '{key}': {e}"); return None

    def is_master_password_set(self) -> bool: result = self.get_setting("master_hash") is not None; logging.debug(f"Checked if master password is set: {result}"); return result

    def _hash_password(self, password: str, salt: bytes) -> str:
        logging.debug(f"_hash_password called. Len: {len(password)}")
        try: pwd_bytes = password.encode('utf-8'); hasher = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000, backend=default_backend()); hashed_bytes = hasher.derive(pwd_bytes); hashed_b64 = base64.b64encode(hashed_bytes).decode('utf-8'); logging.debug(f"_hash_password returning hash: {hashed_b64[:10]}..."); return hashed_b64
        except Exception as e: logging.exception("Error in _hash_password"); raise

    def set_master_password(self, master_password: str):
        logging.debug("Setting master password.")
        if not master_password or len(master_password) < settings.MIN_MASTER_PASSWORD_LENGTH: raise ValueError(f"Master pwd >= {settings.MIN_MASTER_PASSWORD_LENGTH} chars.")
        master_salt = generate_salt(); master_salt_b64 = base64.b64encode(master_salt).decode('utf-8'); logging.debug(f"Generated master salt (b64): {master_salt_b64}")
        master_hash = self._hash_password(master_password, master_salt); logging.debug(f"Generated master hash (b64): {master_hash}")
        encryption_salt = generate_salt(); encryption_salt_b64 = base64.b64encode(encryption_salt).decode('utf-8'); logging.debug(f"Generated encrypt salt (b64): {encryption_salt_b64}")
        try:
            logging.debug("Storing master pwd settings."); self.set_setting("master_salt", master_salt_b64); self.set_setting("master_hash", master_hash); self.set_setting("encryption_salt", encryption_salt_b64); logging.info("Master pwd settings set.")
        except Exception as e:
            logging.error(f"Failed store master pwd settings: {e}"); self.clear_master_password_settings(); self.clear_security_questions(); raise ValueError("Failed save master pwd settings.") from e

    def verify_master_password(self, master_password: str) -> bool:
        logging.debug("Verifying master pwd."); stored_salt_b64 = self.get_setting("master_salt"); stored_hash_b64 = self.get_setting("master_hash")
        if not stored_salt_b64 or not stored_hash_b64: logging.warning("Verification attempt, but settings missing."); return False
        try:
            salt_bytes = base64.b64decode(stored_salt_b64.encode('utf-8')); provided_hash_b64 = self._hash_password(master_password, salt_bytes); logging.debug(f"Hash from input (b64): {provided_hash_b64[:10]}..."); comparison_result = hashlib.compare_digest(provided_hash_b64.encode('utf-8'), stored_hash_b64.encode('utf-8')); logging.debug(f"Comparison result: {comparison_result}"); return comparison_result
        except AttributeError as ae: logging.error(f"AttributeError during verify (compare_digest?): {ae}"); logging.warning("Falling back to basic string comparison."); comparison_result = (provided_hash_b64 == stored_hash_b64); logging.debug(f"Fallback compare result: {comparison_result}"); return comparison_result
        except Exception as e: logging.exception("Error during master pwd verification"); return False

    # --- CORRECTED get_encryption_salt ---
    def get_encryption_salt(self) -> Optional[bytes]:
        """Retrieves the salt used for deriving the encryption key."""
        salt_b64 = self.get_setting("encryption_salt")
        if salt_b64:
            try:
                # Correctly indented return statement
                return base64.b64decode(salt_b64.encode('utf-8'))
            except Exception as e:
                # Correctly indented except block
                logging.error(f"Error decoding encryption salt: {e}")
                return None
        # Correctly indented return if salt_b64 is None
        logging.warning("Encryption salt not found in settings.")
        return None
    # --- END CORRECTION ---

    def clear_master_password_settings(self):
        logging.warning("Clearing master password settings.");
        try:
            with self._get_connection() as conn: conn.execute("DELETE FROM settings WHERE key IN (?, ?, ?)",("master_hash", "master_salt", "encryption_salt"))
            logging.info("Master pwd settings cleared.")
        except sqlite3.Error as e: logging.error(f"Error clearing master pwd settings: {e}")

    def set_security_question(self, question_text: str, answer: str):
        if not question_text or not answer: raise ValueError("Question and answer cannot be empty.")
        logging.debug(f"Setting security question: {question_text[:30]}...")
        salt = generate_salt(); hashed_answer = self._hash_password(answer, salt); salt_b64 = base64.b64encode(salt).decode('utf-8')
        try:
            with self._get_connection() as conn: conn.execute("INSERT OR REPLACE INTO security_questions (question_text, hashed_answer, salt) VALUES (?, ?, ?)", (question_text, hashed_answer, salt_b64))
            logging.info(f"Security question set: {question_text[:30]}...")
        except sqlite3.Error as e: logging.error(f"Error setting security question '{question_text[:30]}...': {e}"); raise

    def get_security_questions(self) -> List[Dict[str, Any]]:
        logging.debug("Retrieving security questions.")
        try:
            with self._get_connection() as conn: cursor = conn.cursor(); cursor.execute("SELECT id, question_text FROM security_questions ORDER BY id"); return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e: logging.error(f"Error retrieving security questions: {e}"); return []

    def verify_security_answer(self, question_id: int, provided_answer: str) -> bool:
        logging.debug(f"Verifying answer for question ID: {question_id}")
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor(); cursor.execute("SELECT hashed_answer, salt FROM security_questions WHERE id = ?", (question_id,)); row = cursor.fetchone()
                if not row: logging.warning(f"No security question for ID: {question_id}"); return False
                stored_hashed_answer = row['hashed_answer']; salt_b64 = row['salt']; salt_bytes = base64.b64decode(salt_b64.encode('utf-8'))
                provided_answer_hash = self._hash_password(provided_answer, salt_bytes)
                return hashlib.compare_digest(provided_answer_hash.encode('utf-8'), stored_hashed_answer.encode('utf-8'))
        except Exception as e: logging.exception(f"Error verifying security answer ID {question_id}"); return False

    def are_security_questions_set(self) -> bool:
        questions = self.get_security_questions(); is_set = len(questions) >= settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET; logging.debug(f"Security questions set: {is_set} (Found {len(questions)}, Need {settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET})"); return is_set

    def clear_security_questions(self):
        logging.warning("Clearing ALL security questions from database.")
        try:
            with self._get_connection() as conn: conn.execute("DELETE FROM security_questions")
            logging.info("All security questions cleared.")
        except sqlite3.Error as e: logging.error(f"Error clearing security questions: {e}")

    def add_credential(self, service: str, username: str, encrypted_password: bytes, notes: str = ""):
        logging.info(f"Attempting to add credential for: {service}")
        print(f"--- DB DEBUG (add_credential): Service='{service}', User='{username}', EncPassLen={len(encrypted_password)}, Notes='{notes[:20]}...'")
        if not service or not username or not encrypted_password: logging.error("Add Credential validation failed."); raise ValueError("Service, username, password cannot be empty.")
        try:
            with self._get_connection() as conn: cursor = conn.cursor(); cursor.execute("INSERT INTO credentials (service, username, encrypted_password, notes) VALUES (?, ?, ?, ?)", (service, username, encrypted_password, notes if notes else "")); print(f"--- DB DEBUG (add_credential): Insert executed. Last row ID: {cursor.lastrowid}"); logging.info(f"Cred added: {service}. Last row ID: {cursor.lastrowid}")
        except sqlite3.Error as e: logging.error(f"DB error adding cred for '{service}': {e}"); print(f"---!!!! DB DEBUG (add_credential): FAILED insert: {e} !!!! ---"); raise
        except Exception as e: logging.exception(f"Unexpected error adding cred for '{service}'"); print(f"---!!!! DB DEBUG (add_credential): UNEXPECTED error: {e} !!!! ---"); raise

    def get_all_credentials(self, sort_by: str = "service", sort_order: str = "ASC") -> List[Dict]:
        allowed_sort_columns = {"service": "service", "username": "username", "is_favorite": "is_favorite", "created_at": "created_at", "updated_at": "updated_at"}
        allowed_orders = {"ASC": "ASC", "DESC": "DESC"}
        db_column = allowed_sort_columns.get(sort_by, "service"); order = allowed_orders.get(sort_order.upper(), "ASC")
        collate_clause = "COLLATE NOCASE" if db_column in ["service", "username"] else ""
        query = f"SELECT id, service, username, encrypted_password, notes, is_favorite FROM credentials ORDER BY {db_column} {collate_clause} {order}"
        logging.debug(f"Executing get_all_credentials query: {query}"); print(f"--- DB DEBUG (get_all): Running query: {query} ---")
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                results = [dict(row) for row in cursor.fetchall()]
                print(f"--- DB DEBUG (get_all): Fetched {len(results)} rows. ---")
                return results
        except sqlite3.Error as e:
            logging.error(f"Error retrieving all creds: {e}")
            print(f"---!!!! DB DEBUG (get_all): FAILED query: {e} !!!! ---")
            return []

    def get_credential_by_id(self, credential_id: int) -> Optional[Dict]:
        logging.debug(f"Getting credential by ID: {credential_id}")
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, service, username, encrypted_password, notes, is_favorite FROM credentials WHERE id = ?", (credential_id,))
                row = cursor.fetchone()
                result_dict = dict(row) if row else None
                logging.debug(f"get_credential_by_id result: {'Found' if result_dict else 'Not Found'}")
                return result_dict
        except sqlite3.Error as e:
            logging.error(f"Error retrieving credential ID {credential_id}: {e}")
            print(f"---!!!! DB DEBUG (get_credential_by_id): FAILED query: {e} !!!! ---")
            return None

    def update_credential(self, credential_id: int, service: str, username: str, encrypted_password: bytes, notes: str):
        if not service or not username or not encrypted_password: raise ValueError("Service, username, password cannot be empty.")
        try:
            with self._get_connection() as conn: conn.execute("UPDATE credentials SET service = ?, username = ?, encrypted_password = ?, notes = ? WHERE id = ?", (service, username, encrypted_password, notes if notes else "", credential_id)); logging.info(f"Cred updated ID: {credential_id}")
        except sqlite3.Error as e: logging.error(f"Error updating cred ID {credential_id}: {e}"); raise

    def delete_credential(self, credential_id: int):
        try:
            with self._get_connection() as conn: conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,)); logging.info(f"Cred deleted ID: {credential_id}")
        except sqlite3.Error as e: logging.error(f"Error deleting cred ID {credential_id}: {e}"); raise

    def search_credentials(self, query: str, sort_by: str = "service", sort_order: str = "ASC") -> List[Dict]:
        if not query: print("--- DB DEBUG (search): Empty query, calling get_all_credentials ---"); return self.get_all_credentials(sort_by=sort_by, sort_order=sort_order)
        allowed_sort_columns = {"service": "service", "username": "username", "is_favorite": "is_favorite", "created_at": "created_at", "updated_at": "updated_at"}
        allowed_orders = {"ASC": "ASC", "DESC": "DESC"}
        db_column = allowed_sort_columns.get(sort_by, "service"); order = allowed_orders.get(sort_order.upper(), "ASC"); collate_clause = "COLLATE NOCASE" if db_column in ["service", "username"] else ""
        search_term = f"%{query}%"
        sql_query = f"SELECT id, service, username, encrypted_password, notes, is_favorite FROM credentials WHERE service LIKE ? OR username LIKE ? ORDER BY {db_column} {collate_clause} {order}"
        logging.debug(f"Executing search_credentials query: {sql_query}"); print(f"--- DB DEBUG (search): Running query: {sql_query} with term: {search_term} ---")
        try:
            with self._get_connection() as conn: cursor = conn.cursor(); cursor.execute(sql_query, (search_term, search_term)); results = [dict(row) for row in cursor.fetchall()]; print(f"--- DB DEBUG (search): Fetched {len(results)} rows. ---"); return results
        except sqlite3.Error as e: logging.error(f"Error searching creds query '{query}': {e}"); print(f"---!!!! DB DEBUG (search): FAILED query: {e} !!!! ---"); return []

    def toggle_favorite_status(self, credential_id: int):
        logging.debug(f"Toggling favorite status for ID: {credential_id}")
        query = "UPDATE credentials SET is_favorite = CASE is_favorite WHEN 0 THEN 1 ELSE 0 END, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor(); cursor.execute(query, (credential_id,))
                if cursor.rowcount == 0: logging.warning(f"Toggle favorite failed, ID not found: {credential_id}")
                else: logging.info(f"Toggled favorite status ID: {credential_id}")
        except sqlite3.Error as e: logging.error(f"Error toggling favorite status ID {credential_id}: {e}"); raise

    def close(self): logging.info("Database close method called (usually not required).")

# End of file password_manager/app/core/database.py
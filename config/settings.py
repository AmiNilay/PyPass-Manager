"""Application-wide settings and paths."""

import os

# --- Application ---
APP_NAME = "PyPass Manager"
APP_VERSION = "2.0.0"

# --- Paths ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
ICON_DIR = os.path.join(ASSETS_DIR, "icons")
STYLE_DIR = os.path.join(ASSETS_DIR, "styles")

# User data (database, log, caches) lives outside the install directory.
DATA_DIR = os.path.join(os.path.expanduser("~"), ".pypass_manager")
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(DATA_DIR, "passwords.db")

# --- Logging ---
LOG_FILE = os.path.join(DATA_DIR, "app.log")
LOG_LEVEL = "INFO"

# --- UI ---
THEME = "Dark"
COLOR_SCHEME = os.path.join(STYLE_DIR, "graphite.json")
CLIPBOARD_TIMEOUT = 15000  # ms before a copied password is cleared
AUTOLOCK_TIMEOUT_MS = 5 * 60 * 1000  # lock the vault after 5 minutes of inactivity

# Show website logos. Only the domain is requested (from the site itself, then
# Google's favicon service); logos are cached in FAVICON_DIR. Set False to stay offline.
FETCH_FAVICONS = True
FAVICON_DIR = os.path.join(DATA_DIR, "favicons")

# --- Security ---
MIN_MASTER_PASSWORD_LENGTH = 8

PREDEFINED_SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What was the name of the elementary school you attended?",
    "What city were you born in?",
    "What is your mother's maiden name?",
    "What was the make and model of your first car?",
    "In what city did your parents meet?",
    "What is your favorite childhood book?",
]
NUMBER_OF_SECURITY_QUESTIONS_TO_SET = 3

# --- Icon files (assets/icons) ---
APP_ICON_FILE_ICO = os.path.join(ICON_DIR, "app_icon.ico")
APP_ICON_FILE_PNG = os.path.join(ICON_DIR, "app_icon.png")
EDIT_ICON_FILE = os.path.join(ICON_DIR, "edit.png")
DELETE_ICON_FILE = os.path.join(ICON_DIR, "delete.png")
COPY_ICON_FILE = os.path.join(ICON_DIR, "copy.png")
VIEW_ICON_FILE = os.path.join(ICON_DIR, "view.png")
GENERATE_ICON_FILE = os.path.join(ICON_DIR, "generate.png")
VISIBLE_ICON_FILE = os.path.join(ICON_DIR, "visible.png")
HIDDEN_ICON_FILE = os.path.join(ICON_DIR, "hidden.png")
# Not on disk yet, but still referenced by the UI (which falls back gracefully).
FAVORITE_ICON_FILE = os.path.join(ICON_DIR, "star_filled.png")
NOT_FAVORITE_ICON_FILE = os.path.join(ICON_DIR, "star_empty.png")

# password_manager/config/settings.py
import os

# --- General Settings ---
APP_NAME = "PyPass Manager"
APP_VERSION = "1.0.0"

# --- Base Directory ---
# Get the base directory of the project
# Assumes settings.py is in password_manager/config/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- Asset Paths (Define BEFORE using them) ---
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
ICON_DIR = os.path.join(ASSETS_DIR, "icons")
STYLE_DIR = os.path.join(ASSETS_DIR, "styles")
# --- End Asset Paths ---

# --- Database Settings ---
DATA_DIR = os.path.join(os.path.expanduser("~"), ".pypass_manager")
os.makedirs(DATA_DIR, exist_ok=True) # Ensure the directory exists
DATABASE_PATH = os.path.join(DATA_DIR, "passwords.db")

# --- UI Settings ---
THEME = "Light"  # "System", "Dark", "Light" - Keeping "Light" as requested
COLOR_SCHEME = "blue"  # "blue", "green", "dark-blue"
CLIPBOARD_TIMEOUT = 15000  # Milliseconds
AUTOLOCK_TIMEOUT_MS = 60 * 1000 # 1 minute (Used for the Auto-Lock feature when we implement it)

# --- Security Settings ---
MIN_MASTER_PASSWORD_LENGTH = 8
# --- Security Question Settings (as added for the current feature) ---
PREDEFINED_SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What was the name of the elementary school you attended?",
    "What city were you born in?",
    "What is your mother's maiden name?",
    "What was the make and model of your first car?",
    "In what city did your parents meet?",
    "What is your favorite childhood book?"
]
NUMBER_OF_SECURITY_QUESTIONS_TO_SET = 3 # User must set this many
# --- End Security Question Settings ---

# --- Logging ---
LOG_FILE = os.path.join(DATA_DIR, "app.log")
LOG_LEVEL = "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL

# --- Icon Files (Now ICON_DIR is defined) ---
APP_ICON_FILE_ICO = os.path.join(ICON_DIR, "app_icon.ico")
APP_ICON_FILE_PNG = os.path.join(ICON_DIR, "app_icon.png")
ADD_ICON_FILE = os.path.join(ICON_DIR, "add.png")
EDIT_ICON_FILE = os.path.join(ICON_DIR, "edit.png")
DELETE_ICON_FILE = os.path.join(ICON_DIR, "delete.png")
COPY_ICON_FILE = os.path.join(ICON_DIR, "copy.png")
VIEW_ICON_FILE = os.path.join(ICON_DIR, "view.png")
GENERATE_ICON_FILE = os.path.join(ICON_DIR, "generate.png")
SEARCH_ICON_FILE = os.path.join(ICON_DIR, "search.png")
VISIBLE_ICON_FILE = os.path.join(ICON_DIR, "visible.png")
HIDDEN_ICON_FILE = os.path.join(ICON_DIR, "hidden.png")
SAVE_ICON_FILE = os.path.join(ICON_DIR, "save.png")
CANCEL_ICON_FILE = os.path.join(ICON_DIR, "cancel.png")
LOCAL_GEN_ICON_FILE = os.path.join(ICON_DIR, "local_gen.png")
# --- Favorite Icons ---
FAVORITE_ICON_FILE = os.path.join(ICON_DIR, "star_filled.png")
NOT_FAVORITE_ICON_FILE = os.path.join(ICON_DIR, "star_empty.png")
# --- End Favorite Icons ---
# --- End Icon Files ---

# --- NO Gemini Settings ---
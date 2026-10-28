# password_manager/main.py
"""
Application entry point: configures logging and theme, then opens the login window.
"""
import logging
import os
import sys

import customtkinter as ctk

from config import settings
from app.core.database import PasswordDatabase
from app.ui.login_window import LoginWindow
from app.ui.theme import apply_widget_defaults
from app.ui.widgets import set_window_icon


def setup_logging() -> None:
    """Logs to settings.LOG_FILE and stdout. Falls back to stderr notices if that fails."""
    try:
        os.makedirs(os.path.dirname(settings.LOG_FILE), exist_ok=True)
    except Exception as e:
        sys.stderr.write(f"Error creating log dir: {e}\n")
    try:
        logging.basicConfig(
            level=settings.LOG_LEVEL.upper(),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(settings.LOG_FILE, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    except Exception as e:
        sys.stderr.write(f"Error setting up logging: {e}\n")


def main() -> None:
    setup_logging()
    logging.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    hidden_root = None

    try:
        hidden_root = ctk.CTk()
        hidden_root.withdraw()

        try:
            ctk.set_default_color_theme(settings.COLOR_SCHEME)
        except Exception as e:
            logging.warning(f"Theme file {settings.COLOR_SCHEME} failed to load ({e}); using default.")

        ctk.set_appearance_mode("Dark")

        try:
            apply_widget_defaults()
        except Exception:
            logging.exception("apply_widget_defaults failed.")

        db = PasswordDatabase(settings.DATABASE_PATH)
        logging.debug(f"Database opened: {settings.DATABASE_PATH}")

        login_app = LoginWindow(master=hidden_root, db=db)
        set_window_icon(login_app)

        # LoginWindow destroys itself if its UI fails to build; don't wait on an empty mainloop
        if login_app.winfo_exists():
            hidden_root.mainloop()
        logging.info("Main loop ended.")

    except KeyboardInterrupt:
        logging.info("Terminated by user.")
    except Exception:
        logging.exception("Unhandled error.")
    finally:
        if hidden_root and hidden_root.winfo_exists():
            try:
                hidden_root.destroy()
            except Exception:
                pass


if __name__ == "__main__":
    main()

# password_manager/main.py
import customtkinter as ctk
import logging
import os
from tkinter import messagebox
# No PIL needed here

# Local imports
from config import settings
from app.core.database import PasswordDatabase
# LoginWindow will be launched, it handles MainWindow creation
from app.ui.login_window import LoginWindow


def setup_logging():
    # ... (logging setup code remains the same) ...
    try: log_dir = os.path.dirname(settings.LOG_FILE); os.makedirs(log_dir, exist_ok=True)
    except Exception as e: print(f"Error creating log dir: {e}")
    try:
        logging.basicConfig(level=settings.LOG_LEVEL.upper(), format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s', handlers=[logging.FileHandler(settings.LOG_FILE, encoding='utf-8'), logging.StreamHandler()])
        logging.info("Logging setup complete.")
    except Exception as e: print(f"Error setting up logging: {e}")


def main():
    setup_logging()
    logging.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    hidden_root = None
    login_app = None

    try:
        # --- Create HIDDEN Root CTk Instance FIRST ---
        logging.debug("Creating hidden CTk root instance.")
        hidden_root = ctk.CTk()
        hidden_root.withdraw()
        logging.debug("Hidden CTk root created and withdrawn.")

        # Set Appearance AFTER root exists
        custom_theme_path = os.path.join(settings.STYLE_DIR, "your_theme.json")
        try:
            if os.path.exists(custom_theme_path):
                 try: ctk.set_default_color_theme(custom_theme_path); logging.info(f"Loaded theme: {custom_theme_path}")
                 except Exception as e: logging.error(f"Failed load theme: {e}. Using default."); ctk.set_default_color_theme(settings.COLOR_SCHEME)
            else: ctk.set_default_color_theme(settings.COLOR_SCHEME)
            ctk.set_appearance_mode(settings.THEME)
            logging.debug(f"Theme/Appearance set (Theme: {settings.THEME}, Color: {settings.COLOR_SCHEME})")
        except Exception as e: logging.warning(f"Could not set theme/color: {e}. Using defaults."); ctk.set_appearance_mode("System"); ctk.set_default_color_theme("blue")

        # Initialize database
        db = None
        try: db = PasswordDatabase(settings.DATABASE_PATH); logging.info(f"Database object created.")
        except Exception as e: logging.exception("Fatal DB init error."); messagebox.showerror("DB Error", f"DB Init Error:\n{e}\nApp cannot start.", parent=hidden_root); return

        # --- Create LoginWindow as a Toplevel of hidden_root ---
        login_app = LoginWindow(master=hidden_root, db=db)
        logging.info(f"LoginWindow (Toplevel) object created: {login_app}")
        # Icon setting for LoginWindow (Toplevel now) might need self.master? Test without first.
        # login_app.master.iconbitmap(...) ? Or just login_app.iconbitmap(...)
        try:
            icon_path_to_use = settings.APP_ICON_FILE_ICO
            if not os.path.exists(icon_path_to_use) or not icon_path_to_use.endswith(".ico"): icon_path_to_use = settings.APP_ICON_FILE_PNG
            if os.path.exists(icon_path_to_use): login_app.iconbitmap(icon_path_to_use); logging.info(f"Set LoginWindow icon: {icon_path_to_use}")
            else: logging.warning(f"App icon file not found for LoginWindow: {icon_path_to_use}")
        except Exception as e: logging.error(f"Failed set LoginWindow icon: {e}")


        # --- Start mainloop on the HIDDEN root ---
        logging.info("Starting hidden_root.mainloop()")
        hidden_root.mainloop()
        logging.info("hidden_root.mainloop() finished.")

    except KeyboardInterrupt: logging.warning("App terminated by user."); print("\nApp terminated.")
    except Exception as e:
        logging.exception("UNEXPECTED APP ERROR")
        try: messagebox.showerror("App Error", f"Critical error:\n{e}", parent=hidden_root if hidden_root else None)
        except: pass
    finally:
         logging.info(f"{settings.APP_NAME} finished.")
         # No need to explicitly destroy login_app/main_app here if they derive from Toplevel,
         # destroying hidden_root should handle it if they haven't been closed manually.
         if hidden_root and hidden_root.winfo_exists():
             try: hidden_root.destroy(); logging.debug("Hidden root destroyed.")
             except Exception as e: logging.error(f"Error destroying hidden_root: {e}")
         print("Cleanup finished.")


if __name__ == "__main__":
    main()
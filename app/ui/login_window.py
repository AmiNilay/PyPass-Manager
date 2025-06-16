# password_manager/app/ui/login_window.py
import customtkinter as ctk
from tkinter import messagebox
import logging
import os
from PIL import Image

# Local imports
from app.core.database import PasswordDatabase
from app.core.encryption import derive_key
from config import settings
# Import MainWindow HERE
from app.ui.main_window import MainWindow
from app.ui.security_questions_setup_dialog import SecurityQuestionsSetupDialog
# --- NEW: Import ResetMasterPasswordDialog AND PasswordRecoveryDialog ---
from app.ui.reset_master_password_dialog import ResetMasterPasswordDialog
from app.ui.password_recovery_dialog import PasswordRecoveryDialog # <-- ADDED THIS IMPORT
# --- END NEW ---


# --- Icon Loader Helper ---
# (Keep function as is)
def load_icon(file_path, size=(20, 20)):
    if not os.path.exists(file_path): return None
    try:
        img = Image.open(file_path);
        if img.mode not in ['RGB', 'RGBA']: img = img.convert('RGBA')
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception as e: logging.error(f"Failed to load icon {file_path}: {e}"); return None


class LoginWindow(ctk.CTkToplevel): # Inherit from Toplevel
    """Login window (Toplevel)."""

    # --- __init__ and _setup_ui remain the same ---
    def __init__(self, master, db: PasswordDatabase):
        super().__init__(master)
        logging.debug("LoginWindow: Initializing.")
        self.db = db
        self.transient(master)
        self.title(f"{settings.APP_NAME} - Login")
        self.geometry("400x380") # Base geometry, forgot pwd link might expand it
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.is_setup_mode = not self.db.is_master_password_set()
        self.save_icon = None; self.login_icon = None
        try:
            self.save_icon = load_icon(settings.SAVE_ICON_FILE)
            self.login_icon = load_icon(settings.SAVE_ICON_FILE, size=(18,18))
            if not self.save_icon: logging.warning(f"Save/Login icon not found at {settings.SAVE_ICON_FILE}")
        except Exception as e: logging.error(f"Error loading icons: {e}")
        try: self._setup_ui()
        except Exception as e: logging.exception("FAILED LoginWindow _setup_ui"); self.destroy(); return
        try: self.eval('tk::PlaceWindow . center')
        except Exception as e: logging.warning(f"Failed PlaceWindow eval: {e}")
        self.lift(); self.focus(); logging.debug("LoginWindow initialized.")

    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        rows_needed = 6 if self.is_setup_mode else 5
        for i in range(rows_needed): self.grid_rowconfigure(i, weight=0)
        if self.is_setup_mode: self.grid_rowconfigure(3, weight=1)
        else: self.grid_rowconfigure(4, weight=1)
        title_text = "Set Master Password" if self.is_setup_mode else "Enter Master Password"
        self.title_label = ctk.CTkLabel(self, text=title_text, font=ctk.CTkFont(size=20, weight="bold")); self.title_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Master Password", show="*", width=250); self.password_entry.grid(row=1, column=0, padx=20, pady=10); self.password_entry.bind("<Return>", self._perform_action)
        self.status_label = ctk.CTkLabel(self, text="", text_color="red")
        current_row = 2
        if self.is_setup_mode:
            self.confirm_password_entry = ctk.CTkEntry(self, placeholder_text="Confirm Master Password", show="*", width=250); self.confirm_password_entry.grid(row=current_row, column=0, padx=20, pady=(5, 10)); self.confirm_password_entry.bind("<Return>", self._perform_action); current_row +=1
            action_button_text = "Set Password & Initialize"; button_icon = self.save_icon
            info_text = (f"Pwd >= {settings.MIN_MASTER_PASSWORD_LENGTH} chars.\n\n⚠️ IMPORTANT ⚠️\nNo password recovery! Remember it!"); self.info_label = ctk.CTkLabel(self, text=info_text, wraplength=360, justify="center", anchor="n", font=ctk.CTkFont(size=11)); self.info_label.grid(row=current_row, column=0, padx=20, pady=(10, 15), sticky="ew"); current_row +=1
            self.action_button = ctk.CTkButton(self, text=action_button_text, image=button_icon, command=self._perform_action); self.action_button.grid(row=current_row, column=0, padx=20, pady=(10, 15)); current_row +=1
            self.status_label.grid(row=current_row, column=0, padx=20, pady=(0, 10), sticky="sew")
        else: # Login mode
            action_button_text = "Login"; button_icon = self.login_icon; self.confirm_password_entry = None
            self.action_button = ctk.CTkButton(self, text=action_button_text, image=button_icon, command=self._perform_action); self.action_button.grid(row=current_row, column=0, padx=20, pady=20); current_row +=1
            self.status_label.grid(row=current_row, column=0, padx=20, pady=(0, 5), sticky="s"); current_row +=1
            forgot_button = ctk.CTkButton(self, text="Forgot Master Password?", fg_color="transparent", text_color=("gray10", "gray90"), hover=False, command=self._forgot_password_action, font=ctk.CTkFont(size=12, underline=True))
            forgot_button.grid(row=current_row, column=0, pady=(0,10), sticky="s")
        self.password_entry.focus()

    def _set_status(self, message: str, color: str = "red"):
        if hasattr(self, 'status_label') and self.status_label and self.status_label.winfo_exists(): self.status_label.configure(text=message, text_color=color)
        else: logging.warning(f"Status label unavailable: {message}")

    def _perform_action(self, event=None):
        self._set_status("");
        if not hasattr(self, 'password_entry') or not self.password_entry.winfo_exists(): logging.error("Password entry missing."); return
        password = self.password_entry.get()
        if not password: self._set_status("Master password cannot be empty."); return
        if self.is_setup_mode:
             if not hasattr(self, 'confirm_password_entry') or not self.confirm_password_entry.winfo_exists(): logging.error("Confirm password entry missing."); return
             confirm_password = self.confirm_password_entry.get()
             if password != confirm_password: self._set_status("Passwords do not match."); return
             if len(password) < settings.MIN_MASTER_PASSWORD_LENGTH: self._set_status(f"Pwd >= {settings.MIN_MASTER_PASSWORD_LENGTH} chars."); return
             try:
                 self.db.set_master_password(password)
                 logging.info("Master password set successfully during initial setup.")
                 if not self.db.are_security_questions_set():
                     logging.info("Security questions not set. Launching setup dialog.")
                     messagebox.showinfo("Next Step", "Master password set!\nNow, please set up your security questions for password recovery.", parent=self)
                     self.withdraw()
                     sq_dialog = SecurityQuestionsSetupDialog(parent=self, db=self.db)
                     # SecurityQuestionsSetupDialog should call self._security_questions_setup_done on success
                 else:
                     logging.warning("In setup mode, but security questions already set. Proceeding.")
                     messagebox.showinfo("Setup Complete", "Master password set.", parent=self.master)
                     self._login_successful(password)
             except ValueError as ve: self._set_status(str(ve)); logging.error(f"Master password setup failed: {ve}")
             except Exception as e: self._set_status("Error during setup."); messagebox.showerror("Setup Error", f"Could not init DB settings:\n{e}", parent=self.master); logging.exception("Unexpected setup error.")
        else: # Login mode
             if self.db.verify_master_password(password):
                 if not self.db.are_security_questions_set():
                     logging.warning("Login successful, but security questions not set. Forcing setup.")
                     messagebox.showwarning("Security Setup Required", "Login successful, but you haven't set up security questions yet.\nPlease set them up now for password recovery.", parent=self)
                     self.withdraw()
                     sq_dialog = SecurityQuestionsSetupDialog(parent=self, db=self.db)
                 else: self._login_successful(password)
             else: self._set_status("Incorrect master password."); logging.warning("Incorrect master password attempt.")

    def _security_questions_setup_done(self):
        logging.info("Security questions setup is complete.")
        password = self.password_entry.get()
        if self.is_setup_mode and password:
            messagebox.showinfo("Setup Fully Complete", "Security questions saved.\nMain application will now open.", parent=self.master) # Use master for main app messages
            self._login_successful(password)
        else:
            logging.info("Security questions setup complete (not initial). Login window will re-appear.")
            self.deiconify_and_focus()
            messagebox.showinfo("Setup Complete", "Security questions saved.\nPlease log in again if needed.", parent=self)
            self.password_entry.delete(0, ctk.END)
            self.password_entry.focus()

    def _login_successful(self, master_password: str):
        logging.info("Login/Setup successful. Proceeding to MainWindow.")
        encryption_salt = self.db.get_encryption_salt()
        if not encryption_salt: messagebox.showerror("Login Error", "Could not retrieve encryption salt.", parent=self.master); logging.critical("Encryption salt missing!"); self.destroy(); return
        main_app = None
        try:
            derived_encryption_key = derive_key(master_password, encryption_salt); logging.debug("Encryption key derived.")
            self.withdraw(); logging.debug("LoginWindow withdrawn.")
            logging.info("Creating MainWindow instance.")
            main_app = MainWindow(master=self.master, db=self.db, encryption_key=derived_encryption_key)
            logging.info(f"MainWindow (Toplevel) instance created: {main_app}")
            icon_path_to_use = settings.APP_ICON_FILE_ICO
            if not os.path.exists(icon_path_to_use) or not icon_path_to_use.endswith(".ico"): icon_path_to_use = settings.APP_ICON_FILE_PNG
            if os.path.exists(icon_path_to_use):
                try:
                    if main_app and main_app.winfo_exists(): main_app.iconbitmap(icon_path_to_use); logging.debug("Set MainWindow icon.")
                except Exception as e: logging.error(f"Failed set MainWindow Toplevel icon: {e}")
            else: logging.warning(f"App icon file not found for MainWindow: {icon_path_to_use}")
            main_app.focus()
            self.after(100, self.destroy)
            logging.debug("_login_successful finished, LoginWindow scheduled for destruction.")
        except Exception as e:
            logging.exception("Error launching main window.")
            messagebox.showerror("Startup Error", f"Failed launch main window:\n{e}", parent=self.master)
            if main_app and main_app.winfo_exists(): main_app.destroy()
            if self.winfo_exists(): self.destroy()

    def _forgot_password_action(self):
        logging.info("Forgot password action initiated.")
        if not self.db.are_security_questions_set():
            messagebox.showwarning("Recovery Not Set Up", "Security questions have not been set up.\nRecovery is not possible.", parent=self)
            return
        logging.debug("Launching PasswordRecoveryDialog.")
        # self.withdraw() # Keep LoginWindow visible but disabled under modal dialog
        recovery_dialog = PasswordRecoveryDialog(master=self.master, db=self.db, success_callback=self._on_security_questions_verified)
        # PasswordRecoveryDialog will grab_set()

    def _on_security_questions_verified(self):
        logging.info("Security questions verified. Launching reset master password dialog.")
        # PasswordRecoveryDialog should have destroyed itself.
        # LoginWindow may be withdrawn or just behind; ensure it's not interactable.
        # self.withdraw() # ensure it is hidden
        reset_dialog = ResetMasterPasswordDialog(master=self.master, db=self.db, success_callback=self._on_master_password_reset)
        # ResetMasterPasswordDialog will grab_set()

    def _on_master_password_reset(self):
        logging.info("Master password has been reset.")
        messagebox.showinfo("Password Reset", "Master password has been reset.\n"
                                            "Please log in with your new master password.\n"
                                            "You will need to set up new security questions after logging in.",
                                            parent=self.master)
        self.deiconify_and_focus() # Bring LoginWindow back to front
        self.password_entry.delete(0, ctk.END)
        self.is_setup_mode = False # Ensure it's in login mode
        # Force UI update for login mode if needed, though state should handle it.
        # Consider a more robust way to refresh the UI elements if _setup_ui needs full rerun
        # For now, assume current _setup_ui logic handles the transition if state is correct.
        self.password_entry.focus()


    def deiconify_and_focus(self):
        try:
            if self.winfo_exists():
                self.deiconify(); self.lift(); self.focus()
        except Exception as e: logging.warning(f"Error in deiconify_and_focus: {e}")

    def _on_closing(self):
        logging.info("Login window WM_DELETE_WINDOW received.")
        self.destroy()

    def destroy(self):
        logging.debug(f"Destroying LoginWindow ({self})")
        try: pass
        except Exception as e: logging.error(f"Error during LoginWindow custom destroy: {e}")
        finally:
            try:
                super_obj = super()
                if hasattr(super_obj, 'destroy'): super_obj.destroy(); logging.debug(f"super().destroy() called for LoginWindow ({self})")
                else: logging.warning("super() has no destroy method in LoginWindow.destroy")
            except Exception as super_e: logging.error(f"Error calling super().destroy() in LoginWindow: {super_e}")
# End of file password_manager/app/ui/login_window.py
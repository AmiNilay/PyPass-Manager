# password_manager/app/ui/login_window.py
"""
Startup window: creates a new vault or unlocks an existing one, and drives
the forgot-password (recovery/reset) flow before handing over to MainWindow.
"""
import logging
from tkinter import messagebox
from typing import List

import customtkinter as ctk

from config import settings
from app.core.database import PasswordDatabase
from app.core.password_utils import check_password_strength
from app.ui.theme import (BG, BORDER, ACCENT, SUCCESS, SECONDARY, DANGER, TEXT_MUTED,
                          FONT_SMALL, PAD_X, INPUT_HEIGHT, BTN_PRIMARY, BTN_GHOST)
from app.ui.widgets import (FIELD_WIDTH, brand_header, security_footer, labeled_field,
                            password_entry, caps_label, status_label, bind_caps_lock_warning,
                            center_over, set_window_icon)
from app.ui.main_window import MainWindow
from app.ui.security_questions_setup_dialog import SecurityQuestionsSetupDialog
from app.ui.reset_master_password_dialog import ResetMasterPasswordDialog
from app.ui.password_recovery_dialog import PasswordRecoveryDialog
from app.ui.emergency_dialogs import EmergencyRecoveryDialog

# Strength meter colours by score 0..4 (Very Weak .. Very Strong)
STRENGTH_COLORS = (DANGER, DANGER, SECONDARY, ACCENT, SUCCESS)


class LoginWindow(ctk.CTkToplevel):
    """Create-vault / unlock window shown at startup."""

    def __init__(self, master, db: PasswordDatabase):
        super().__init__(master)
        self.db = db
        self.transient(master)
        self.title(f"{settings.APP_NAME}")
        self.geometry("440x640" if not self.db.is_master_password_set() else "440x560")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.is_setup_mode = not self.db.is_master_password_set()
        self.vault_key = None
        # Set once a MainWindow takes over; otherwise closing this window exits the app
        self._main_window_launched = False

        try:
            self._setup_ui()
        except Exception:
            logging.exception("FAILED LoginWindow _setup_ui")
            self.destroy()
            return

        center_over(self)
        self.after(50, lambda: center_over(self))
        self.lift()
        self.focus()

    def _setup_ui(self):
        security_footer(self)
        body = ctk.CTkFrame(self, fg_color="transparent", width=FIELD_WIDTH)
        body.pack(expand=True, padx=PAD_X)

        if self.is_setup_mode:
            brand_header(body, "Create your vault",
                         "Choose a master password. It encrypts everything and cannot be recovered by us.")
        else:
            brand_header(body, "Unlock your vault", "Enter your master password to continue.")

        self.password_entry = labeled_field(body, "Master password",
                                            lambda p: password_entry(p, "Enter master password"),
                                            top_pad=0)
        self.password_entry.bind("<Return>", self._perform_action)
        caps_entries = [self.password_entry]

        if self.is_setup_mode:
            meter = ctk.CTkFrame(body, fg_color="transparent")
            meter.pack(fill="x", pady=(8, 0))
            self.strength_bar = ctk.CTkProgressBar(meter, height=4, corner_radius=2,
                                                   fg_color=BORDER, progress_color=BORDER)
            self.strength_bar.set(0)
            self.strength_bar.pack(side="left", fill="x", expand=True, padx=(0, 10))
            self.strength_text = ctk.CTkLabel(meter, text="", font=FONT_SMALL,
                                              text_color=TEXT_MUTED, width=72, anchor="e")
            self.strength_text.pack(side="right")
            self.password_entry.bind("<KeyRelease>", self._update_strength, add="+")

            self.confirm_password_entry = labeled_field(
                body, "Confirm password", lambda p: password_entry(p, "Re-enter master password"))
            self.confirm_password_entry.bind("<Return>", self._perform_action)
            caps_entries.append(self.confirm_password_entry)

            ctk.CTkLabel(body,
                         text=f"At least {settings.MIN_MASTER_PASSWORD_LENGTH} characters. A long passphrase "
                              "is easiest to remember. You'll set up recovery questions next.",
                         font=FONT_SMALL, text_color=TEXT_MUTED, wraplength=FIELD_WIDTH,
                         justify="left", anchor="w").pack(fill="x", pady=(10, 0))

        self.caps_label = caps_label(body)
        self.caps_label.pack(fill="x", pady=(6, 0))
        bind_caps_lock_warning(caps_entries, self.caps_label)
        self.status_label = status_label(body, wrap=FIELD_WIDTH)
        self.status_label.pack(fill="x")

        ctk.CTkButton(body, text="Create vault" if self.is_setup_mode else "Unlock",
                      command=self._perform_action,
                      **{**BTN_PRIMARY, "height": INPUT_HEIGHT, "width": FIELD_WIDTH}).pack(
            fill="x", pady=(8, 0))

        if not self.is_setup_mode:
            links = ctk.CTkFrame(body, fg_color="transparent")
            links.pack(pady=(12, 0))
            ctk.CTkButton(links, text="Forgot master password?", command=self._forgot_password_action,
                          **{**BTN_GHOST, "font": FONT_SMALL, "height": 28}).pack(side="left")
            if self._emergency_status() is not None:
                ctk.CTkLabel(links, text="·", font=FONT_SMALL, text_color=TEXT_MUTED).pack(
                    side="left", padx=2)
                ctk.CTkButton(links, text="Use emergency kit", command=self._emergency_recovery_action,
                              **{**BTN_GHOST, "font": FONT_SMALL, "height": 28}).pack(side="left")

        self.password_entry.focus()

    def _update_strength(self, event=None):
        pwd = self.password_entry.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_bar.configure(progress_color=BORDER)
            self.strength_text.configure(text="")
            return
        score, text, _ = check_password_strength(pwd)
        self.strength_bar.set((score + 1) / 5)
        color = STRENGTH_COLORS[max(0, min(score, 4))]
        self.strength_bar.configure(progress_color=color)
        self.strength_text.configure(text=text, text_color=color)

    def _set_status(self, message, color=DANGER):
        if hasattr(self, 'status_label') and self.status_label and self.status_label.winfo_exists():
            self.status_label.configure(text=message, text_color=color)

    def _lockout_message(self) -> str:
        wait = self.db.lockout_remaining()
        return f"Too many attempts. Try again in {wait}s." if wait else ""

    def _perform_action(self, event=None):
        self._set_status("")
        password = self.password_entry.get()
        if not password:
            self._set_status("Password cannot be empty.")
            return

        if self.is_setup_mode:
            if not hasattr(self, 'confirm_password_entry') or not self.confirm_password_entry.winfo_exists():
                return
            confirm = self.confirm_password_entry.get()
            if password != confirm:
                self._set_status("Passwords do not match.")
                return
            if len(password) < settings.MIN_MASTER_PASSWORD_LENGTH:
                self._set_status(f"Minimum {settings.MIN_MASTER_PASSWORD_LENGTH} characters.")
                return
            try:
                self.vault_key = self.db.create_vault(password)
                messagebox.showinfo("Next Step", "Master password set!\nNow set up security questions.",
                                    parent=self)
                self._open_security_questions_setup()
            except ValueError as ve:
                self._set_status(str(ve))
            except Exception:
                self._set_status("Error during setup.")
                logging.exception("Setup error.")
        else:
            if self._lockout_message():
                self._set_status(self._lockout_message())
                return
            try:
                vault_key = self.db.unlock_vault(password)
            except Exception:
                logging.exception("Unlock error.")
                self._set_status("Could not unlock the vault.")
                return
            if vault_key is None:
                self._set_status(self._lockout_message() or "Incorrect master password.")
                return
            self.vault_key = vault_key
            if not self.db.are_security_questions_set() or not self.db.has_recovery_key():
                # Vaults created before recovery keys existed need their questions saved again
                messagebox.showwarning("Setup Required",
                                       "Please set up security questions.\n"
                                       "They let you recover your vault if you forget the master password.",
                                       parent=self)
                self._open_security_questions_setup()
            else:
                self._login_successful(vault_key)

    def _open_security_questions_setup(self):
        self.withdraw()
        SecurityQuestionsSetupDialog(parent=self, db=self.db, vault_key=self.vault_key)

    def _security_questions_setup_done(self):
        if self.vault_key:
            messagebox.showinfo("Complete", "Setup complete. Opening vault.", parent=self.master)
            self._login_successful(self.vault_key)
        else:
            self.deiconify_and_focus()

    def _security_questions_setup_cancelled(self):
        # The vault is already created/unlocked; skipping questions just leaves recovery unavailable
        if self.vault_key:
            self._login_successful(self.vault_key)
        else:
            self.deiconify_and_focus()

    def _login_successful(self, vault_key: bytes):
        try:
            self.withdraw()
            main_app = MainWindow(master=self.master, db=self.db, encryption_key=vault_key)
            self._main_window_launched = True
            root = self.master

            def _on_main_destroy(event, win=main_app):
                if event.widget is win:
                    try:
                        root.quit()
                    except Exception:
                        pass

            main_app.bind("<Destroy>", _on_main_destroy, add="+")
            set_window_icon(main_app)
            main_app.focus()
            self.vault_key = None
            self.after(100, self.destroy)
        except Exception as e:
            logging.exception("Error launching main window.")
            self._main_window_launched = False
            messagebox.showerror("Error", f"Failed to launch:\n{e}", parent=self.master)
            if self.winfo_exists():
                self.destroy()

    def _forgot_password_action(self):
        if not self.db.are_security_questions_set():
            messagebox.showwarning("Not Available", "Security questions not set up.", parent=self)
            return
        if self._lockout_message():
            self._set_status(self._lockout_message())
            return
        PasswordRecoveryDialog(master=self.master, db=self.db,
                               success_callback=self._on_security_questions_verified)

    def _on_security_questions_verified(self, answers: List[str]):
        # None when the vault predates recovery keys; the reset dialog then offers a wipe
        vault_key = self.db.recover_vault_key(answers)
        ResetMasterPasswordDialog(master=self.master, db=self.db, vault_key=vault_key,
                                  success_callback=self._on_master_password_reset)

    def _emergency_status(self):
        try:
            return self.db.emergency_access_status()
        except Exception:
            logging.debug("emergency_access_status failed", exc_info=True)
            return None

    def _emergency_recovery_action(self):
        if self._emergency_status() is None:
            messagebox.showwarning("Not Available", "Emergency access is not set up.", parent=self)
            return
        if self._lockout_message():
            self._set_status(self._lockout_message())
            return
        EmergencyRecoveryDialog(master=self.master, db=self.db,
                                success_callback=self._on_emergency_recovered)

    def _on_emergency_recovered(self, vault_key: bytes):
        ResetMasterPasswordDialog(master=self.master, db=self.db, vault_key=vault_key,
                                  success_callback=self._on_master_password_reset)

    def _on_master_password_reset(self):
        messagebox.showinfo("Reset Complete", "Log in with your new password.", parent=self.master)
        self.deiconify_and_focus()
        self.password_entry.delete(0, ctk.END)
        self.is_setup_mode = False
        self.password_entry.focus()

    def deiconify_and_focus(self) -> None:
        """Re-shows this window (used by child dialogs when they close)."""
        try:
            if self.winfo_exists():
                self.deiconify()
                self.lift()
                self.focus()
        except Exception:
            pass

    def _on_closing(self):
        self.destroy()

    def destroy(self):
        root = self.master
        try:
            super().destroy()
        except Exception:
            pass
        if not getattr(self, '_main_window_launched', False):
            # Nothing else is visible; stop the hidden root's mainloop so the process exits
            try:
                root.quit()
            except Exception:
                pass

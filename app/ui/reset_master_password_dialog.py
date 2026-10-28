# password_manager/app/ui/reset_master_password_dialog.py
"""
Forgot-password flow, step 2: choose a new master password (or erase a legacy vault).
"""
import logging
from tkinter import messagebox
from typing import Callable, Optional

import customtkinter as ctk

from config import settings
from app.core.database import PasswordDatabase
from app.ui.theme import (DANGER, DANGER_SOFT, ACCENT_SOFT, TEXT_SECONDARY, FONT_SMALL,
                          BUTTON_RADIUS, BTN_DANGER)
from app.ui.widgets import (DIALOG_WIDTH, CARD_PAD, dialog_card, dialog_header, dialog_buttons,
                            labeled_field, password_entry, caps_label, status_label,
                            bind_caps_lock_warning, center_over, release_grab)

FIELD_WIDTH = DIALOG_WIDTH - 2 * CARD_PAD - 32


class ResetMasterPasswordDialog(ctk.CTkToplevel):
    """Sets a new master password; calls success_callback() when done."""

    def __init__(self, master, db: PasswordDatabase, vault_key: Optional[bytes],
                 success_callback: Callable[[], None]):
        super().__init__(master)
        self.db = db
        # None means the vault key could not be recovered, so resetting must erase the vault
        self.vault_key = vault_key
        self.success_callback = success_callback
        self.parent_window = master
        self.title("Reset Master Password")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.grab_set()
        self.lift()
        self.focus()
        self.after(1, self._create_widgets)
        self.after(50, lambda: center_over(self))

    def _create_widgets(self):
        main = dialog_card(self)
        dialog_header(main, "Set a new master password",
                      f"Use at least {settings.MIN_MASTER_PASSWORD_LENGTH} characters. "
                      "You'll use it to unlock your vault from now on.")

        # Notice banner: neutral when data is kept, danger when the vault must be erased
        if self.vault_key:
            notice = "Your stored passwords will be kept."
            bg, fg = ACCENT_SOFT, TEXT_SECONDARY
        else:
            notice = ("This vault was created before recovery keys existed. "
                      "Resetting will erase all stored passwords.")
            bg, fg = DANGER_SOFT, DANGER
        banner = ctk.CTkFrame(main, fg_color=bg, corner_radius=BUTTON_RADIUS)
        banner.pack(fill="x", pady=(10, 0))
        ctk.CTkLabel(banner, text=notice, font=FONT_SMALL, text_color=fg, wraplength=FIELD_WIDTH - 10,
                     justify="left", anchor="w").pack(fill="x", padx=12, pady=8)

        self.new_entry = labeled_field(main, "New master password",
                                       lambda p: password_entry(p, width=FIELD_WIDTH))
        self.confirm_entry = labeled_field(main, "Confirm new password",
                                           lambda p: password_entry(p, width=FIELD_WIDTH))

        self.caps_label = caps_label(main)
        self.caps_label.pack(fill="x", pady=(8, 0))
        bind_caps_lock_warning([self.new_entry, self.confirm_entry], self.caps_label)
        self.status_label = status_label(main)
        self.status_label.pack(fill="x")

        dialog_buttons(main, "Reset password" if self.vault_key else "Erase & reset",
                       self._reset_password, self._cancel,
                       primary_style=None if self.vault_key else BTN_DANGER)
        self.bind("<Escape>", lambda e: self._cancel())

        self.new_entry.focus()
        self.new_entry.bind("<Return>", lambda e: self.confirm_entry.focus())
        self.confirm_entry.bind("<Return>", lambda e: self._reset_password())

    def _set_status(self, msg, color=DANGER):
        if hasattr(self, 'status_label') and self.status_label.winfo_exists():
            self.status_label.configure(text=msg, text_color=color)

    def _reset_password(self):
        self._set_status("")
        new = self.new_entry.get()
        confirm = self.confirm_entry.get()
        if not new or not confirm:
            self._set_status("Both fields are required.")
            return
        if new != confirm:
            self._set_status("Passwords do not match.")
            return
        if len(new) < settings.MIN_MASTER_PASSWORD_LENGTH:
            self._set_status(f"Minimum {settings.MIN_MASTER_PASSWORD_LENGTH} characters.")
            return
        try:
            if self.vault_key:
                self.db.change_master_password(self.vault_key, new)
                messagebox.showinfo("Password Reset",
                                    "Master password has been reset.\nYour stored passwords are intact.",
                                    parent=self)
            else:
                if not messagebox.askyesno("Erase Vault?",
                                           "Your stored passwords cannot be recovered.\n\n"
                                           "Erase ALL stored passwords and start a new vault\n"
                                           "with this master password?",
                                           icon='warning', parent=self):
                    return
                self.db.wipe_vault()
                self.db.create_vault(new)
                messagebox.showwarning("Vault Erased",
                                       "A new, empty vault was created.\n"
                                       "You will set up security questions after logging in.",
                                       parent=self)
            release_grab(self)
            self.destroy()
            self.success_callback()
        except ValueError as ve:
            self._set_status(str(ve))
        except Exception as e:
            logging.exception("Failed to reset master password.")
            messagebox.showerror("Error", f"Could not reset:\n{e}", parent=self)

    def _cancel(self):
        release_grab(self)
        self.destroy()
        if hasattr(self.parent_window, 'deiconify_and_focus'):
            self.parent_window.deiconify_and_focus()
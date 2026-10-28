# password_manager/app/ui/lock_screen.py
"""
Auto-lock screen: blocks the vault until the master password is re-entered.
"""
import logging
from typing import Callable

import customtkinter as ctk

from app.core.database import PasswordDatabase
from app.ui.theme import BG, PAD_X, INPUT_HEIGHT, BTN_PRIMARY
from app.ui.widgets import (FIELD_WIDTH, brand_header, security_footer, labeled_field,
                            password_entry, caps_label, status_label, bind_caps_lock_warning,
                            center_over, release_grab)

LOCK_W, LOCK_H = 440, 520


class LockScreen(ctk.CTkToplevel):
    """Topmost unlock window; calls unlock_callback(vault_key) on success."""

    def __init__(self, master, db: PasswordDatabase, unlock_callback: Callable[[bytes], None]):
        super().__init__(master)
        self.db = db
        self.unlock_callback = unlock_callback

        self.title("Vault Locked")
        self.geometry(f"{LOCK_W}x{LOCK_H}")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        self.attributes("-topmost", True)

        self.after(100, self._build_ui)
        self.after(200, lambda: center_over(self))

    def _build_ui(self):
        security_footer(self)
        body = ctk.CTkFrame(self, fg_color="transparent", width=FIELD_WIDTH)
        body.pack(expand=True, padx=PAD_X)

        brand_header(body, "Vault locked", "Enter your master password to continue.")

        self.password_entry = labeled_field(body, "Master password",
                                            lambda p: password_entry(p, "Enter master password"),
                                            top_pad=0)
        self.password_entry.bind("<Return>", self._verify)

        self.caps_label = caps_label(body)
        self.caps_label.pack(fill="x", pady=(6, 0))
        bind_caps_lock_warning([self.password_entry], self.caps_label)
        self.status_label = status_label(body, wrap=FIELD_WIDTH)
        self.status_label.pack(fill="x")

        ctk.CTkButton(body, text="Unlock", command=self._verify,
                      **{**BTN_PRIMARY, "height": INPUT_HEIGHT, "width": FIELD_WIDTH}).pack(
            fill="x", pady=(8, 0))

        self.grab_set()
        self.password_entry.focus()

    def _verify(self, event=None):
        password = self.password_entry.get()
        if not password:
            self.status_label.configure(text="Password cannot be empty.")
            return
        wait = self.db.lockout_remaining()
        if wait:
            self.status_label.configure(text=f"Too many attempts. Try again in {wait}s.")
            return
        try:
            vault_key = self.db.unlock_vault(password)
        except Exception:
            logging.exception("Unlock error.")
            vault_key = None
        if vault_key:
            release_grab(self)
            self.destroy()
            self.unlock_callback(vault_key)
        else:
            wait = self.db.lockout_remaining()
            self.status_label.configure(text=f"Too many attempts. Try again in {wait}s." if wait else "Incorrect password.")
            self.password_entry.select_range(0, 'end')
            self.password_entry.focus()

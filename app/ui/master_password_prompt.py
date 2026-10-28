# password_manager/app/ui/master_password_prompt.py
"""
Small modal dialogs that ask for the master password (verify / change).
"""
from typing import List, Optional

import customtkinter as ctk

from config import settings
from app.ui.widgets import (DIALOG_WIDTH, CARD_PAD, dialog_card, dialog_header, labeled_field,
                            password_entry, caps_label, status_label, bind_caps_lock_warning,
                            dialog_buttons, center_over, release_grab)


class _MaskedFieldsDialog(ctk.CTkToplevel):
    """Modal dialog with one or more masked entries. get_input() returns the values or None."""

    def __init__(self, parent, title: str, heading: str, placeholders: List[str],
                 description: Optional[str] = None, action_text: str = "Continue"):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.result: Optional[List[str]] = None

        main = dialog_card(self)
        dialog_header(main, heading, description)

        self.entries = []
        for label in placeholders:
            entry = labeled_field(main, label,
                                  lambda p: password_entry(p, width=DIALOG_WIDTH - 2 * CARD_PAD - 32))
            entry.bind("<Return>", self._submit)
            self.entries.append(entry)

        self.caps_label = caps_label(main)
        self.caps_label.pack(fill="x", pady=(8, 0))
        bind_caps_lock_warning(self.entries, self.caps_label)
        self.status_label = status_label(main)
        self.status_label.pack(fill="x")

        dialog_buttons(main, action_text, self._submit, self._cancel)

        self.bind("<Escape>", lambda e: self._cancel())
        self.after(50, lambda: center_over(self, self.master))
        self.after(100, self._grab)

    def _grab(self):
        try:
            self.grab_set()
            self.entries[0].focus_force()
        except Exception:
            pass

    def _set_status(self, msg: str):
        self.status_label.configure(text=msg)

    def _validate(self, values: List[str]) -> Optional[str]:
        """Returns an error message, or None if the values are acceptable."""
        return None if values[0] else "Password cannot be empty."

    def _submit(self, event=None):
        values = [e.get() for e in self.entries]
        error = self._validate(values)
        if error:
            self._set_status(error)
            return
        self.result = values
        self._close()

    def _cancel(self):
        self.result = None
        self._close()

    def _close(self):
        release_grab(self)
        self.destroy()

    def get_input(self) -> Optional[List[str]]:
        """Blocks until the dialog closes; returns the entered values, or None if cancelled."""
        self.wait_window()
        return self.result


class MasterPasswordPrompt(_MaskedFieldsDialog):
    """Asks for the master password to confirm the user's identity."""

    def __init__(self, parent, heading: str = "Verify Identity"):
        super().__init__(parent, "Verify Identity", heading, ["Master password"],
                         description="Confirm your master password to continue.",
                         action_text="Confirm")

    def get_password(self) -> Optional[str]:
        """Blocks until closed; returns the entered password, or None if cancelled."""
        values = self.get_input()
        return values[0] if values else None


class ChangeMasterPasswordDialog(_MaskedFieldsDialog):
    """Returns [current, new] from get_input(); the new password is length- and match-checked."""

    def __init__(self, parent):
        super().__init__(parent, "Change Master Password", "Change master password",
                         ["Current master password", "New master password", "Confirm new password"],
                         description=(f"Use at least {settings.MIN_MASTER_PASSWORD_LENGTH} characters. "
                                      "Your stored passwords stay encrypted and intact."),
                         action_text="Change password")

    def _validate(self, values: List[str]) -> Optional[str]:
        current, new, confirm = values
        if not current or not new:
            return "All fields are required."
        if new != confirm:
            return "New passwords do not match."
        if len(new) < settings.MIN_MASTER_PASSWORD_LENGTH:
            return f"Minimum {settings.MIN_MASTER_PASSWORD_LENGTH} characters."
        if new == current:
            return "New password must differ from the current one."
        return None

    def _submit(self, event=None):
        super()._submit(event)
        if self.result:
            self.result = self.result[:2]

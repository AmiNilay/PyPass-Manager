# password_manager/app/ui/password_recovery_dialog.py
"""
Forgot-password flow, step 1: verify the user's security-question answers.
"""
import logging
from tkinter import messagebox
from typing import Any, Callable, Dict, List

import customtkinter as ctk

from config import settings
from app.core.database import PasswordDatabase
from app.ui.theme import TEXT_PRIMARY, FONT_BODY, ENTRY_STYLE
from app.ui.widgets import (dialog_card, dialog_header, dialog_buttons, caption_label,
                            status_label, center_over, release_grab)

RECOVERY_WRAP = 380   # content width inside the recovery card


class PasswordRecoveryDialog(ctk.CTkToplevel):
    """Asks every security question; calls success_callback(answers) once all are correct."""

    def __init__(self, master, db: PasswordDatabase, success_callback: Callable[[List[str]], None]):
        super().__init__(master)
        self.db = db
        self.success_callback = success_callback
        self.parent_window = master
        self.title("Password Recovery")
        self.lift()
        self.attributes("-topmost", True)
        self.protocol("WM_DELETE_WINDOW", self._cancel_recovery)
        self.resizable(False, False)
        self.stored_questions: List[Dict[str, Any]] = []
        self.answer_entries: List[ctk.CTkEntry] = []
        self._load_questions_and_setup_ui()
        self.after(50, lambda: center_over(self))
        self.after(100, self._grab_focus)

    def _grab_focus(self):
        try:
            self.focus_force()
            self.grab_set()
        except Exception as e:
            logging.warning(f"RecoveryDialog grab error: {e}")

    def _load_questions_and_setup_ui(self):
        self.stored_questions = self.db.get_security_questions()
        num = min(len(self.stored_questions), settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET)
        if num < settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET:
            logging.error(f"Only {num} questions found, expected {settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET}.")
            messagebox.showerror("Recovery Error",
                                 f"Not enough security questions ({num}/{settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET}).",
                                 parent=self.parent_window)
            self.after(10, self._close_and_notify)
            return
        self._create_widgets(num)

    def _create_widgets(self, num_questions):
        main = dialog_card(self)
        dialog_header(main, "Recover your vault",
                      "Answer your security questions to set a new master password. "
                      "Capitalisation and extra spaces don't matter.", wrap=RECOVERY_WRAP)

        for i in range(num_questions):
            q = self.stored_questions[i]
            caption_label(main, f"Question {i + 1}").pack(fill="x", pady=(14, 2))
            ctk.CTkLabel(main, text=q['question_text'], wraplength=RECOVERY_WRAP, justify="left",
                         anchor="w", font=FONT_BODY, text_color=TEXT_PRIMARY).pack(fill="x", pady=(0, 6))
            entry = ctk.CTkEntry(main, placeholder_text="Your answer",
                                 **{**ENTRY_STYLE, "width": RECOVERY_WRAP})
            entry.pack(fill="x")
            self.answer_entries.append(entry)
            if i == 0:
                entry.focus()
            if i == num_questions - 1:
                entry.bind("<Return>", lambda e: self._verify_answers())
            else:
                entry.bind("<Return>", lambda e, idx=i: self.answer_entries[idx + 1].focus())

        self.status_label = status_label(main, wrap=RECOVERY_WRAP)
        self.status_label.pack(fill="x", pady=(10, 0))
        dialog_buttons(main, "Verify answers", self._verify_answers, self._cancel_recovery)
        self.bind("<Escape>", lambda e: self._cancel_recovery())

    def _verify_answers(self):
        wait = self.db.lockout_remaining()
        if wait:
            messagebox.showerror("Locked", f"Too many attempts. Try again in {wait}s.", parent=self)
            self._close_and_notify()
            return
        # stored_questions/answer_entries share get_security_questions() order,
        # which is the order recover_vault_key() expects
        for i, entry in enumerate(self.answer_entries):
            answer = entry.get().strip()
            q = self.stored_questions[i]
            if not answer:
                self.status_label.configure(text=f"Please answer question {i + 1}.")
                entry.focus()
                return
            if not self.db.verify_security_answer(q['id'], answer):
                wait = self.db.lockout_remaining()
                if wait:
                    messagebox.showerror("Locked", f"Too many attempts. Try again in {wait}s.", parent=self)
                    self._close_and_notify()
                    return
                self.status_label.configure(text=f"The answer to question {i + 1} is incorrect.")
                entry.select_range(0, 'end')
                entry.focus()
                return
        answers = [entry.get().strip() for entry in self.answer_entries]
        messagebox.showinfo("Verified", "All answers correct!\nYou can now reset your password.", parent=self)
        self._close_dialog()
        self.success_callback(answers)

    def _close_and_notify(self):
        release_grab(self)
        self.destroy()
        if hasattr(self.parent_window, 'deiconify_and_focus'):
            self.parent_window.deiconify_and_focus()

    def _cancel_recovery(self):
        self._close_and_notify()

    def _close_dialog(self):
        release_grab(self)
        try:
            self.destroy()
        except Exception:
            pass
# password_manager/app/ui/security_questions_setup_dialog.py
"""
Dialog for choosing and answering the security questions used for vault recovery.
"""
import logging
from tkinter import messagebox

import customtkinter as ctk

from config import settings
from app.core.database import PasswordDatabase
from app.ui.theme import (SURFACE_ACTIVE, BORDER_STRONG, TEXT_PRIMARY, INPUT_BG, FONT_BODY,
                          BUTTON_RADIUS, INPUT_HEIGHT, ENTRY_STYLE)
from app.ui.widgets import (dialog_card, dialog_header, dialog_buttons, caption_label,
                            status_label, center_over, release_grab)

SQ_WIDTH = 420                      # content width inside the card
PLACEHOLDER_Q = "Select a question..."


class SecurityQuestionsSetupDialog(ctk.CTkToplevel):
    """Saves security questions; notifies the parent via _security_questions_setup_done/_cancelled."""

    def __init__(self, parent, db: PasswordDatabase, vault_key: bytes):
        super().__init__(parent)
        self.db = db
        self.vault_key = vault_key
        self.parent_window = parent
        # Replacing existing questions: closing without saving keeps the old ones
        try:
            self.replacing_existing = bool(self.db.are_security_questions_set())
        except Exception:
            self.replacing_existing = False
        # A transient of a withdrawn window is hidden too (LoginWindow withdraws itself first)
        try:
            if parent is not None and parent.winfo_viewable():
                self.transient(parent)
        except Exception:
            pass
        self.title("Security Questions Setup")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_closing_warning)
        self.grab_set()
        self.lift()
        self.focus()
        self.questions_widgets = []
        self.setup_complete = False
        self.after(1, self._create_widgets)
        self.after(50, lambda: center_over(self, self.master))

    def _on_closing_warning(self):
        if not self.setup_complete:
            if self.replacing_existing:
                confirmed = messagebox.askyesno("Discard Changes",
                                                "Close without saving?\n"
                                                "Your existing security questions will be kept.",
                                                parent=self)
            else:
                confirmed = messagebox.askyesno("Confirm Close",
                                                "Security questions not saved. Close anyway?\n"
                                                "You won't be able to recover your password.",
                                                icon='warning', parent=self)
            if confirmed:
                release_grab(self)
                self.destroy()
                if hasattr(self.parent_window, '_security_questions_setup_cancelled'):
                    self.parent_window._security_questions_setup_cancelled()
        else:
            release_grab(self)
            self.destroy()

    def _create_widgets(self):
        main = dialog_card(self)
        n = settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET
        dialog_header(main, "Set up account recovery",
                      f"Choose and answer {n} security questions. If you forget your master "
                      "password, these let you regain access. Capitalisation and extra spaces "
                      "don't matter.", wrap=SQ_WIDTH)

        question_options = [PLACEHOLDER_Q] + settings.PREDEFINED_SECURITY_QUESTIONS

        for i in range(n):
            caption_label(main, f"Question {i + 1}").pack(fill="x", pady=(14, 6))
            q_var = ctk.StringVar(value=question_options[0])
            q_menu = ctk.CTkOptionMenu(main, variable=q_var, values=question_options,
                                       width=SQ_WIDTH, height=INPUT_HEIGHT, font=FONT_BODY,
                                       dropdown_font=FONT_BODY, fg_color=INPUT_BG,
                                       button_color=SURFACE_ACTIVE, button_hover_color=BORDER_STRONG,
                                       text_color=TEXT_PRIMARY, corner_radius=BUTTON_RADIUS,
                                       dynamic_resizing=False)
            q_menu.pack(fill="x")
            ans_entry = ctk.CTkEntry(main, placeholder_text="Your answer (min. 4 characters)",
                                     **{**ENTRY_STYLE, "width": SQ_WIDTH})
            ans_entry.pack(fill="x", pady=(8, 0))
            self.questions_widgets.append((q_var, ans_entry, q_menu))

        self.status_label = status_label(main, wrap=SQ_WIDTH)
        self.status_label.pack(fill="x", pady=(10, 0))
        dialog_buttons(main, "Save questions", self._save_questions, self._on_closing_warning,
                       cancel_text="Skip" if not self.replacing_existing else "Cancel")

    def _save_questions(self):
        questions_data = []
        selected = set()
        self.status_label.configure(text="")
        for q_var, ans_entry, q_menu in self.questions_widgets:
            q_text = q_var.get()
            ans_text = ans_entry.get().strip()
            if q_text == PLACEHOLDER_Q:
                self.status_label.configure(text="Please select a question for every slot.")
                q_menu.focus()
                return
            if not ans_text:
                self.status_label.configure(text="Please provide an answer for every question.")
                ans_entry.focus()
                return
            if len(ans_text) < 4:
                self.status_label.configure(text="Answers must be at least 4 characters.")
                ans_entry.focus()
                return
            if q_text in selected:
                self.status_label.configure(text="Each question can only be used once.")
                q_menu.focus()
                return
            selected.add(q_text)
            questions_data.append({"question_text": q_text, "answer": ans_text})
        try:
            self.db.set_security_questions(questions_data, self.vault_key)
            self.setup_complete = True
            messagebox.showinfo("Saved", "Security questions saved!", parent=self)
            release_grab(self)
            self.destroy()
            if hasattr(self.parent_window, '_security_questions_setup_done'):
                self.parent_window._security_questions_setup_done()
        except Exception as e:
            logging.exception("Failed to save security questions.")
            messagebox.showerror("Error", f"Could not save:\n{e}", parent=self)
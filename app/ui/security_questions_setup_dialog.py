# password_manager/app/ui/security_questions_setup_dialog.py
import customtkinter as ctk
from tkinter import messagebox
import logging

from config import settings
from app.core.database import PasswordDatabase # To interact with DB


class SecurityQuestionsSetupDialog(ctk.CTkToplevel):
    """
    A dialog for users to set up their security questions and answers
    after initial master password setup.
    """
    def __init__(self, parent, db: PasswordDatabase):
        super().__init__(parent)
        self.db = db
        self.parent_window = parent # Keep a reference to the parent (LoginWindow)

        self.title("Set Up Security Questions")
        # Adjust geometry based on number of questions
        num_questions = settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET
        dialog_height = 200 + (num_questions * 75) # Base height + per question
        self.geometry(f"550x{dialog_height}")
        self.resizable(False, False)

        self.protocol("WM_DELETE_WINDOW", self._on_closing_warning) # Warn if closed prematurely
        self.grab_set() # Make modal
        self.lift()     # Bring to front
        self.focus()

        self.questions_widgets = [] # To store (option_menu, answer_entry) tuples
        self.setup_complete = False # Flag to indicate successful setup

        self._create_widgets()
        self.after(50, self._center_dialog)

    def _center_dialog(self):
        try:
            self.update_idletasks()
            parent_x = self.master.winfo_x()
            parent_y = self.master.winfo_y()
            parent_w = self.master.winfo_width()
            parent_h = self.master.winfo_height()
            win_w = self.winfo_width()
            win_h = self.winfo_height()
            x = max(0, parent_x + (parent_w // 2) - (win_w // 2))
            y = max(0, parent_y + (parent_h // 2) - (win_h // 2))
            self.geometry(f"+{x}+{y}")
        except Exception as e:
            logging.warning(f"SQDialog: Could not center dialog: {e}")

    def _on_closing_warning(self):
        """Warn user if they try to close without saving."""
        if not self.setup_complete:
            if messagebox.askyesno("Confirm Close",
                                   "Security questions are not saved. Are you sure you want to close?\n"
                                   "You will not be able to use password recovery without them.",
                                   icon='warning', parent=self):
                self.grab_release()
                self.destroy()
            else:
                return # Do not close
        else:
            self.grab_release()
            self.destroy()


    def _create_widgets(self):
        """Creates the UI elements for the dialog."""
        self.grid_columnconfigure(0, weight=1)

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        main_frame.grid_columnconfigure(1, weight=1) # Allow entry fields to expand

        instruction_label = ctk.CTkLabel(main_frame,
                                         text=f"Please select and answer {settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET} security questions.\n"
                                              "These will be used to recover your master password if you forget it.\n"
                                              "Answers are case-sensitive.",
                                         wraplength=500, justify="left")
        instruction_label.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 15), sticky="ew")

        # Create question/answer sections
        for i in range(settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET):
            q_label_text = f"Question {i+1}:"
            q_label = ctk.CTkLabel(main_frame, text=q_label_text)
            q_label.grid(row=i*2 + 1, column=0, padx=10, pady=(10,0), sticky="w")

            # Filter out already selected questions for subsequent dropdowns
            # This is a bit complex for dynamic dropdowns, so for now, we allow re-selection
            # but will validate for uniqueness on save.
            question_options = ["Select a question..."] + settings.PREDEFINED_SECURITY_QUESTIONS
            question_var = ctk.StringVar(value=question_options[0])
            question_menu = ctk.CTkOptionMenu(main_frame, variable=question_var, values=question_options, width=400)
            question_menu.grid(row=i*2 + 1, column=1, padx=10, pady=(10,0), sticky="ew")

            ans_label_text = f"Answer {i+1}:"
            ans_label = ctk.CTkLabel(main_frame, text=ans_label_text)
            ans_label.grid(row=i*2 + 2, column=0, padx=10, pady=(0,10), sticky="w")

            answer_entry = ctk.CTkEntry(main_frame, width=400)
            answer_entry.grid(row=i*2 + 2, column=1, padx=10, pady=(0,10), sticky="ew")

            self.questions_widgets.append((question_var, answer_entry, question_menu)) # Store var and menu

        # Save Button
        save_button = ctk.CTkButton(main_frame, text="Save Security Questions", command=self._save_questions)
        save_button.grid(row=settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET * 2 + 1, column=0, columnspan=2, pady=(20, 10))


    def _save_questions(self):
        """Validates and saves the security questions and answers."""
        questions_data = []
        selected_questions_texts = set()

        for q_var, ans_entry, q_menu in self.questions_widgets:
            question_text = q_var.get()
            answer_text = ans_entry.get().strip() # Strip whitespace from answer

            if question_text == "Select a question...":
                messagebox.showerror("Validation Error", "Please select a question for all entries.", parent=self)
                q_menu.focus()
                return
            if not answer_text:
                messagebox.showerror("Validation Error", "Please provide an answer for all selected questions.", parent=self)
                ans_entry.focus()
                return
            if len(answer_text) < 4: # Arbitrary minimum answer length
                messagebox.showerror("Validation Error", "Answers must be at least 4 characters long.", parent=self)
                ans_entry.focus()
                return
            if question_text in selected_questions_texts:
                messagebox.showerror("Validation Error", "Please select unique questions. Each question can only be used once.", parent=self)
                q_menu.focus()
                return

            selected_questions_texts.add(question_text)
            questions_data.append({"question_text": question_text, "answer": answer_text})

        if len(questions_data) != settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET:
            # This case should be caught by "Select a question..." check, but as a safeguard:
            messagebox.showerror("Validation Error", f"Please set up all {settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET} questions.", parent=self)
            return

        # If validation passes, save to DB
        try:
            # Clear any old questions first (in case of re-setup, though this dialog is for initial setup)
            # self.db.clear_security_questions() # Maybe not here, as this is initial setup
            for item in questions_data:
                self.db.set_security_question(item["question_text"], item["answer"])
            
            self.setup_complete = True # Mark setup as complete
            messagebox.showinfo("Setup Complete", "Security questions saved successfully!", parent=self)
            self.grab_release()
            self.destroy() # Close dialog on success
            # Optionally, notify the parent (LoginWindow) to proceed
            if hasattr(self.parent_window, '_security_questions_setup_done'):
                self.parent_window._security_questions_setup_done()

        except Exception as e:
            logging.exception("Failed to save security questions to DB.")
            messagebox.showerror("Database Error", f"Could not save security questions:\n{e}", parent=self)
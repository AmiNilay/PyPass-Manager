# password_manager/app/ui/password_recovery_dialog.py
import customtkinter as ctk
from tkinter import messagebox
import logging
from typing import List, Dict, Any, Callable # Import Callable

from config import settings # For NUMBER_OF_SECURITY_QUESTIONS_TO_SET
from app.core.database import PasswordDatabase

class PasswordRecoveryDialog(ctk.CTkToplevel):
    """
    Dialog to guide the user through answering their security questions
    for master password recovery.
    """
    def __init__(self, master, db: PasswordDatabase, success_callback: Callable):
        super().__init__(master)
        self.db = db
        self.success_callback = success_callback # To call when questions are verified
        self.parent_window = master # This is the hidden_root from main.py

        self.title("Password Recovery - Security Questions")
        # Modal behavior relative to the hidden root.
        # grab_set will be called after widgets are created to avoid issues.
        self.lift()
        self.attributes("-topmost", True) # Try to keep on top

        self.protocol("WM_DELETE_WINDOW", self._cancel_recovery)

        self.stored_questions: List[Dict[str, Any]] = []
        self.answer_entries: List[ctk.CTkEntry] = []

        self._load_questions_and_setup_ui() # This also sets geometry
        self.after(50, self._center_dialog_on_screen) # Center on screen
        self.after(100, self._grab_focus_and_set) # Delay grab_set

    def _grab_focus_and_set(self):
        """Safely attempt to grab focus and set grab."""
        try:
            self.focus_force()
            self.grab_set()
            logging.debug("RecoveryDialog: Grab set successfully.")
        except Exception as e:
            logging.warning(f"RecoveryDialog: Error setting grab/focus: {e}")


    def _center_dialog_on_screen(self):
        try:
            self.update_idletasks()
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            win_w = self.winfo_width()
            win_h = self.winfo_height()
            x = (screen_width // 2) - (win_w // 2)
            y = (screen_height // 2) - (win_h // 2)
            self.geometry(f"+{x}+{y}")
        except Exception as e:
            logging.warning(f"RecoveryDialog: Could not center: {e}")

    def _load_questions_and_setup_ui(self):
        self.stored_questions = self.db.get_security_questions()

        # Ensure we use the correct number of questions that are actually stored,
        # up to the configured number.
        num_questions_to_ask = min(len(self.stored_questions), settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET)

        if num_questions_to_ask < settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET:
            # This case implies incomplete setup or data issue.
            logging.error(f"Recovery Error: Only {num_questions_to_ask} questions found, expected {settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET}.")
            messagebox.showerror("Recovery Error",
                                 f"Not enough security questions found ({num_questions_to_ask}/{settings.NUMBER_OF_SECURITY_QUESTIONS_TO_SET}).\n"
                                 "Recovery is not possible. You may need to reset if this persists.",
                                 parent=self.parent_window) # Show relative to hidden_root/main app context
            self.after(10, self._close_and_notify_parent) # Close self and notify LoginWindow
            return

        # Dynamically adjust height
        dialog_height = 150 + (num_questions_to_ask * 65)
        self.geometry(f"500x{dialog_height}")
        self._create_widgets(num_questions_to_ask)

    def _create_widgets(self, num_questions_to_ask: int):
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        main_frame.grid_columnconfigure(1, weight=1)

        instruction = ctk.CTkLabel(main_frame, text="Please answer your security questions:", wraplength=450)
        instruction.grid(row=0, column=0, columnspan=2, pady=(0, 15), sticky="ew")

        # Only display the number of questions that were successfully set up
        for i in range(num_questions_to_ask):
            q_data = self.stored_questions[i] # Get question from the loaded list
            q_text = q_data['question_text']
            
            q_label = ctk.CTkLabel(main_frame, text=f"Q{i+1}: {q_text}", wraplength=420, justify="left")
            q_label.grid(row=i*2 + 1, column=0, columnspan=2, padx=5, pady=(10,0), sticky="w")

            ans_entry = ctk.CTkEntry(main_frame, width=400)
            ans_entry.grid(row=i*2 + 2, column=0, columnspan=2, padx=5, pady=(0,10), sticky="ew")
            self.answer_entries.append(ans_entry)
            if i == 0: ans_entry.focus() # Focus first answer field

        submit_button = ctk.CTkButton(main_frame, text="Submit Answers", command=self._verify_answers)
        submit_button.grid(row=num_questions_to_ask*2 + 1, column=0, columnspan=2, pady=(20,0))

    def _verify_answers(self):
        logging.debug("RecoveryDialog: Verifying answers.")
        all_correct = True
        # Iterate based on the number of questions displayed (and entries created)
        for i in range(len(self.answer_entries)):
            q_data = self.stored_questions[i]
            question_id = q_data['id']
            provided_answer = self.answer_entries[i].get().strip()

            if not provided_answer:
                messagebox.showwarning("Missing Answer", f"Please provide an answer for Question {i+1}.", parent=self)
                self.answer_entries[i].focus()
                all_correct = False
                break

            if not self.db.verify_security_answer(question_id, provided_answer):
                messagebox.showerror("Verification Failed", f"Answer for Question {i+1} is incorrect.", parent=self)
                self.answer_entries[i].focus()
                self.answer_entries[i].selection_range(0, 'end')
                all_correct = False
                break
        
        if all_correct:
            logging.info("All security questions verified successfully.")
            messagebox.showinfo("Success", "Security questions verified!\nYou can now reset your master password.", parent=self)
            self._close_dialog() # Close self first
            self.success_callback() # Then call success to open next dialog
        else:
            logging.warning("One or more security answers were incorrect.")

    def _close_and_notify_parent(self):
        """Closes this dialog and notifies the parent (LoginWindow) to re-show itself."""
        self.grab_release()
        self.destroy()
        # Notify LoginWindow to re-appear if it's expecting it
        if hasattr(self.parent_window, 'deiconify_and_focus'): # parent_window is actually LoginWindow
            self.parent_window.deiconify_and_focus()


    def _cancel_recovery(self):
        logging.debug("RecoveryDialog: Recovery cancelled by user.")
        self._close_and_notify_parent()


    def _close_dialog(self):
        """Helper method to release grab and destroy the dialog."""
        logging.debug("RecoveryDialog: Closing dialog (_close_dialog)")
        try: self.grab_release()
        except Exception as e: logging.warning(f"RecoveryDialog: Error releasing grab: {e}")
        try: self.destroy()
        except Exception as e: logging.warning(f"RecoveryDialog: Error destroying: {e}")

# End of file password_manager/app/ui/password_recovery_dialog.py
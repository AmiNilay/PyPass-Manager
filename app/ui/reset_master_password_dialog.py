# password_manager/app/ui/reset_master_password_dialog.py
import customtkinter as ctk
from tkinter import messagebox
import logging
from typing import Callable # Import Callable

from config import settings
from app.core.database import PasswordDatabase # Assuming you need db to set new master password

class ResetMasterPasswordDialog(ctk.CTkToplevel):
    """
    Dialog to allow the user to set a new master password after
    successful security question verification.
    """
    def __init__(self, master, db: PasswordDatabase, success_callback: Callable):
        super().__init__(master)
        self.db = db
        self.success_callback = success_callback # To notify LoginWindow on success
        self.parent_window = master # This should be the hidden_root from main.py

        self.title("Reset Master Password")
        self.geometry("400x330") # Adjusted size for content
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cancel_reset) # Handle X button
        self.grab_set() # Make modal
        self.lift()     # Bring to front
        self.focus()

        self._create_widgets()
        self.after(50, self._center_dialog)

    def _center_dialog(self):
        try:
            self.update_idletasks()
            # Center relative to the screen if master is hidden_root or not a visible window
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            win_w = self.winfo_width()
            win_h = self.winfo_height()
            x = (screen_width // 2) - (win_w // 2)
            y = (screen_height // 2) - (win_h // 2)
            self.geometry(f"+{x}+{y}")
        except Exception as e:
            logging.warning(f"ResetPassDialog: Could not center: {e}")

    def _create_widgets(self):
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        main_frame.grid_columnconfigure(0, weight=1)

        info_label = ctk.CTkLabel(main_frame,
                                  text="Enter your new master password below.\n"
                                       "WARNING: This will make all previously stored\n"
                                       "passwords unreadable!",
                                  wraplength=350, justify="center", text_color="orange") # Warning color
        info_label.grid(row=0, column=0, padx=10, pady=(0, 15), sticky="ew")

        self.new_password_entry = ctk.CTkEntry(main_frame, placeholder_text="New Master Password", show="*", width=280)
        self.new_password_entry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.confirm_password_entry = ctk.CTkEntry(main_frame, placeholder_text="Confirm New Password", show="*", width=280)
        self.confirm_password_entry.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.status_label = ctk.CTkLabel(main_frame, text="", text_color="red")
        self.status_label.grid(row=3, column=0, padx=10, pady=(5,0), sticky="ew")

        reset_button = ctk.CTkButton(main_frame, text="Set New Master Password", command=self._reset_password)
        reset_button.grid(row=4, column=0, padx=10, pady=(15,10))

        self.new_password_entry.focus()
        # Bind enter key
        self.new_password_entry.bind("<Return>", lambda e: self.confirm_password_entry.focus())
        self.confirm_password_entry.bind("<Return>", lambda e: self._reset_password())

    def _set_status(self, message: str, color: str = "red"):
        if hasattr(self, 'status_label') and self.status_label.winfo_exists():
            self.status_label.configure(text=message, text_color=color)

    def _reset_password(self):
        self._set_status("")
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not new_password or not confirm_password:
            self._set_status("Both password fields are required.")
            return
        if new_password != confirm_password:
            self._set_status("New passwords do not match.")
            return
        if len(new_password) < settings.MIN_MASTER_PASSWORD_LENGTH:
            self._set_status(f"Password must be at least {settings.MIN_MASTER_PASSWORD_LENGTH} characters.")
            return

        try:
            # Setting a new master password also clears old salts and security questions.
            self.db.set_master_password(new_password)
            logging.info("Master password has been successfully reset.")

            # IMPORTANT WARNING to the user
            messagebox.showwarning("Password Reset Successful",
                                  "Your master password has been reset.\n\n"
                                  "CRITICAL: All previously stored credential passwords are\n"
                                  "now ENCRYPTED WITH THE NEW KEY and cannot be read\n"
                                  "using the old master password. Any existing password entries\n"
                                  "will effectively need to be re-entered or updated.\n\n"
                                  "You will also need to set up new security questions after logging in.",
                                  parent=self) # Show relative to this dialog
            
            self.grab_release()
            self.destroy()
            self.success_callback() # Notify the LoginWindow to refresh/re-show

        except ValueError as ve:
            self._set_status(str(ve))
            logging.error(f"ValueError during password reset: {ve}")
        except Exception as e:
            logging.exception("Failed to reset master password.")
            messagebox.showerror("Error", f"Could not reset master password:\n{e}", parent=self)

    def _cancel_reset(self):
        logging.debug("ResetPassDialog: Reset cancelled by user.")
        self.grab_release()
        self.destroy()
        # Notify parent (LoginWindow) that reset was cancelled so it can re-appear
        if hasattr(self.parent_window, 'deiconify_and_focus'):
            self.parent_window.deiconify_and_focus()

# End of file password_manager/app/ui/reset_master_password_dialog.py
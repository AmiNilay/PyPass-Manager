# password_manager/app/ui/password_generator.py
import customtkinter as ctk
from tkinter import messagebox
import pyperclip
import logging
import os
from PIL import Image

# Local imports (Remove Gemini imports)
from config import settings # Keep settings for icons
from app.core.password_utils import generate_local_password
# Remove: from app.gemini.gemini_api import GeminiClient, GeminiAPIError

# --- Icon Loader Helper ---
# (Keep the load_icon function)
def load_icon(file_path, size=(20, 20)):
    if not os.path.exists(file_path): return None
    try:
        img = Image.open(file_path);
        if img.mode not in ['RGB', 'RGBA']: img = img.convert('RGBA')
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception as e: logging.error(f"Failed to load icon {file_path}: {e}"); return None

class PasswordGeneratorWindow(ctk.CTkToplevel):
    """A window for generating passwords locally."""

    def __init__(self, parent):
        super().__init__(parent)
        logging.debug("PasswordGenerator: Initializing.")

        self.title("Password Generator")
        # Adjusted size as Analysis section is removed
        self.geometry("550x350") # Reduced height
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._close_dialog)

        # Load only needed icons
        icon_size_small = (16, 16)
        icon_size_medium = (18, 18)
        self.copy_icon = load_icon(settings.COPY_ICON_FILE, size=icon_size_small)
        self.local_gen_icon = load_icon(settings.LOCAL_GEN_ICON_FILE, size=icon_size_medium)
        # Removed: self.gemini_gen_icon, self.analyze_icon

        # Removed: self.gemini_client = GeminiClient()

        # Defer widget creation
        self.after(1, self._setup_ui)
        logging.debug("PasswordGenerator: __init__ finished (widgets pending).")

    def _setup_ui(self):
        """Creates and lays out the UI elements."""
        logging.debug("PasswordGenerator: Setting up UI.")
        try:
            self.grid_columnconfigure(0, weight=1)
            # Removed rowconfigure for analysis box

            # --- Generation Section ---
            gen_frame = ctk.CTkFrame(self)
            # Span full width now, adjust row/column if needed, pack is simpler here
            # gen_frame.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
            gen_frame.pack(padx=15, pady=15, fill="x", expand=False)
            gen_frame.grid_columnconfigure(1, weight=1) # For slider

            ctk.CTkLabel(gen_frame, text="Password Generation", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, columnspan=3, pady=(5, 10))

            # Length
            ctk.CTkLabel(gen_frame, text="Length:").grid(row=1, column=0, padx=(10, 5), pady=5, sticky="w")
            self.length_var = ctk.IntVar(value=16)
            self.length_slider = ctk.CTkSlider(gen_frame, from_=8, to=64, number_of_steps=56, variable=self.length_var, command=self._update_length_label)
            self.length_slider.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
            self.length_label = ctk.CTkLabel(gen_frame, text="16", width=30)
            self.length_label.grid(row=1, column=2, padx=(5, 10), pady=5, sticky="e")

            # Options
            options_frame = ctk.CTkFrame(gen_frame, fg_color="transparent")
            options_frame.grid(row=2, column=0, columnspan=3, pady=5)
            self.uppercase_var = ctk.BooleanVar(value=True)
            self.digits_var = ctk.BooleanVar(value=True)
            self.symbols_var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(options_frame, text="Uppercase (A-Z)", variable=self.uppercase_var).pack(side="left", padx=10)
            ctk.CTkCheckBox(options_frame, text="Digits (0-9)", variable=self.digits_var).pack(side="left", padx=10)
            ctk.CTkCheckBox(options_frame, text="Symbols (!@#...)", variable=self.symbols_var).pack(side="left", padx=10)

            # Result Entry and Buttons
            result_frame = ctk.CTkFrame(gen_frame, fg_color="transparent")
            result_frame.grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
            result_frame.grid_columnconfigure(0, weight=1)

            self.generated_password_entry = ctk.CTkEntry(result_frame, font=ctk.CTkFont(family="Courier", size=12), width=300)
            self.generated_password_entry.grid(row=0, column=0, padx=(10, 5), sticky="ew")

            self.copy_button = ctk.CTkButton(result_frame, text="", image=self.copy_icon, width=30, height=30, command=self._copy_generated_password)
            self.copy_button.grid(row=0, column=1, padx=(0, 10))

            # Generation Buttons Frame
            button_frame = ctk.CTkFrame(gen_frame, fg_color="transparent")
            button_frame.grid(row=4, column=0, columnspan=3, pady=(5, 15)) # Increased bottom padding

            # ONLY Local Generate Button
            self.generate_local_button = ctk.CTkButton(button_frame, text="Generate Password", image=self.local_gen_icon, command=self._generate_local)
            self.generate_local_button.pack(side="left", padx=10)

            # REMOVED Gemini Button
            # self.generate_gemini_button = ctk.CTkButton(...)

            # REMOVED Analysis Section Frame
            # analysis_frame = ctk.CTkFrame(self) ...

            # REMOVED Analysis Result Box
            # self.analysis_result_box = ctk.CTkTextbox(...) ...

            # Center window after widgets are created
            self.after(50, self._center_window)
            logging.debug("PasswordGenerator: UI setup complete.")

        except Exception as e:
            logging.exception("PasswordGenerator: FAILED UI creation")
            try: messagebox.showerror("Generator Error", f"Failed create UI:\n{e}", parent=self)
            except: pass
            self.after(10, self.destroy)

    def _center_window(self):
         logging.debug("PasswordGenerator: Centering window.")
         try:
             self.update_idletasks(); master = self.master
             if not master: return
             master_x = master.winfo_x(); master_y = master.winfo_y(); master_w = master.winfo_width(); master_h = master.winfo_height()
             win_w = self.winfo_width(); win_h = self.winfo_height(); x = max(0, master_x + (master_w // 2) - (win_w // 2)); y = max(0, master_y + (master_h // 2) - (win_h // 2))
             self.geometry(f"+{x}+{y}")
         except Exception as e: logging.warning(f"Could not center generator: {e}")

    def _update_length_label(self, value): self.length_label.configure(text=str(int(value)))
    def _set_generated_password(self, password: str): self.generated_password_entry.delete(0, "end"); self.generated_password_entry.insert(0, password)
    def _copy_generated_password(self):
        password = self.generated_password_entry.get()
        if password:
            try: pyperclip.copy(password); logging.info("Generated password copied."); original_fg = self.copy_button.cget("fg_color"); self.copy_button.configure(text="Copied!", image=None, fg_color="green"); self.after(2000, lambda: self.copy_button.configure(text="", image=self.copy_icon, fg_color=original_fg))
            except Exception as e: logging.error(f"Failed copy gen pass: {e}"); messagebox.showwarning("Clipboard Error", f"Could not copy:\n{e}", parent=self)
        else: logging.warning("Attempted copy empty gen pass.")
    def _generate_local(self):
        logging.info("Generating password locally."); self._set_generated_password("Generating..."); self.update_idletasks()
        try: password = generate_local_password(length=self.length_var.get(), use_uppercase=self.uppercase_var.get(), use_digits=self.digits_var.get(), use_symbols=self.symbols_var.get()); self._set_generated_password(password)
        except Exception as e: self._set_generated_password(""); logging.error(f"Local gen failed: {e}"); messagebox.showerror("Gen Error", f"Could not generate locally:\n{e}", parent=self)

    # REMOVED _generate_gemini method
    # REMOVED _set_analysis_result method
    # REMOVED _analyze_strength method

    def _close_dialog(self):
        """Closes the dialog gracefully."""
        logging.debug("PasswordGenerator: Closing dialog.")
        try: self.grab_release()
        except Exception as e: logging.warning(f"Error releasing grab: {e}")
        self.destroy()

    def destroy(self):
        logging.debug(f"Destroying PasswordGenerator ({self})")
        super().destroy()

# End of file password_manager/app/ui/password_generator.py
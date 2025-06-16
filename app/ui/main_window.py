# password_manager/app/ui/main_window.py
import customtkinter as ctk
from tkinter import messagebox, simpledialog
import pyperclip
import logging
import os
from typing import Optional, Dict, List
from PIL import Image

# Local imports
from config import settings
from app.core.database import PasswordDatabase
from app.core.encryption import encrypt_data, decrypt_data
# Correctly import the generator which no longer uses Gemini
from app.ui.password_generator import PasswordGeneratorWindow
# Import strength checker
from app.core.password_utils import check_password_strength


# --- Icon Loader Helper ---
def load_icon(file_path, size=(20, 20)):
    """Loads an icon file using Pillow and returns a CTkImage or None."""
    if not os.path.exists(file_path): return None
    try:
        img = Image.open(file_path);
        if img.mode not in ['RGB', 'RGBA']: img = img.convert('RGBA')
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception as e: logging.error(f"Failed to load icon {file_path}: {e}"); return None
# --- End Icon Loader ---


# --- Tooltip Class (Restored) ---
class Tooltip:
    """
    Creates a tooltip (pop-up) for a given widget.
    """
    def __init__(self, widget, text, delay=500, wraplength=200):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.wraplength = wraplength
        self.tooltip_window = None
        self._id = None # For after_cancel

        self.widget.bind("<Enter>", self._schedule_tooltip)
        self.widget.bind("<Leave>", self._hide_tooltip)
        self.widget.bind("<ButtonPress>", self._hide_tooltip) # Hide on click too

    def _schedule_tooltip(self, event=None):
        self._hide_tooltip(cancel_timer_only=True) # Cancel any pending show
        self._id = self.widget.after(self.delay, self._show_tooltip)

    def _show_tooltip(self, event=None):
        self._id = None # Timer has fired or was cancelled
        if self.tooltip_window: return # Already shown

        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5

        self.tooltip_window = ctk.CTkToplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")

        try:
            bg_color = self.widget._apply_appearance_mode(ctk.ThemeManager.theme["CTkFrame"]["fg_color"])
            text_color = self.widget._apply_appearance_mode(ctk.ThemeManager.theme["CTkLabel"]["text_color"])
        except Exception:
            bg_color = "gray20" if ctk.get_appearance_mode() == "Dark" else "gray90"
            text_color = "white" if ctk.get_appearance_mode() == "Dark" else "black"

        label = ctk.CTkLabel(self.tooltip_window,
                             text=self.text,
                             fg_color=bg_color,
                             text_color=text_color,
                             corner_radius=3,
                             padx=5, pady=3,
                             wraplength=self.wraplength,
                             justify="left",
                             font=ctk.CTkFont(size=10))
        label.pack()
        self.tooltip_window.lift()

    def _hide_tooltip(self, event=None, cancel_timer_only=False):
        if self._id is not None: # If a show timer is pending
            self.widget.after_cancel(self._id)
            self._id = None
        if not cancel_timer_only and self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None
# --- END Tooltip Class ---


class MainWindow(ctk.CTkToplevel):
    # ... (Rest of MainWindow class remains unchanged from the version that fixed the last syntax error) ...
    def __init__(self, master, db: PasswordDatabase, encryption_key: bytes):
        super().__init__(master); logging.debug("MW: Entering MainWindow.__init__")
        self.db = db; self.encryption_key = encryption_key; logging.debug("MW: DB and key assigned")
        try:
            self.grab_set(); self.title(f"{settings.APP_NAME} - Dashboard"); self.geometry("900x600"); self.minsize(700, 400); self.protocol("WM_DELETE_WINDOW", self._on_closing); logging.debug("MW: Basic properties and protocol set")
        except Exception as e:
            logging.warning(f"MW: Error setting basic properties/grab: {e}")
        self.current_credentials: Dict[int, Dict] = {}; self.clipboard_clear_job = None; self._search_job = None;
        self.sort_options_map = { "Service (A-Z)": ("service", "ASC"), "Service (Z-A)": ("service", "DESC"), "Username (A-Z)": ("username", "ASC"), "Username (Z-A)": ("username", "DESC"), "Date Added (Newest)": ("created_at", "DESC"), "Date Added (Oldest)": ("created_at", "ASC"), "Date Modified (Newest)": ("updated_at", "DESC"), "Date Modified (Oldest)": ("updated_at", "ASC"), "Favorites First": ("is_favorite", "DESC"), }
        self.sort_options_list = list(self.sort_options_map.keys()); self.current_sort_selection = self.sort_options_list[0]
        self.autolock_timer_id = None; self.lock_screen = None
        logging.debug("MW: Internal variables initialized")
        logging.debug("MW: Scheduling _initialize_ui"); self.after(1, self._initialize_ui); logging.debug("MW: Exiting MainWindow.__init__ (UI pending)")
    def _initialize_ui(self):
        logging.debug("MW: Entering _initialize_ui")
        try:
            logging.debug("MW: Loading icons"); icon_size_main_actions = (20, 20); icon_size_list_actions = (16, 16); self.add_icon = load_icon(settings.ADD_ICON_FILE, size=icon_size_main_actions); self.generate_icon = load_icon(settings.GENERATE_ICON_FILE, size=icon_size_main_actions); self.search_icon = load_icon(settings.SEARCH_ICON_FILE, size=(18,18)); self.copy_icon = load_icon(settings.COPY_ICON_FILE, size=icon_size_list_actions); self.edit_icon = load_icon(settings.EDIT_ICON_FILE, size=icon_size_list_actions); self.delete_icon = load_icon(settings.DELETE_ICON_FILE, size=icon_size_list_actions); self.view_icon = load_icon(settings.VIEW_ICON_FILE, size=icon_size_list_actions);
            self.fav_icon = load_icon(settings.FAVORITE_ICON_FILE, size=icon_size_list_actions); self.not_fav_icon = load_icon(settings.NOT_FAVORITE_ICON_FILE, size=icon_size_list_actions)
            logging.debug("MW: Icons loaded (or attempted)")
            self._setup_ui(); self.load_and_display_credentials()
            logging.debug("MW: Setting window icon"); icon_path_to_use = settings.APP_ICON_FILE_ICO
            if not os.path.exists(icon_path_to_use) or not icon_path_to_use.endswith(".ico"): icon_path_to_use = settings.APP_ICON_FILE_PNG
            if os.path.exists(icon_path_to_use):
                try: self.iconbitmap(icon_path_to_use)
                except Exception as e: logging.error(f"MW: Failed to set icon: {e}")
            else: logging.warning(f"MW: App icon file not found: {icon_path_to_use}")
            logging.debug("MW: Scheduling centering"); self.after(50, self._center_relative_to_master)
            self._setup_activity_bindings(); self._reset_autolock_timer()
            logging.debug("MW: _initialize_ui finished successfully.")
        except Exception as e:
            logging.exception("MW: FAILED during _initialize_ui")
            try: messagebox.showerror("UI Error", f"Failed to initialize main UI:\n{e}", parent=self)
            except Exception as mb_error: logging.error(f"MW: Failed to show UI init error messagebox: {mb_error}")
            self.destroy()
    def _setup_activity_bindings(self): logging.debug("MW: Setting up activity bindings."); self.bind_all("<KeyPress>", self._user_activity_detected); self.bind_all("<ButtonPress>", self._user_activity_detected); self.bind_all("<Motion>", self._user_activity_detected)
    def _user_activity_detected(self, event=None):
        if self.lock_screen is None or not self.lock_screen.winfo_exists(): self._reset_autolock_timer()
    def _reset_autolock_timer(self):
        if self.autolock_timer_id is not None: self.after_cancel(self.autolock_timer_id)
        try:
            timeout_ms = int(settings.AUTOLOCK_TIMEOUT_MS);
            if timeout_ms <= 0: logging.warning("MW: Auto-lock timeout invalid, disabling."); self.autolock_timer_id = None; return
        except (ValueError, TypeError): logging.error("MW: Invalid AUTOLOCK_TIMEOUT_MS, using default."); timeout_ms = 60000
        self.autolock_timer_id = self.after(timeout_ms, self._lock_application)
    def _lock_application(self):
        if self.lock_screen and self.lock_screen.winfo_exists(): logging.debug("MW: App already locked."); return
        logging.info("MW: Auto-lock timer expired. Locking application."); self.autolock_timer_id = None;
        from app.ui.lock_screen import LockScreen # Define LockScreen in a separate file
        self.lock_screen = LockScreen(master=self, db=self.db, unlock_callback=self._unlock_application)
    def _unlock_application(self):
        logging.info("MW: Application unlocked."); self.grab_set(); self.focus_force(); self._reset_autolock_timer()
    def _center_relative_to_master(self):
         logging.debug("MW: Centering window.")
         try:
             self.update_idletasks(); master = self.master;
             if not master or not master.winfo_exists(): logging.warning("MW: Master window invalid for centering."); return
             master_x = master.winfo_x(); master_y = master.winfo_y(); master_w = master.winfo_width(); master_h = master.winfo_height(); win_w = self.winfo_width(); win_h = self.winfo_height(); x = max(0, master_x + (master_w // 2) - (win_w // 2)); y = max(0, master_y + (master_h // 2) - (win_h // 2)); self.geometry(f"+{x}+{y}"); logging.debug(f"MW: Centered at +{x}+{y}")
         except Exception as e: logging.warning(f"MW: Could not center: {e}")
    def _setup_ui(self):
        logging.debug("MW: Setting up UI widgets.")
        self.grid_columnconfigure(0, weight=1); self.grid_rowconfigure(1, weight=1)
        top_frame = ctk.CTkFrame(self, height=50); top_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew"); top_frame.grid_columnconfigure(0, weight=3); top_frame.grid_columnconfigure(1, weight=0); top_frame.grid_columnconfigure(2, weight=0); top_frame.grid_columnconfigure(3, weight=1); top_frame.grid_columnconfigure(4, weight=0); top_frame.grid_columnconfigure(5, weight=0)
        self.search_var = ctk.StringVar(); self.search_entry = ctk.CTkEntry(top_frame, placeholder_text="Search Service or Username...", textvariable=self.search_var)
        self.search_entry.bind("<Return>", self._perform_search); self.search_entry.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="ew"); self.search_var.trace_add("write", self._on_search_change)
        search_button_width = 30; self.search_button = ctk.CTkButton(top_frame, text="", image=self.search_icon, width=search_button_width, height=search_button_width, fg_color="transparent", hover_color=("gray70", "gray30"), command=self._perform_search)
        self.search_button.grid(row=0, column=1, padx=(0, 10), pady=10); Tooltip(self.search_button, "Search credentials")
        sort_label = ctk.CTkLabel(top_frame, text="Sort by:"); sort_label.grid(row=0, column=2, padx=(10, 2), pady=10, sticky="e")
        self.sort_option_menu = ctk.CTkOptionMenu(top_frame, values=self.sort_options_list, command=self._on_sort_change, width=180); self.sort_option_menu.set(self.current_sort_selection); self.sort_option_menu.grid(row=0, column=3, padx=(0, 10), pady=10, sticky="ew"); Tooltip(self.sort_option_menu, "Select sort order")
        self.add_button = ctk.CTkButton(top_frame, text="Add", image=self.add_icon, width=80, height=30, command=self._add_credential_dialog, compound="left"); self.add_button.grid(row=0, column=4, padx=5, pady=10); Tooltip(self.add_button, "Add new credential")
        self.generate_button = ctk.CTkButton(top_frame, text="Generator", image=self.generate_icon, width=110, height=30, command=self._open_password_generator, compound="left"); self.generate_button.grid(row=0, column=5, padx=(5, 10), pady=10); Tooltip(self.generate_button, "Open Password Generator")
        self.scrollable_frame = ctk.CTkScrollableFrame(self, label_text="Stored Credentials"); self.scrollable_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.scrollable_frame.grid_columnconfigure(0, weight=3); self.scrollable_frame.grid_columnconfigure(1, weight=3); col_index = 2; col_width = 35
        self.scrollable_frame.grid_columnconfigure(col_index, weight=0, minsize=col_width); self.scrollable_frame.grid_columnconfigure(col_index + 1, weight=0, minsize=col_width); self.scrollable_frame.grid_columnconfigure(col_index + 2, weight=0, minsize=col_width + 10); self.scrollable_frame.grid_columnconfigure(col_index + 3, weight=0, minsize=col_width + 10); self.scrollable_frame.grid_columnconfigure(col_index + 4, weight=0, minsize=col_width); self.scrollable_frame.grid_columnconfigure(col_index + 5, weight=0, minsize=col_width)
        self.status_bar = ctk.CTkLabel(self, text="Ready", anchor="w", height=20); self.status_bar.grid(row=2, column=0, padx=10, pady=(0, 5), sticky="ew"); logging.debug("MW: UI widgets setup complete.")
    def _on_sort_change(self, selected_option: str):
        logging.info(f"Sort option changed to: {selected_option}")
        self.current_sort_selection = selected_option
        self.load_and_display_credentials(self.search_var.get())
    def _perform_search(self, event=None):
        if self._search_job:
            self.after_cancel(self._search_job)
            self._search_job = None
        search_query = self.search_var.get()
        self.load_and_display_credentials(search_query)
    def _on_search_change(self, *args):
        if self._search_job:
            self.after_cancel(self._search_job)
        self._search_job = self.after(300, lambda: self.load_and_display_credentials(self.search_var.get()))
    def _set_status(self, message: str, duration: int = 0):
        if hasattr(self, 'status_bar') and self.status_bar and self.status_bar.winfo_exists():
            self.status_bar.configure(text=message)
        if duration > 0:
            self.after(duration, lambda current_msg=message: self._reset_status_if_unchanged(current_msg))
    def _reset_status_if_unchanged(self, original_message: str):
        if hasattr(self, 'status_bar') and self.status_bar and self.status_bar.winfo_exists() and self.status_bar.cget("text") == original_message:
            self.status_bar.configure(text="Ready")

    # --- CORRECTED load_and_display_credentials ---
    def load_and_display_credentials(self, search_query: str = ""):
        sort_column, sort_order = self.sort_options_map.get(self.current_sort_selection, ("service", "ASC"))
        logging.info(f"Loading credentials (Query: '{search_query}', Sort: {sort_column} {sort_order})...")
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.current_credentials.clear()
        try:
            if search_query:
                db_credentials = self.db.search_credentials(search_query, sort_by=sort_column, sort_order=sort_order)
            else:
                db_credentials = self.db.get_all_credentials(sort_by=sort_column, sort_order=sort_order)

            font_bold = None
            try:
                # Create font
                font_bold = ctk.CTkFont(weight="bold")
            except Exception as e:
                # Log error if font creation fails
                logging.error(f"Failed bold font: {e}")

            header_kwargs = {"font": font_bold} if font_bold else {}
            headers = ["Service", "Username", "Actions"]
            ctk.CTkLabel(self.scrollable_frame, text=headers[0], **header_kwargs).grid(row=0, column=0, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.scrollable_frame, text=headers[1], **header_kwargs).grid(row=0, column=1, padx=10, pady=5, sticky="w")
            ctk.CTkLabel(self.scrollable_frame, text=headers[2], **header_kwargs).grid(row=0, column=2, columnspan=6, padx=10, pady=5, sticky="w") # Span 6
            if not db_credentials:
                ctk.CTkLabel(self.scrollable_frame, text="No credentials found." if not search_query else "No matching credentials found.").grid(row=1, column=0, columnspan=8, padx=10, pady=10) # Span 8
                self.scrollable_frame.configure(label_text=f"Stored Credentials (0)")
                return
            for index, cred in enumerate(db_credentials):
                row_index = index + 1; cred_id = cred['id']; service = cred['service']; username = cred['username']; encrypted_password = cred['encrypted_password']; notes = cred.get('notes', ''); is_favorite = bool(cred.get('is_favorite', 0))
                decrypted_password = ""; display_username = username; buttons_state = "normal"
                try:
                    decrypted_password = decrypt_data(encrypted_password, self.encryption_key)
                    if decrypted_password == "[Decryption Error]":
                        logging.error(f"Decryption failed ID {cred_id}.")
                        display_username += " [DECRYPTION FAILED]"
                        decrypted_password = ""
                        buttons_state = "disabled"
                except Exception as e:
                    logging.exception(f"Decrypt error ID {cred_id}: {e}")
                    display_username += " [ERROR]"
                    decrypted_password = ""
                    buttons_state = "disabled"
                self.current_credentials[cred_id] = {'service': service, 'username': username, 'password': decrypted_password, 'notes': notes, 'is_favorite': is_favorite}
                ctk.CTkLabel(self.scrollable_frame, text=service, anchor="w").grid(row=row_index, column=0, padx=10, pady=5, sticky="ew")
                ctk.CTkLabel(self.scrollable_frame, text=display_username, anchor="w").grid(row=row_index, column=1, padx=10, pady=5, sticky="ew")
                bw = 28; bh = 28; bpx = (2, 2); bpy = (3, 3); col = 2
                fav_icon = self.fav_icon if is_favorite else self.not_fav_icon; fav_hover = ("#F1C40F", "#F39C12")
                fav_btn = ctk.CTkButton(self.scrollable_frame, text="", image=fav_icon, width=bw, height=bh, state="normal", fg_color="transparent", hover_color=fav_hover, command=lambda i=cred_id: self._toggle_favorite(i)); fav_btn.grid(row=row_index, column=col, padx=bpx, pady=bpy); Tooltip(fav_btn, "Toggle Favorite"); col += 1
                view_btn = ctk.CTkButton(self.scrollable_frame, text="View" if not self.view_icon else "", image=self.view_icon, width=bw if self.view_icon else 40, height=bh, state=buttons_state, fg_color="transparent", hover_color=("gray70", "gray30"), command=lambda i=cred_id: self._view_password_action(i)); view_btn.grid(row=row_index, column=col, padx=bpx, pady=bpy); Tooltip(view_btn, "View Password"); col += 1
                copy_u_btn = ctk.CTkButton(self.scrollable_frame, text="CopyU" if not self.copy_icon else "", image=self.copy_icon, width=bw if self.copy_icon else 45, height=bh, state=buttons_state, fg_color="transparent", hover_color=("gray70", "gray30"), command=lambda u=username: self._copy_to_clipboard(u, "Username")); copy_u_btn.grid(row=row_index, column=col, padx=bpx, pady=bpy); Tooltip(copy_u_btn, "Copy Username"); col += 1
                copy_p_btn = ctk.CTkButton(self.scrollable_frame, text="CopyP" if not self.copy_icon else "", image=self.copy_icon, width=bw if self.copy_icon else 45, height=bh, state=buttons_state, fg_color="transparent", hover_color=("gray70", "gray30"), command=lambda p=decrypted_password: self._copy_to_clipboard(p, "Password")); copy_p_btn.grid(row=row_index, column=col, padx=bpx, pady=bpy); Tooltip(copy_p_btn, "Copy Password"); col += 1
                edit_btn = ctk.CTkButton(self.scrollable_frame, text="Edit" if not self.edit_icon else "", image=self.edit_icon, width=bw if self.edit_icon else 40, height=bh, state=buttons_state, fg_color="transparent", hover_color=("gray70", "gray30"), command=lambda i=cred_id: self._edit_credential_dialog(i)); edit_btn.grid(row=row_index, column=col, padx=bpx, pady=bpy); Tooltip(edit_btn, "Edit Credential"); col += 1
                del_btn = ctk.CTkButton(self.scrollable_frame, text="Del" if not self.delete_icon else "", image=self.delete_icon, width=bw if self.delete_icon else 35, height=bh, state="normal", fg_color="transparent", hover_color=("#E74C3C", "#C0392B"), command=lambda i=cred_id, s=service: self._delete_credential(i, s)); del_btn.grid(row=row_index, column=col, padx=(bpx[0], 10), pady=bpy); Tooltip(del_btn, "Delete Credential")
            self.scrollable_frame.configure(label_text=f"Stored Credentials ({len(db_credentials)})")
            logging.info(f"Displayed {len(db_credentials)} credentials.")
        except Exception as e:
            logging.exception("Failed load/display credentials.")
            messagebox.showerror("Load Error", f"Error: {e}", parent=self)
            ctk.CTkLabel(self.scrollable_frame, text=f"Error: {e}", text_color="red").grid(row=1, column=0, columnspan=8, padx=10, pady=10)
    # --- END CORRECT load_and_display_credentials ---

    def _toggle_favorite(self, credential_id: int):
        logging.debug(f"Toggle favorite requested for ID: {credential_id}")
        try:
            self.db.toggle_favorite_status(credential_id)
            self.load_and_display_credentials(self.search_var.get())
        except Exception as e:
            logging.exception(f"Failed toggle fav ID {credential_id}")
            messagebox.showerror("Error", f"Could not toggle favorite:\n{e}", parent=self)

    def _copy_to_clipboard(self, text: str, item_name: str):
        if not text:
            logging.warning(f"Attempted copy empty {item_name}.")
            self._set_status(f"{item_name} empty.", 3000)
            return
        try:
            if self.clipboard_clear_job:
                self.after_cancel(self.clipboard_clear_job)
                self.clipboard_clear_job = None
            pyperclip.copy(text)
            logging.info(f"{item_name} copied.")
            self._set_status(f"{item_name} copied (clears in {settings.CLIPBOARD_TIMEOUT//1000}s).", settings.CLIPBOARD_TIMEOUT)
            self.clipboard_clear_job = self.after(settings.CLIPBOARD_TIMEOUT, self._clear_clipboard)
        except Exception as e:
            logging.error(f"Failed copy {item_name}: {e}")
            try:
                messagebox.showwarning("Clipboard Error", f"Could not copy:\n{e}", parent=self)
            except Exception as mb_error:
                 logging.error(f"Failed show clipboard error messagebox: {mb_error}")
            self._set_status(f"Error copy {item_name}.", 3000)

    def _clear_clipboard(self):
        try:
            pyperclip.copy('')
            logging.info("Clipboard cleared.")
            self._set_status("Clipboard cleared.", 3000)
            self.clipboard_clear_job = None
        except Exception as e:
            logging.warning(f"Could not clear clipboard: {e}")
            self._set_status("Failed clear clipboard.", 3000)
            self.clipboard_clear_job = None

    def _view_password_action(self, credential_id: int):
        logging.debug(f"View password requested for ID: {credential_id}")
        entered_password = None; dialog = None; grabbed = False
        try:
            logging.debug("MW: Releasing grab before opening InputDialog.")
            self.grab_release()
            grabbed = True
        except Exception as grab_e:
            logging.warning(f"MW: Error releasing grab before InputDialog: {grab_e}")
        try:
            logging.debug("MW: Creating CTkInputDialog")
            dialog = ctk.CTkInputDialog(text="Enter Master Password to view:", title="Verify Identity")
            logging.debug("MW: CTkInputDialog created. Waiting for input...")
            entered_password = dialog.get_input() # This blocks
            logging.debug(f"MW: CTkInputDialog returned: {repr(entered_password)}")
        except Exception as e:
             logging.exception("Error with CTkInputDialog")
             messagebox.showerror("Dialog Error", f"Could not open prompt:\n{e}", parent=self)
             if grabbed: self.after(50, self.grab_set) # Re-grab only if released
             return
        finally:
             if grabbed: logging.debug("MW: Scheduling re-acquire grab after InputDialog."); self.after(50, self.grab_set) # Re-grab after dialog closes
        if entered_password is None: logging.debug("Password view cancelled."); return
        if not entered_password: messagebox.showwarning("Verification Required", "Master password cannot be empty.", parent=self); return
        logging.debug("Verifying entered master password..."); is_correct = False
        try:
            is_correct = self.db.verify_master_password(entered_password)
            logging.debug(f"Verification result: {is_correct}")
        except Exception as e:
            logging.exception("Error calling verify_master_password")
            messagebox.showerror("Verification Error", f"Verification error:\n{e}", parent=self)
            return
        if is_correct:
            logging.debug("Master password verified successfully."); cred_data = self.current_credentials.get(credential_id)
            if cred_data and 'password' in cred_data:
                decrypted_password = cred_data['password']
                service_name = cred_data.get('service', 'Unknown')
                logging.debug(f"Password retrieved: {'<empty>' if not decrypted_password else decrypted_password[:3]+'...'}")
                if decrypted_password == "[DECRYPTION FAILED]": messagebox.showerror("View Error", "Previous decryption error.", parent=self)
                elif decrypted_password == "": messagebox.showwarning("View Warning", "Password empty.", parent=self)
                else: messagebox.showinfo(f"Password for '{service_name}'", f"Password:\n\n{decrypted_password}", parent=self)
            else: logging.error(f"Could not retrieve pwd data ID {credential_id}"); messagebox.showerror("View Error", "Could not get password data.", parent=self)
        else: logging.warning("Incorrect master password for viewing."); messagebox.showerror("Verification Failed", "Incorrect master password.", parent=self)
        logging.debug(f"MW: _view_password_action finished ID: {credential_id}")

    def _add_credential_dialog(self):
        logging.debug("MW: Opening Add Credential dialog."); dialog = None; result = None; grabbed = False
        try:
            self.grab_release(); grabbed = True; logging.debug("MW: Grab released for Add Dialog.")
            dialog = CredentialDialog(parent=self, title="Add New Credential"); result = dialog.get_input();
        except Exception as e: logging.exception("Error creating/running Add Dialog"); messagebox.showerror("Dialog Error", f"Failed open Add dialog:\n{e}", parent=self); result = None
        finally:
            if grabbed: self.after(50, self.grab_set); logging.debug("MW: Scheduled grab re-acquire after Add.")
        logging.debug(f"MW: Add Credential dialog returned: {result}")
        if result:
            service, username, password, notes = result
            try:
                encrypted_password = encrypt_data(password, self.encryption_key); self.db.add_credential(service, username, encrypted_password, notes); logging.info(f"Added: {service}"); self.load_and_display_credentials(""); self._set_status(f"'{service}' added.", 3000)
            except ValueError as e: messagebox.showerror("Input Error", f"{e}", parent=self)
            except Exception as e: logging.exception(f"Failed add {service}"); messagebox.showerror("DB Error", f"Could not save:\n{e}", parent=self)

    def _edit_credential_dialog(self, credential_id: int):
        logging.debug(f"MW: Opening Edit Credential dialog for ID: {credential_id}.")
        cred_data = self.current_credentials.get(credential_id)
        if not cred_data: messagebox.showerror("Error", "Could not find data.", parent=self); return
        dialog = None; result = None; grabbed = False
        try:
            self.grab_release(); grabbed = True; logging.debug("MW: Grab released for Edit Dialog.")
        except Exception as e: logging.warning(f"MW: Failed grab release for Edit: {e}")
        try:
             dialog = CredentialDialog(parent=self, title="Edit Credential", initial_service=cred_data['service'], initial_username=cred_data['username'], initial_password=cred_data['password'], initial_notes=cred_data['notes']); result = dialog.get_input();
        except Exception as e: logging.exception("Error creating/running Edit Dialog"); messagebox.showerror("Dialog Error", f"Failed open Edit dialog:\n{e}", parent=self); result = None
        finally:
             if grabbed: self.after(50, self.grab_set); logging.debug("MW: Scheduled grab re-acquire after Edit.")
        logging.debug(f"MW: Edit Credential dialog returned: {result}")
        if result:
            service, username, password, notes = result
            try:
                encrypted_password = encrypt_data(password, self.encryption_key); self.db.update_credential(credential_id, service, username, encrypted_password, notes); logging.info(f"Updated ID: {credential_id}"); self.load_and_display_credentials(self.search_var.get()); self._set_status(f"'{service}' updated.", 3000)
            except ValueError as e: messagebox.showerror("Input Error", f"{e}", parent=self)
            except Exception as e: logging.exception(f"Failed update ID {credential_id}"); messagebox.showerror("DB Error", f"Could not update:\n{e}", parent=self)

    def _delete_credential(self, credential_id: int, service_name: str):
        original_username = self.current_credentials.get(credential_id, {}).get('username', '?'); confirm_msg = f"Delete credential for:\n\nService: {service_name}\nUsername: {original_username}?"
        grabbed = False; confirm = False
        try:
             self.grab_release(); grabbed = True; logging.debug("MW: Grab released for Delete Confirm.")
             confirm = messagebox.askyesno("Confirm Deletion", confirm_msg, icon='warning', parent=self)
        except Exception as e:
             logging.error(f"Failed during delete confirmation prompt: {e}")
        finally:
             if grabbed:
                 self.after(50, self.grab_set)
                 logging.debug("MW: Scheduled grab re-acquire after Delete Confirm.")
        if confirm:
            try: self.db.delete_credential(credential_id); logging.info(f"Deleted ID: {credential_id}"); self.current_credentials.pop(credential_id, None); self.load_and_display_credentials(self.search_var.get()); self._set_status(f"'{service_name}' deleted.", 3000)
            except Exception as e: logging.exception(f"Failed delete ID {credential_id}"); messagebox.showerror("DB Error", f"Could not delete:\n{e}", parent=self)

    def _open_password_generator(self):
        generator_win = None
        try:
            self.grab_release(); logging.debug("MW: Grab released for Generator.")
            generator_win = PasswordGeneratorWindow(self); generator_win.focus()
        except Exception as e:
            logging.exception("Failed to open Password Generator window")
            messagebox.showerror("Error", f"Could not open generator:\n{e}", parent=self)
            self.after(50, self.grab_set) # Re-grab on error

    def _on_closing(self):
        logging.info("MainWindow (Toplevel) closing.")
        if self.clipboard_clear_job: self.after_cancel(self.clipboard_clear_job); self._clear_clipboard()
        try: self.grab_release()
        except: pass
        self.destroy()

    def destroy(self):
        logging.debug(f"Destroying MainWindow (Toplevel) ({self})")
        if hasattr(self, 'autolock_timer_id') and self.autolock_timer_id is not None:
            self.after_cancel(self.autolock_timer_id)
            logging.debug("MW: Cancelled autolock timer during destroy.")
        super().destroy()
# --- End MainWindow Class ---


# --- Full CredentialDialog Class (with strength indicator) ---
# (This class should be the correct one now, with the strength indicator parts)
class CredentialDialog(ctk.CTkToplevel):
    # ... (Full CredentialDialog code remains unchanged) ...
    def __init__(self, parent, title: str, initial_service: str = "", initial_username: str = "", initial_password: str = "", initial_notes: str = ""):
        logging.debug("CD: Entering CredentialDialog.__init__")
        try: parent_bg = parent.cget("fg_color"); super().__init__(parent, fg_color=parent_bg); logging.debug("CD: super().__init__(parent) called")
        except Exception as e: logging.exception("CD: FAILED super().__init__"); raise
        self.initial_service = initial_service; self.initial_username = initial_username; self.initial_password = initial_password; self.initial_notes = initial_notes
        logging.debug("CD: Setting up basic window properties")
        try: self.grab_set(); self.title(title); self.geometry("450x400"); self.resizable(False, False); self.protocol("WM_DELETE_WINDOW", self._cancel); logging.debug("CD: Basic properties and protocol set") # Increased height
        except Exception as e: logging.warning(f"CD: Error setting basic properties/grab: {e}")
        self.result: Optional[tuple] = None; self._password_visible = False; logging.debug("CD: result and visibility initialized")
        self.password_var = ctk.StringVar(); self.password_var.trace_add("write", self._update_strength_indicator) # Added var trace
        logging.debug("CD: Scheduling _create_widgets"); self.after(1, self._create_widgets); logging.debug("CD: Exiting CredentialDialog.__init__ (widgets pending)")
    def _create_widgets(self):
        logging.debug("CD: Entering _create_widgets")
        try:
            logging.debug("CD: Loading icons in _create_widgets"); icon_size = (18, 18); self.visible_icon = load_icon(settings.VISIBLE_ICON_FILE, size=icon_size); self.hidden_icon = load_icon(settings.HIDDEN_ICON_FILE, size=icon_size); self.save_icon = load_icon(settings.SAVE_ICON_FILE, size=icon_size); self.cancel_icon = load_icon(settings.CANCEL_ICON_FILE, size=icon_size)
            if not self.visible_icon or not self.hidden_icon or not self.save_icon or not self.cancel_icon: logging.warning("One or more CredentialDialog icons failed to load.")
            logging.debug("CD: Starting UI element creation in _create_widgets"); self.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(self, text="Service/Website:").grid(row=0, column=0, padx=10, pady=(10,5), sticky="w"); self.service_entry = ctk.CTkEntry(self, width=250); self.service_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=(10,5), sticky="ew"); self.service_entry.insert(0, self.initial_service)
            ctk.CTkLabel(self, text="Username/Email:").grid(row=1, column=0, padx=10, pady=5, sticky="w"); self.username_entry = ctk.CTkEntry(self, width=250); self.username_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="ew"); self.username_entry.insert(0, self.initial_username)
            ctk.CTkLabel(self, text="Password:").grid(row=2, column=0, padx=10, pady=5, sticky="w"); self.password_entry = ctk.CTkEntry(self, width=250, show="*", textvariable=self.password_var); self.password_entry.grid(row=2, column=1, padx=(10,5), pady=5, sticky="ew"); self.password_entry.insert(0, self.initial_password)
            initial_icon = self.hidden_icon if self.hidden_icon else None; self.show_pass_button = ctk.CTkButton(self, text="", image=initial_icon, width=30, height=30, fg_color="transparent", hover_color=("gray70", "gray30"), command=self._toggle_password_visibility); self.show_pass_button.grid(row=2, column=2, padx=(0,10), pady=5)
            if not self.visible_icon or not self.hidden_icon: self.show_pass_button.configure(state="disabled")
            strength_frame = ctk.CTkFrame(self, fg_color="transparent"); strength_frame.grid(row=3, column=1, columnspan=2, padx=10, pady=(0,5), sticky="ew"); strength_frame.grid_columnconfigure(0, weight=1)
            self.strength_bar = ctk.CTkProgressBar(strength_frame, width=200, height=10, corner_radius=5); self.strength_bar.grid(row=0, column=0, padx=(0, 5), pady=2, sticky="ew"); self.strength_bar.set(0)
            self.strength_label = ctk.CTkLabel(strength_frame, text="Empty", width=80, anchor="w", font=ctk.CTkFont(size=10)); self.strength_label.grid(row=0, column=1, padx=(0,0), pady=2, sticky="w")
            ctk.CTkLabel(self, text="Notes (Optional):").grid(row=4, column=0, padx=10, pady=5, sticky="nw"); self.notes_textbox = ctk.CTkTextbox(self, height=80, wrap="word"); self.notes_textbox.grid(row=4, column=1, columnspan=2, padx=10, pady=5, sticky="nsew")
            if self.initial_notes: self.notes_textbox.insert("1.0", self.initial_notes)
            button_frame = ctk.CTkFrame(self, fg_color="transparent"); button_frame.grid(row=5, column=0, columnspan=3, pady=10); self.save_button = ctk.CTkButton(button_frame, text="Save", image=self.save_icon, command=self._save); self.save_button.pack(side="left", padx=10); self.cancel_button = ctk.CTkButton(button_frame, text="Cancel", image=self.cancel_icon, command=self._cancel, fg_color="grey"); self.cancel_button.pack(side="left", padx=10); logging.debug("CD: UI elements created.")
            logging.debug("CD: Setting focus and bindings."); self.service_entry.focus();
            if self.initial_service: self.service_entry.select_range(0, 'end')
            self.bind("<Return>", lambda event: self._save()); self.bind("<Escape>", lambda event: self._cancel())
            logging.debug("CD: Scheduling _center_dialog."); self.after(50, self._center_dialog); self._update_strength_indicator(); logging.debug("CD: _create_widgets finished.")
        except Exception as e:
            logging.exception("CD: FAILED UI creation (_create_widgets)")
            try: messagebox.showerror("Dialog Error", f"Failed create dialog UI:\n{e}", parent=self)
            except Exception as mb_error: logging.error(f"CD: Failed to show error messagebox: {mb_error}")
            self.after(10, self.destroy)
    def _update_strength_indicator(self, *args):
        if not hasattr(self, 'password_var') or not hasattr(self, 'strength_bar') or not hasattr(self, 'strength_label'): logging.debug("CD: Strength indicator widgets not ready yet."); return
        if not self.strength_bar.winfo_exists() or not self.strength_label.winfo_exists(): logging.debug("CD: Strength indicator widgets destroyed before update."); return
        password = self.password_var.get(); score, text, color = check_password_strength(password)
        progress_value = score / 4.0; self.strength_bar.set(progress_value); self.strength_bar.configure(progress_color=color)
        self.strength_label.configure(text=text, text_color=color)
    def _toggle_password_visibility(self):
        if not self.visible_icon or not self.hidden_icon: logging.warning("Cannot toggle password visibility, icons missing."); return
        if self._password_visible: self.password_entry.configure(show="*"); self.show_pass_button.configure(image=self.hidden_icon); self._password_visible = False; logging.debug("CD: Password hidden")
        else: self.password_entry.configure(show=""); self.show_pass_button.configure(image=self.visible_icon); self._password_visible = True; logging.debug("CD: Password shown")
    def _center_dialog(self):
         logging.debug("CD: Centering dialog")
         try: self.update_idletasks(); parent_geo = self.master.winfo_geometry(); parent_w, parent_h, parent_x, parent_y = map(int, parent_geo.replace('x', '+').split('+')); win_w = self.winfo_width(); win_h = self.winfo_height(); x = max(0, parent_x + (parent_w // 2) - (win_w // 2)); y = max(0, parent_y + (parent_h // 2) - (win_h // 2)); self.geometry(f"+{x}+{y}"); logging.debug(f"CD: Dialog centered at +{x}+{y}")
         except Exception as e: logging.warning(f"Could not center credential dialog: {e}")
    def _save(self):
        logging.debug("CD: Save called")
        if not hasattr(self, 'service_entry'): logging.error("CD: Cannot save, UI widgets not fully created."); messagebox.showerror("Error", "Dialog did not initialize correctly.", parent=self); self._close_dialog(); return
        service = self.service_entry.get().strip(); username = self.username_entry.get().strip(); password = self.password_var.get(); notes = self.notes_textbox.get("1.0", "end-1c").strip()
        if not service or not username or not password: logging.warning("CD: Save validation failed"); messagebox.showwarning("Input Required", "Service, Username, and Password fields cannot be empty.", parent=self); self.lift(); self.focus(); return
        logging.debug("CD: Save validation passed"); self.result = (service, username, password, notes); self._close_dialog()
    def _cancel(self, event=None): logging.debug("CD: Cancel called"); self.result = None; self._close_dialog()
    def _close_dialog(self):
        logging.debug("CD: Closing dialog (_close_dialog)")
        try: logging.debug("CD: Releasing grab"); self.grab_release()
        except Exception as e: logging.warning(f"Error releasing grab: {e}")
        try: logging.debug("CD: Destroying self"); self.destroy()
        except Exception as e: logging.warning(f"Error destroying CredentialDialog: {e}")
    def get_input(self) -> Optional[tuple]:
        logging.debug("CD: Waiting for window (get_input)")
        self.wait_window(); logging.debug(f"CD: Wait window finished. Result: {self.result}")
        if self.master and self.master.winfo_exists(): self.master.focus_force(); logging.debug("CD: Returned focus to master")
        return self.result
    def destroy(self): logging.debug(f"Destroying CredentialDialog ({self})"); super().destroy(); logging.debug(f"super().destroy() called for CredentialDialog ({self})")

# End of file password_manager/app/ui/main_window.py
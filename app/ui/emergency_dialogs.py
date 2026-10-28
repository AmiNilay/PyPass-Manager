# password_manager/app/ui/emergency_dialogs.py
"""
Emergency Access (Shamir's Secret Sharing) dialogs:

* EmergencySetupDialog   - wizard that creates a trustee kit and hands out shares
* EmergencyRecoveryDialog - login-screen flow that combines shares to recover the vault
"""
import io
import logging
import os
from tkinter import filedialog, messagebox
from typing import Callable, List, Optional

import customtkinter as ctk
import pyperclip
from PIL import Image

from config import settings
from app.core import emergency
from app.core.database import PasswordDatabase
from app.core.emergency import ShareError, parse_share, printable_kit_text, share_qr_png
from app.ui.theme import (ACCENT, ACCENT_SOFT, BORDER, DANGER, DANGER_SOFT, SECONDARY, SUCCESS,
                          SURFACE, SURFACE_ACTIVE, SURFACE_HOVER, INPUT_BG, INPUT_BORDER,
                          TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED, TEXT_ON_ACCENT,
                          FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_MONO, FONT_SUBHEADING,
                          BUTTON_RADIUS, BTN_PRIMARY, BTN_SECONDARY, BTN_GHOST, BTN_DANGER,
                          ENTRY_STYLE)
from app.ui.widgets import (CARD_PAD, dialog_card, dialog_header, dialog_buttons, caption_label,
                            status_label, center_over, release_grab, draw_icon)

logger = logging.getLogger(__name__)

SETUP_WIDTH = 500
CONTENT_WRAP = SETUP_WIDTH - 2 * CARD_PAD - 40
QR_SIZE = 168


def _banner(parent, text: str, danger: bool = False, wrap: int = CONTENT_WRAP) -> ctk.CTkFrame:
    """Tinted notice box (neutral or danger), as used by the reset dialog."""
    bg, fg = (DANGER_SOFT, DANGER) if danger else (ACCENT_SOFT, TEXT_SECONDARY)
    box = ctk.CTkFrame(parent, fg_color=bg, corner_radius=BUTTON_RADIUS)
    ctk.CTkLabel(box, text=text, font=FONT_SMALL, text_color=fg, wraplength=wrap - 10,
                 justify="left", anchor="w").pack(fill="x", padx=12, pady=8)
    return box


def _segmented(parent, values: List[str], command: Callable[[str], None]) -> ctk.CTkSegmentedButton:
    return ctk.CTkSegmentedButton(
        parent, values=values, command=command, height=32, font=FONT_BODY,
        fg_color=INPUT_BG, selected_color=ACCENT, selected_hover_color=ACCENT,
        unselected_color=INPUT_BG, unselected_hover_color=SURFACE_HOVER,
        text_color=TEXT_PRIMARY, corner_radius=BUTTON_RADIUS, border_width=2)


def _trustee_sentence(k: int, n: int) -> str:
    return f"Any {k} of your {n} trustees together can recover your vault."


class EmergencySetupDialog(ctk.CTkToplevel):
    """Wizard: explain -> choose trustees -> hand out shares -> confirm."""

    def __init__(self, parent, db: PasswordDatabase, vault_key: bytes):
        super().__init__(parent)
        self.db = db
        self.vault_key = vault_key
        self.parent_window = parent
        self._shares: Optional[List[str]] = None
        self._kit_status: Optional[dict] = None
        self._clip_value: Optional[str] = None
        self._clip_job = None
        self._closed = False
        self.n_var = 5
        self.k_var = 3

        self.title("Emergency Access")
        self.resizable(False, False)
        try:
            self.transient(parent)
        except Exception:
            pass
        self.protocol("WM_DELETE_WINDOW", self._request_close)
        self.bind("<Escape>", lambda e: self._request_close())

        self._inner = dialog_card(self)
        # Fixed-width strut keeps every wizard step the same width
        ctk.CTkFrame(self._inner, width=SETUP_WIDTH - 2 * CARD_PAD - 32, height=1,
                     fg_color="transparent").pack(side="top")
        self.body = None
        self._show_intro()

        self.grab_set()
        self.lift()
        self.focus()
        self.after(60, lambda: center_over(self, parent))

    # ── Step plumbing ────────────────────────────────────────

    def _new_step(self) -> ctk.CTkFrame:
        if self.body is not None:
            self.body.destroy()
        self.body = ctk.CTkFrame(self._inner, fg_color="transparent")
        self.body.pack(fill="both", expand=True)
        return self.body

    def _step_caption(self, parent, text: str) -> None:
        ctk.CTkLabel(parent, text=text.upper(), font=("Segoe UI", 10, "bold"),
                     text_color=ACCENT, anchor="w").pack(fill="x", pady=(0, 4))

    def _recenter(self) -> None:
        self.after(20, lambda: center_over(self, self.parent_window))

    # ── Step 1: how it works / current status ────────────────

    def _show_intro(self):
        body = self._new_step()
        status = self.db.emergency_access_status()
        self._step_caption(body, "Step 1 of 3" if status is None else "Emergency access")
        dialog_header(body, "Emergency Access",
                      "A safety net for when you can't unlock your vault yourself.",
                      wrap=CONTENT_WRAP)

        points = (
            ("user", "Pick people you trust",
             "Family members, a close friend, your lawyer - people who don't all know each other well is best."),
            ("key", "Give each of them one share",
             "A share is a short code (and QR). On its own it reveals nothing about your passwords."),
            ("shield", "Any K of them together can unlock",
             "If you forget your master password or are unavailable, enough trustees combine their "
             "shares on this computer to set a new one. Fewer than K learn nothing."),
        )
        for icon, title, text in points:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", pady=(10, 0))
            img = draw_icon(icon, ACCENT, (18, 18))
            ctk.CTkLabel(row, text="", image=img, width=28).pack(side="left", anchor="n", pady=(2, 0))
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", fill="x", expand=True, padx=(8, 0))
            ctk.CTkLabel(col, text=title, font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY,
                         anchor="w").pack(fill="x")
            ctk.CTkLabel(col, text=text, font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w",
                         justify="left", wraplength=CONTENT_WRAP - 40).pack(fill="x")

        if status is not None:
            box = ctk.CTkFrame(body, fg_color=SURFACE_ACTIVE, corner_radius=BUTTON_RADIUS,
                               border_width=1, border_color=BORDER)
            box.pack(fill="x", pady=(18, 0))
            top = ctk.CTkFrame(box, fg_color="transparent")
            top.pack(fill="x", padx=14, pady=(10, 0))
            ctk.CTkLabel(top, text="●  On", font=FONT_BODY_BOLD, text_color=SUCCESS,
                         anchor="w").pack(side="left")
            ctk.CTkLabel(top, text=f"{status['threshold']} of {status['shares']} trustees",
                         font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY).pack(side="right")
            created = status.get("created_at") or "unknown date"
            ctk.CTkLabel(box, text=f"Kit created {created}. Creating a new kit makes every "
                                   "old share stop working.",
                         font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w", justify="left",
                         wraplength=CONTENT_WRAP - 20).pack(fill="x", padx=14, pady=(2, 10))

            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", side="bottom", pady=(18, 0))
            ctk.CTkButton(row, text="Create new kit", command=self._show_choose,
                          **{**BTN_PRIMARY, "width": 140}).pack(side="right")
            ctk.CTkButton(row, text="Close", command=self._request_close,
                          **{**BTN_SECONDARY, "width": 96}).pack(side="right", padx=(0, 10))
            ctk.CTkButton(row, text="Turn off", command=self._turn_off,
                          **{**BTN_DANGER, "width": 96}).pack(side="left")
        else:
            dialog_buttons(body, "Get started", self._show_choose, self._request_close,
                           cancel_text="Not now")
        self._recenter()

    def _turn_off(self):
        if not messagebox.askyesno("Turn off Emergency Access?",
                                   "All shares you handed out will stop working immediately.\n\n"
                                   "Turn off emergency access?", icon="warning", parent=self):
            return
        try:
            self.db.disable_emergency_access()
        except Exception as e:
            logger.error("Disabling emergency access failed: %s", type(e).__name__)
            messagebox.showerror("Error", "Could not turn off emergency access.", parent=self)
            return
        self._show_intro()

    # ── Step 2: choose trustees ──────────────────────────────

    def _show_choose(self):
        body = self._new_step()
        self._step_caption(body, "Step 2 of 3")
        dialog_header(body, "Choose your trustees",
                      "How many people get a share, and how many are needed together?",
                      wrap=CONTENT_WRAP)

        caption_label(body, "Number of trustees").pack(fill="x", pady=(10, 6))
        self.n_seg = _segmented(body, [str(i) for i in range(emergency.MIN_TRUSTEES,
                                                              emergency.MAX_TRUSTEES + 1)],
                                self._on_n_changed)
        self.n_seg.pack(fill="x")
        self.n_seg.set(str(self.n_var))

        caption_label(body, "Shares needed to recover").pack(fill="x", pady=(16, 6))
        self.k_holder = ctk.CTkFrame(body, fg_color="transparent")
        self.k_holder.pack(fill="x")
        self.k_seg = None

        sentence_box = ctk.CTkFrame(body, fg_color=ACCENT_SOFT, corner_radius=BUTTON_RADIUS)
        sentence_box.pack(fill="x", pady=(18, 0))
        self.sentence = ctk.CTkLabel(sentence_box, text="", font=FONT_BODY_BOLD,
                                     text_color=TEXT_PRIMARY, anchor="w", justify="left",
                                     wraplength=CONTENT_WRAP - 10)
        self.sentence.pack(fill="x", padx=12, pady=(10, 0))
        self.hint = ctk.CTkLabel(sentence_box, text="", font=FONT_SMALL, text_color=TEXT_SECONDARY,
                                 anchor="w", justify="left", wraplength=CONTENT_WRAP - 10)
        self.hint.pack(fill="x", padx=12, pady=(2, 10))

        if self.db.emergency_access_status() is not None:
            _banner(body, "Creating a new kit replaces your current one - old shares stop working.",
                    danger=True).pack(fill="x", pady=(10, 0))

        self.choose_status = status_label(body, wrap=CONTENT_WRAP)
        self.choose_status.pack(fill="x", pady=(6, 0))
        dialog_buttons(body, "Create kit", self._create_kit, self._show_intro, cancel_text="Back")
        self._rebuild_k()
        self._recenter()

    def _on_n_changed(self, value: str):
        self.n_var = int(value)
        self.k_var = min(self.k_var, self.n_var)
        self._rebuild_k()

    def _rebuild_k(self):
        if self.k_seg is not None:
            self.k_seg.destroy()
        self.k_seg = _segmented(self.k_holder, [str(i) for i in range(2, self.n_var + 1)],
                                self._on_k_changed)
        self.k_seg.pack(fill="x" if self.n_var > 4 else "none", anchor="w")
        self.k_seg.set(str(self.k_var))
        self._update_sentence()

    def _on_k_changed(self, value: str):
        self.k_var = int(value)
        self._update_sentence()

    def _update_sentence(self):
        k, n = self.k_var, self.n_var
        self.sentence.configure(text=_trustee_sentence(k, n))
        if k == n:
            hint = "Every trustee is needed - if one share is lost, recovery becomes impossible."
        elif k == 2 and n > 3:
            hint = "Only two trustees need to cooperate; consider a higher number for more safety."
        else:
            hint = f"Up to {n - k} share(s) can be lost; {k - 1} trustee(s) alone learn nothing."
        self.hint.configure(text=hint)

    def _create_kit(self):
        if self.db.emergency_access_status() is not None:
            if not messagebox.askyesno("Replace kit?",
                                       "Your current shares will stop working.\n\nCreate a new kit?",
                                       icon="warning", parent=self):
                return
        try:
            self._shares = self.db.enable_emergency_access(self.vault_key, self.k_var, self.n_var)
            self._kit_status = self.db.emergency_access_status()
        except ValueError as e:
            self.choose_status.configure(text=str(e))
            return
        except Exception as e:
            logger.error("Creating emergency kit failed: %s", type(e).__name__)
            self.choose_status.configure(text="Could not create the emergency kit.")
            return
        self._show_share(0)

    # ── Step 3: hand out shares ──────────────────────────────

    def _show_share(self, idx: int):
        shares = self._shares or []
        total = len(shares)
        text = shares[idx]
        body = self._new_step()
        self._step_caption(body, f"Step 3 of 3  ·  Share {idx + 1} of {total}")
        dialog_header(body, f"Share {idx + 1} of {total}",
                      "Give this share to one trustee only. Print it, or save it and hand it over "
                      "on paper or a USB stick.", wrap=CONTENT_WRAP)

        if idx == 0:
            _banner(body, "Shares are shown only now and are never stored. If you lose them you "
                          "can create a new kit later.").pack(fill="x", pady=(6, 0))

        qr_frame = ctk.CTkFrame(body, fg_color="transparent")
        qr_frame.pack(pady=(12, 0))
        png = share_qr_png(text)
        qr_img = None
        if png:
            try:
                pil = Image.open(io.BytesIO(png)).convert("RGB")
                qr_img = ctk.CTkImage(light_image=pil, dark_image=pil, size=(QR_SIZE, QR_SIZE))
            except Exception as e:
                logger.debug("QR display failed: %s", type(e).__name__)
        if qr_img is not None:
            ctk.CTkLabel(qr_frame, text="", image=qr_img).pack()
        else:
            ctk.CTkLabel(qr_frame, text="QR code unavailable (install the 'qrcode' package).",
                         font=FONT_SMALL, text_color=TEXT_MUTED).pack()

        caption_label(body, "Share text").pack(fill="x", pady=(12, 6))
        box = ctk.CTkTextbox(body, height=58, font=FONT_MONO, wrap="word", fg_color=INPUT_BG,
                             border_color=INPUT_BORDER, border_width=1,
                             corner_radius=BUTTON_RADIUS, text_color=TEXT_PRIMARY)
        box.pack(fill="x")
        box.insert("1.0", text)
        box.configure(state="disabled")  # still selectable

        tools = ctk.CTkFrame(body, fg_color="transparent")
        tools.pack(fill="x", pady=(10, 0))
        ctk.CTkButton(tools, text="Copy", command=lambda: self._copy(idx),
                      **{**BTN_SECONDARY, "width": 90, "height": 32}).pack(side="left")
        ctk.CTkButton(tools, text="Save kit…", command=lambda: self._save_kit(idx),
                      **{**BTN_SECONDARY, "width": 110, "height": 32}).pack(side="left", padx=(8, 0))
        self.share_status = ctk.CTkLabel(tools, text="", font=FONT_SMALL, text_color=TEXT_MUTED,
                                         anchor="e")
        self.share_status.pack(side="right")

        last = idx == total - 1
        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x", side="bottom", pady=(16, 0))
        ctk.CTkButton(row, text="Finish" if last else "Next share",
                      command=self._show_confirm if last else (lambda: self._show_share(idx + 1)),
                      **{**BTN_PRIMARY, "width": 140}).pack(side="right")
        if idx > 0:
            ctk.CTkButton(row, text="Back", command=lambda: self._show_share(idx - 1),
                          **{**BTN_SECONDARY, "width": 96}).pack(side="right", padx=(0, 10))
        # Progress dots
        dots = ctk.CTkFrame(row, fg_color="transparent")
        dots.pack(side="left")
        for i in range(total):
            ctk.CTkFrame(dots, width=8, height=8, corner_radius=4,
                         fg_color=ACCENT if i == idx else BORDER).pack(side="left", padx=2)
        self._recenter()

    def _copy(self, idx: int):
        if not self._shares:
            return
        value = self._shares[idx]
        try:
            pyperclip.copy(value)
        except Exception as e:
            logger.error("Clipboard copy failed: %s", type(e).__name__)
            self.share_status.configure(text="Copy failed", text_color=DANGER)
            return
        self._clip_value = value
        if self._clip_job is not None:
            try:
                self.after_cancel(self._clip_job)
            except Exception:
                pass
        self._clip_job = self.after(settings.CLIPBOARD_TIMEOUT, self._clear_clipboard)
        self.share_status.configure(
            text=f"Copied · clears in {settings.CLIPBOARD_TIMEOUT // 1000}s", text_color=SUCCESS)

    def _clear_clipboard(self):
        self._clip_job = None
        value, self._clip_value = self._clip_value, None
        try:
            if value and pyperclip.paste() == value:
                pyperclip.copy("")
        except Exception:
            pass

    def _save_kit(self, idx: int):
        if not self._shares:
            return
        total = len(self._shares)
        text = self._shares[idx]
        path = filedialog.asksaveasfilename(
            parent=self, title="Save emergency share", defaultextension=".txt",
            initialfile=f"PyPass-Emergency-Share-{idx + 1}-of-{total}.txt",
            filetypes=[("Text file", "*.txt")])
        if not path:
            return
        status = self._kit_status or {}
        try:
            kit = printable_kit_text(text, idx + 1, total, int(status.get("threshold") or self.k_var),
                                     status.get("created_at") or "")
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(kit)
            png = share_qr_png(text)
            saved_qr = False
            if png:
                with open(os.path.splitext(path)[0] + ".png", "wb") as f:
                    f.write(png)
                saved_qr = True
        except OSError as e:
            logger.error("Saving emergency kit failed: %s", type(e).__name__)
            messagebox.showerror("Error", f"Could not save the kit:\n{e.strerror or e}", parent=self)
            return
        self.share_status.configure(text="Saved kit + QR" if saved_qr else "Saved kit",
                                    text_color=SUCCESS)

    # ── Final confirmation ───────────────────────────────────

    def _show_confirm(self):
        body = self._new_step()
        self._step_caption(body, "All shares created")
        k = int((self._kit_status or {}).get("threshold") or self.k_var)
        n = len(self._shares or [])
        dialog_header(body, "Emergency access is on", _trustee_sentence(k, n), wrap=CONTENT_WRAP)
        tips = ("Tell each trustee what the share is for and to keep it private.\n"
                "Shares will not be shown again - if one is lost, create a new kit.\n"
                "To recover, trustees choose “Use emergency kit” on the unlock screen.")
        for line in tips.split("\n"):
            ctk.CTkLabel(body, text="•  " + line, font=FONT_SMALL, text_color=TEXT_SECONDARY,
                         anchor="w", justify="left", wraplength=CONTENT_WRAP).pack(fill="x", pady=(6, 0))

        self.confirm_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(body, text="I've given each share to a different person",
                        variable=self.confirm_var, command=self._sync_done, font=FONT_BODY,
                        text_color=TEXT_PRIMARY, checkbox_width=20, checkbox_height=20).pack(
            fill="x", pady=(18, 0))

        row = ctk.CTkFrame(body, fg_color="transparent")
        row.pack(fill="x", side="bottom", pady=(16, 0))
        self.done_btn = ctk.CTkButton(row, text="Done", command=self._close,
                                      **{**BTN_PRIMARY, "width": 140})
        self.done_btn.pack(side="right")
        ctk.CTkButton(row, text="Back", command=lambda: self._show_share(n - 1),
                      **{**BTN_SECONDARY, "width": 96}).pack(side="right", padx=(0, 10))
        self._sync_done()
        self._recenter()

    def _sync_done(self):
        self.done_btn.configure(state="normal" if self.confirm_var.get() else "disabled",
                                fg_color=ACCENT if self.confirm_var.get() else SURFACE_ACTIVE)

    # ── Closing ──────────────────────────────────────────────

    def _request_close(self):
        if self._shares and not messagebox.askyesno(
                "Close without finishing?",
                "Shares are never shown again. If you haven't handed them all out, you'll need to "
                "create a new kit.\n\nClose anyway?", icon="warning", parent=self):
            return
        self._close()

    def _close(self):
        if self._closed:
            return
        self._closed = True
        if self._clip_job is not None:
            try:
                self.after_cancel(self._clip_job)
            except Exception:
                pass
        self._clear_clipboard()
        # Drop every reference to the share texts
        self._shares = None
        self.vault_key = None
        release_grab(self)
        self.destroy()
        try:
            if self.parent_window is not None and self.parent_window.winfo_exists():
                self.parent_window.focus()
        except Exception:
            pass


class EmergencyRecoveryDialog(ctk.CTkToplevel):
    """Combines trustee shares; calls success_callback(vault_key) when they unlock the vault."""

    ROW_WIDTH = SETUP_WIDTH - 2 * CARD_PAD - 60

    def __init__(self, master, db: PasswordDatabase, success_callback: Callable[[bytes], None]):
        super().__init__(master)
        self.db = db
        self.success_callback = success_callback
        self.parent_window = master
        self.rows: List[tuple] = []
        status = None
        try:
            status = db.emergency_access_status()
        except Exception:
            logger.debug("emergency_access_status failed", exc_info=True)
        self.status = status
        self.threshold = int(status["threshold"]) if status and status.get("threshold") else 2

        self.title("Emergency Recovery")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Escape>", lambda e: self._cancel())
        self._create_widgets()
        self.grab_set()
        self.lift()
        self.focus()
        self.after(60, lambda: center_over(self))

    def _create_widgets(self):
        main = dialog_card(self)
        if self.status:
            desc = (f"Enter at least {self.threshold} of the {self.status['shares']} trustee shares. "
                    "Dashes, spaces and letter case don't matter.")
        else:
            desc = "Enter the trustee shares. Dashes, spaces and letter case don't matter."
        dialog_header(main, "Recover with emergency kit", desc, wrap=CONTENT_WRAP)

        self.list_frame = ctk.CTkScrollableFrame(main, fg_color=SURFACE, height=290,
                                                 width=self.ROW_WIDTH + 20)
        self.list_frame.pack(fill="x", pady=(4, 0))

        self.add_btn = ctk.CTkButton(main, text="+  Add another share", command=self._add_row,
                                     **{**BTN_GHOST, "font": FONT_SMALL, "height": 28,
                                        "text_color": ACCENT})
        self.add_btn.pack(anchor="w", pady=(6, 0))

        self.status_label = status_label(main, wrap=CONTENT_WRAP)
        self.status_label.pack(fill="x", pady=(4, 0))
        _, self.recover_btn = dialog_buttons(main, "Recover", self._recover, self._cancel)

        for _ in range(self.threshold):
            self._add_row(focus=False)
        if self.rows:
            self.rows[0][0].focus()

    def _add_row(self, focus: bool = True):
        if len(self.rows) >= emergency.MAX_TRUSTEES:
            return
        n = len(self.rows) + 1
        frame = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        frame.pack(fill="x", pady=(0 if n == 1 else 10, 0))
        caption_label(frame, f"Share {n}").pack(fill="x", pady=(0, 4))
        entry = ctk.CTkEntry(frame, placeholder_text="PYPASS-XXXXXX-3of5-01-…",
                             **{**ENTRY_STYLE, "font": (FONT_MONO[0], 12), "width": self.ROW_WIDTH})
        entry.pack(fill="x")
        msg = ctk.CTkLabel(frame, text="", font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w",
                           justify="left", wraplength=self.ROW_WIDTH, height=18)
        msg.pack(fill="x", pady=(2, 0))
        entry.bind("<KeyRelease>", lambda e, i=n - 1: self._validate_row(i), add="+")
        entry.bind("<<Paste>>", lambda e, i=n - 1: self.after(10, lambda: self._validate_row(i)),
                   add="+")
        entry.bind("<Return>", lambda e: self._recover())
        self.rows.append((entry, msg))
        if len(self.rows) >= emergency.MAX_TRUSTEES:
            self.add_btn.configure(state="disabled", text="Maximum of 10 shares")
        if focus:
            entry.focus()
            self.after(50, lambda: self.list_frame._parent_canvas.yview_moveto(1.0))

    def _validate_row(self, i: int):
        entry, msg = self.rows[i]
        text = entry.get()
        if not text.strip():
            msg.configure(text="")
            entry.configure(border_color=INPUT_BORDER)
            return
        try:
            share = parse_share(text, "This share")
        except ShareError as e:
            msg.configure(text=str(e), text_color=DANGER)
            entry.configure(border_color=DANGER)
            return
        if self.status and share.setup_id != self.status.get("id"):
            msg.configure(text="⚠  This share belongs to an older emergency kit.",
                          text_color=SECONDARY)
            entry.configure(border_color=SECONDARY)
            return
        dup = any(j != i and self._index_of(j) == share.index for j in range(len(self.rows)))
        if dup:
            msg.configure(text=f"⚠  Share {share.index} of {share.total} was already entered above.",
                          text_color=SECONDARY)
            entry.configure(border_color=SECONDARY)
            return
        msg.configure(text=f"✓  Valid · share {share.index} of {share.total}",
                      text_color=SUCCESS)
        entry.configure(border_color=SUCCESS)

    def _index_of(self, j: int) -> Optional[int]:
        try:
            return parse_share(self.rows[j][0].get()).index
        except ShareError:
            return None

    def _recover(self):
        self.status_label.configure(text="")
        texts = [e.get() for e, _ in self.rows]
        try:
            vault_key = self.db.recover_with_shares(texts)
        except ShareError as e:
            self.status_label.configure(text=str(e), text_color=DANGER)
            return
        except Exception as e:
            logger.error("Emergency recovery error: %s", type(e).__name__)
            self.status_label.configure(text="Recovery failed unexpectedly.", text_color=DANGER)
            return
        self._clear_entries()
        release_grab(self)
        self.destroy()
        self.success_callback(vault_key)

    def _clear_entries(self):
        for entry, _ in self.rows:
            try:
                entry.delete(0, "end")
            except Exception:
                pass

    def _cancel(self):
        self._clear_entries()
        release_grab(self)
        self.destroy()
        if hasattr(self.parent_window, 'deiconify_and_focus'):
            self.parent_window.deiconify_and_focus()

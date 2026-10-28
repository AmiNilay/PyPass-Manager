# password_manager/app/ui/widgets.py
"""
Shared UI building blocks: image/icon helpers, tooltips, window helpers and
the generic dialog/form widgets used across the application's screens.
"""
import logging
import math
import os
from typing import Callable, Iterable, Optional, Tuple

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageFont

from config import settings
from app.ui.theme import (BG, SURFACE_HOVER, SURFACE_ACTIVE, BORDER, BORDER_STRONG, DANGER,
                          SECONDARY, INPUT_BG, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
                          FONT_DISPLAY, FONT_HEADING, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
                          FONT_CAPTION, BTN_PRIMARY, BTN_SECONDARY, ENTRY_STYLE, CARD_STYLE)

# Layout constants for auth screens and card dialogs
DIALOG_WIDTH = 420          # outer width of card dialogs
FIELD_WIDTH = 320           # standard full-width input
CARD_PAD = 24               # inner padding of dialog cards
TK_LOCK_MASK = 0x0002       # Tk event.state bit for Caps Lock

Size = Tuple[int, int]


# ── Images ────────────────────────────────────────────────────

def load_icon(file_path: Optional[str], size: Size = (20, 20),
              tint: Optional[str] = None) -> Optional[ctk.CTkImage]:
    """Loads a PNG as a CTkImage, optionally recoloured to a solid tint. None on failure."""
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        img = Image.open(file_path)
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        if tint:
            alpha = img.split()[3]
            solid = Image.new('RGBA', img.size, tint)
            solid.putalpha(alpha)
            img = solid
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception as e:
        logging.error(f"Failed to load icon {file_path}: {e}")
        return None


def draw_icon(kind: str, color: str, size: Size = (18, 18)) -> Optional[ctk.CTkImage]:
    """Small vector-style glyphs drawn with PIL (supersampled) for icons not shipped as PNGs."""
    s = 96
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    w = 8  # stroke width at 96px

    def p(*pts):
        return [(x * s, y * s) for x, y in pts]

    try:
        if kind == 'grid':
            for x0, y0 in ((0.14, 0.14), (0.56, 0.14), (0.14, 0.56), (0.56, 0.56)):
                d.rounded_rectangle([x0 * s, y0 * s, (x0 + 0.30) * s, (y0 + 0.30) * s], radius=7,
                                    outline=color, width=w)
        elif kind in ('star', 'star_outline'):
            pts = []
            for i in range(10):
                r = 0.44 if i % 2 == 0 else 0.19
                a = math.radians(-90 + i * 36)
                pts.append((0.5 + r * math.cos(a), 0.54 + r * math.sin(a)))
            if kind == 'star':
                d.polygon(p(*pts), fill=color)
            else:
                d.line(p(*pts, pts[0]), fill=color, width=w, joint="curve")
        elif kind == 'shield':
            pts = ((0.5, 0.08), (0.84, 0.2), (0.82, 0.52), (0.5, 0.9), (0.18, 0.52), (0.16, 0.2))
            d.line(p(*pts, pts[0]), fill=color, width=w, joint="curve")
            d.line(p((0.36, 0.48), (0.47, 0.59), (0.66, 0.38)), fill=color, width=w, joint="curve")
        elif kind == 'lock':
            d.rounded_rectangle([0.2 * s, 0.44 * s, 0.8 * s, 0.88 * s], radius=10, outline=color, width=w)
            d.arc([0.32 * s, 0.12 * s, 0.68 * s, 0.6 * s], 180, 360, fill=color, width=w)
            d.line(p((0.32, 0.36), (0.32, 0.45)), fill=color, width=w)
            d.line(p((0.68, 0.36), (0.68, 0.45)), fill=color, width=w)
            d.ellipse([0.45 * s, 0.6 * s, 0.55 * s, 0.7 * s], fill=color)
        elif kind == 'lock_solid':
            d.rounded_rectangle([0.2 * s, 0.44 * s, 0.8 * s, 0.88 * s], radius=10, fill=color)
            d.arc([0.32 * s, 0.12 * s, 0.68 * s, 0.6 * s], 180, 360, fill=color, width=w + 2)
            d.line(p((0.32, 0.36), (0.32, 0.46)), fill=color, width=w + 2)
            d.line(p((0.68, 0.36), (0.68, 0.46)), fill=color, width=w + 2)
        elif kind == 'key':
            d.ellipse([0.1 * s, 0.3 * s, 0.48 * s, 0.68 * s], outline=color, width=w)
            d.line(p((0.46, 0.49), (0.9, 0.49)), fill=color, width=w)
            d.line(p((0.78, 0.49), (0.78, 0.66)), fill=color, width=w)
            d.line(p((0.66, 0.49), (0.66, 0.62)), fill=color, width=w)
        elif kind == 'help':
            d.ellipse([0.1 * s, 0.1 * s, 0.9 * s, 0.9 * s], outline=color, width=w)
            try:
                f = ImageFont.truetype("segoeuib.ttf", 52)
            except Exception:
                f = ImageFont.load_default()
            d.text((0.5 * s, 0.52 * s), "?", fill=color, font=f, anchor="mm")
        elif kind == 'user':
            d.ellipse([0.33 * s, 0.1 * s, 0.67 * s, 0.44 * s], outline=color, width=w)
            d.arc([0.16 * s, 0.54 * s, 0.84 * s, 1.18 * s], 180, 360, fill=color, width=w)
        elif kind == 'plus':
            d.line(p((0.5, 0.18), (0.5, 0.82)), fill=color, width=w + 2)
            d.line(p((0.18, 0.5), (0.82, 0.5)), fill=color, width=w + 2)
        elif kind == 'search':
            d.ellipse([0.14 * s, 0.14 * s, 0.66 * s, 0.66 * s], outline=color, width=w)
            d.line(p((0.6, 0.6), (0.86, 0.86)), fill=color, width=w + 2)
        elif kind == 'sparkle':
            d.polygon(p((0.5, 0.08), (0.6, 0.4), (0.92, 0.5), (0.6, 0.6), (0.5, 0.92), (0.4, 0.6),
                        (0.08, 0.5), (0.4, 0.4)), fill=color)
        elif kind == 'warning':
            pts = ((0.5, 0.1), (0.92, 0.86), (0.08, 0.86))
            d.line(p(*pts, pts[0]), fill=color, width=w, joint="curve")
            d.line(p((0.5, 0.38), (0.5, 0.6)), fill=color, width=w)
            d.ellipse([0.45 * s, 0.68 * s, 0.55 * s, 0.78 * s], fill=color)
        elif kind == 'lifebuoy':
            d.ellipse([0.1 * s, 0.1 * s, 0.9 * s, 0.9 * s], outline=color, width=w)
            d.ellipse([0.32 * s, 0.32 * s, 0.68 * s, 0.68 * s], outline=color, width=w)
            for a in (45, 135, 225, 315):
                r = math.radians(a)
                d.line(p((0.5 + 0.18 * math.cos(r), 0.5 + 0.18 * math.sin(r)),
                         (0.5 + 0.4 * math.cos(r), 0.5 + 0.4 * math.sin(r))), fill=color, width=w)
        else:
            return None
    except Exception as e:
        logging.debug(f"draw_icon({kind}) failed: {e}")
        return None
    img = img.resize((size[0] * 2, size[1] * 2), Image.LANCZOS)
    return ctk.CTkImage(light_image=img, dark_image=img, size=size)


# ── Tooltip ───────────────────────────────────────────────────

class Tooltip:
    """Delayed hover tooltip shown just below `widget`."""

    def __init__(self, widget, text: str, delay: int = 450, wraplength: int = 240):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.wraplength = wraplength
        self.tooltip_window = None
        self._id = None
        self.widget.bind("<Enter>", self._schedule)
        self.widget.bind("<Leave>", self._hide)
        self.widget.bind("<ButtonPress>", self._hide)

    def _schedule(self, event=None):
        self._hide(cancel_timer_only=True)
        self._id = self.widget.after(self.delay, self._show)

    def _show(self, event=None):
        self._id = None
        if self.tooltip_window or not self.widget.winfo_exists():
            return
        x = self.widget.winfo_rootx() + 4
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tooltip_window = ctk.CTkToplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.configure(fg_color=BORDER_STRONG)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = ctk.CTkLabel(self.tooltip_window, text=self.text,
                             fg_color=SURFACE_ACTIVE, text_color=TEXT_PRIMARY,
                             corner_radius=0, padx=10, pady=5,
                             wraplength=self.wraplength, justify="left", font=FONT_SMALL)
        label.pack(padx=1, pady=1)
        self.tooltip_window.lift()

    def _hide(self, event=None, cancel_timer_only=False):
        if self._id is not None:
            try:
                self.widget.after_cancel(self._id)
            except Exception:
                pass
            self._id = None
        if not cancel_timer_only and self.tooltip_window:
            try:
                self.tooltip_window.destroy()
            except Exception:
                pass
            self.tooltip_window = None


# ── Window helpers ────────────────────────────────────────────

def center_over(window, ref=None, require_viewable: bool = True) -> None:
    """Centres `window` over `ref`, or on screen when there is no (viewable) reference.

    With require_viewable=False, `ref` is used whenever it exists, even if withdrawn.
    """
    try:
        window.update_idletasks()
        w, h = window.winfo_width(), window.winfo_height()
        if ref is not None and ref.winfo_exists() and (ref.winfo_viewable() or not require_viewable):
            rx, ry, rw, rh = ref.winfo_x(), ref.winfo_y(), ref.winfo_width(), ref.winfo_height()
        else:
            rx, ry, rw, rh = 0, 0, window.winfo_screenwidth(), window.winfo_screenheight()
        window.geometry(f"+{max(0, rx + (rw - w) // 2)}+{max(0, ry + (rh - h) // 2)}")
    except Exception:
        logging.debug("center_over failed", exc_info=True)


def release_grab(window) -> None:
    """grab_release() that tolerates windows that are already gone."""
    try:
        window.grab_release()
    except Exception:
        pass


def set_window_icon(window) -> None:
    """Applies the app icon (.ico preferred, .png fallback) to a toplevel window."""
    icon_path = settings.APP_ICON_FILE_ICO
    if not os.path.exists(icon_path) or not icon_path.endswith(".ico"):
        icon_path = settings.APP_ICON_FILE_PNG
    if os.path.exists(icon_path):
        try:
            window.iconbitmap(icon_path)
        except Exception as e:
            logging.debug(f"Setting window icon failed: {e}")


# ── Form widgets ──────────────────────────────────────────────

def caption_label(parent, text: str) -> ctk.CTkLabel:
    """Uppercase caption-style field label."""
    return ctk.CTkLabel(parent, text=text.upper(), font=FONT_CAPTION,
                        text_color=TEXT_SECONDARY, anchor="w")


def add_visibility_toggle(entry: ctk.CTkEntry) -> ctk.CTkButton:
    """Adds a show/hide eye button inside a masked CTkEntry."""
    shown_icon = load_icon(settings.VISIBLE_ICON_FILE, (16, 16), tint=TEXT_SECONDARY)
    hidden_icon = load_icon(settings.HIDDEN_ICON_FILE, (16, 16), tint=TEXT_SECONDARY)
    state = {"visible": False}

    btn = ctk.CTkButton(entry, text="" if hidden_icon else "Show", width=28, height=28,
                        image=hidden_icon, fg_color=INPUT_BG, hover_color=SURFACE_HOVER,
                        text_color=TEXT_SECONDARY, font=FONT_SMALL, corner_radius=6,
                        border_width=0, cursor="hand2")

    def toggle():
        state["visible"] = not state["visible"]
        entry.configure(show="" if state["visible"] else "*")
        if shown_icon and hidden_icon:
            btn.configure(image=shown_icon if state["visible"] else hidden_icon)
        else:
            btn.configure(text="Hide" if state["visible"] else "Show")

    btn.configure(command=toggle)
    btn.place(relx=1.0, x=-6, rely=0.5, anchor="e")
    return btn


def bind_caps_lock_warning(entries: Iterable[ctk.CTkEntry], label: ctk.CTkLabel) -> None:
    """Shows 'Caps Lock is on' in `label` while typing in any of `entries` with Caps Lock active."""
    def check(event):
        try:
            on = bool(event.state & TK_LOCK_MASK)
            # On the Caps_Lock key itself, state reflects the value before the toggle
            if event.keysym == "Caps_Lock" and str(event.type) in ("2", "KeyPress"):
                on = not on
            label.configure(text="Caps Lock is on" if on else "")
        except Exception:
            pass

    for e in entries:
        e.bind("<KeyPress>", check, add="+")
        e.bind("<FocusIn>", check, add="+")


def password_entry(parent, placeholder: str = "", width: int = FIELD_WIDTH,
                   toggle: bool = True) -> ctk.CTkEntry:
    """Masked entry in the standard style, with an optional show/hide toggle."""
    entry = ctk.CTkEntry(parent, placeholder_text=placeholder, show="*",
                         **{**ENTRY_STYLE, "width": width})
    if toggle:
        add_visibility_toggle(entry)
    return entry


def labeled_field(parent, label: str, entry_factory: Callable, top_pad: int = 14):
    """Caption label above a field. entry_factory(container) must return the entry widget."""
    caption_label(parent, label).pack(fill="x", pady=(top_pad, 6))
    entry = entry_factory(parent)
    entry.pack(fill="x")
    return entry


def status_label(parent, wrap: int = DIALOG_WIDTH - 2 * CARD_PAD - 40) -> ctk.CTkLabel:
    """Inline error/notice text, left-aligned, initially empty."""
    return ctk.CTkLabel(parent, text="", font=FONT_SMALL, text_color=DANGER, anchor="w",
                        justify="left", wraplength=wrap, height=20)


def caps_label(parent) -> ctk.CTkLabel:
    """Empty label that bind_caps_lock_warning() fills in."""
    return ctk.CTkLabel(parent, text="", font=FONT_SMALL, text_color=SECONDARY, anchor="w",
                        height=20)


# ── Dialog layout ─────────────────────────────────────────────

def dialog_card(window) -> ctk.CTkFrame:
    """Builds the standard card body in a dialog window. Returns the inner content frame."""
    window.configure(fg_color=BG)
    card = ctk.CTkFrame(window, **CARD_STYLE)
    card.pack(padx=16, pady=16, fill="both", expand=True)
    inner = ctk.CTkFrame(card, fg_color="transparent")
    inner.pack(padx=CARD_PAD, pady=CARD_PAD, fill="both", expand=True)
    return inner


def dialog_header(parent, title: str, description: Optional[str] = None,
                  wrap: int = DIALOG_WIDTH - 2 * CARD_PAD - 40) -> None:
    """Dialog title, optional description and a divider line."""
    ctk.CTkLabel(parent, text=title, font=FONT_HEADING, text_color=TEXT_PRIMARY,
                 anchor="w", justify="left").pack(fill="x")
    if description:
        ctk.CTkLabel(parent, text=description, font=FONT_BODY, text_color=TEXT_SECONDARY,
                     anchor="w", justify="left", wraplength=wrap).pack(fill="x", pady=(4, 0))
    ctk.CTkFrame(parent, height=1, fg_color=BORDER, corner_radius=0).pack(fill="x", pady=(18, 4))


def dialog_buttons(parent, primary_text: str, primary_cmd: Callable, cancel_cmd: Callable,
                   cancel_text: str = "Cancel", primary_style: Optional[dict] = None
                   ) -> Tuple[ctk.CTkButton, ctk.CTkButton]:
    """Right-aligned Cancel (secondary) + primary action row. Returns (cancel_btn, primary_btn)."""
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(16, 0))
    primary = ctk.CTkButton(row, text=primary_text, command=primary_cmd,
                            **{**(primary_style or BTN_PRIMARY), "width": 140})
    primary.pack(side="right")
    cancel = ctk.CTkButton(row, text=cancel_text, command=cancel_cmd,
                           **{**BTN_SECONDARY, "width": 96})
    cancel.pack(side="right", padx=(0, 10))
    return cancel, primary


def brand_header(parent, title: str, subtitle: str) -> None:
    """App icon + wordmark, then title and subtitle, centred (login / lock screens)."""
    brand = ctk.CTkFrame(parent, fg_color="transparent")
    brand.pack(pady=(0, 28))
    icon = load_icon(settings.APP_ICON_FILE_PNG, (28, 28))
    if icon:
        ctk.CTkLabel(brand, text="", image=icon).pack(side="left", padx=(0, 10))
    ctk.CTkLabel(brand, text="PyPass Manager",
                 font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY).pack(side="left")
    ctk.CTkLabel(parent, text=title, font=FONT_DISPLAY, text_color=TEXT_PRIMARY).pack()
    ctk.CTkLabel(parent, text=subtitle, font=FONT_BODY, text_color=TEXT_SECONDARY,
                 wraplength=FIELD_WIDTH, justify="center").pack(pady=(6, 24))


def security_footer(parent) -> None:
    """Encryption summary line pinned to the bottom of the auth screens."""
    ctk.CTkLabel(parent, text="Stored encrypted on this device  ·  AES-128 (Fernet)  ·  PBKDF2-SHA256",
                 font=FONT_SMALL, text_color=TEXT_MUTED).pack(side="bottom", pady=(0, 18))

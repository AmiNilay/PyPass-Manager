# password_manager/app/ui/password_generator.py
"""
Password / passphrase generator dialog.

All randomness comes from the `secrets` module (CSPRNG).
"""
import logging
import secrets
import string
import tkinter as tk

import customtkinter as ctk
import pyperclip

from config import settings
from app.core.password_utils import check_password_strength
from app.ui.theme import (
    BG, SURFACE, SURFACE_HOVER, SURFACE_ACTIVE, BORDER, ACCENT, SECONDARY, SUCCESS, DANGER,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED, TEXT_ON_ACCENT, INPUT_BG,
    FONT_HEADING, FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_CAPTION, FONT_MONO,
    BUTTON_RADIUS, PAD_X, PAD_Y, ICON_SIZE_SM,
    BTN_PRIMARY, BTN_SECONDARY, CARD_STYLE,
)
from app.ui.widgets import load_icon, center_over, release_grab


# ── Generation rules ──────────────────────────────────────────
MIN_LENGTH = 8
MAX_LENGTH = 128
SLIDER_MIN, SLIDER_MAX = 8, 64
DEFAULT_LENGTH = 20

MIN_WORDS, MAX_WORDS, DEFAULT_WORDS = 3, 8, 5
WORD_SEPARATOR = "-"

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
AMBIGUOUS = set("Il1O0")

# ~200 short, common, unambiguous English words for passphrases.
WORDLIST = (
    "able acid aged also area army away baby back ball band bank base bath bear beat "
    "bell belt best bird blue boat body bold bone book born boss both bowl bulk burn "
    "bush busy cake calm camp card care cart case cash cast cell chat chef chip city "
    "clay club coal coat code cold cook cool copy core corn cost crew crop cube cure "
    "dark data dawn deal deck deep deer desk dial dish dock door dove draw drum duck "
    "dust duty each earn east easy edge exit face fact fair farm fast fern file film "
    "fine fire firm fish flag flat foam fold food fork form fort frog fuel gate gear "
    "gift glad glow goal gold golf good grid grow gulf hall hand harp hawk head heat "
    "herb hero hill hint home hope horn host idea inch iron jade jazz join jump keen "
    "kept kind king kite knee lake lamp land lane leaf lens lift lime line link lion "
    "list loaf lock loft loud lucky lunar maple march mango metal mint moon moss nest "
    "noble north ocean olive orbit panda paper pearl piano pilot plum polar quiet "
    "radar raven river robin rocket royal ruby salad sand scout shell silk solar "
    "spark stone storm sugar swift table tiger toast topaz tower trail tulip urban "
    "valley velvet violet water whale willow winter yacht zebra"
).split()


def _filter(chars: str, avoid_ambiguous: bool) -> str:
    return "".join(c for c in chars if c not in AMBIGUOUS) if avoid_ambiguous else chars


def generate_password(length: int = DEFAULT_LENGTH, use_upper: bool = True, use_lower: bool = True,
                      use_digits: bool = True, use_symbols: bool = True,
                      avoid_ambiguous: bool = False) -> str:
    """Random password with at least one character from every enabled class."""
    length = max(MIN_LENGTH, min(int(length), MAX_LENGTH))
    classes = [_filter(chars, avoid_ambiguous) for chars, on in (
        (UPPER, use_upper), (LOWER, use_lower), (DIGITS, use_digits), (SYMBOLS, use_symbols)) if on]
    if not classes:
        classes = [_filter(LOWER, avoid_ambiguous)]

    chars = [secrets.choice(c) for c in classes]
    pool = "".join(classes)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_strong_password(length: int) -> str:
    """Secure password containing upper, lower, digit and symbol (length >= 8)."""
    return generate_password(length, True, True, True, True, False)


def generate_passphrase(words: int = DEFAULT_WORDS, capitalize: bool = True,
                        include_number: bool = True, separator: str = WORD_SEPARATOR) -> str:
    """Diceware-style passphrase from the built-in word list."""
    words = max(MIN_WORDS, min(int(words), MAX_WORDS))
    picked = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        picked = [w.capitalize() for w in picked]
    if include_number:
        i = secrets.randbelow(words)
        picked[i] = picked[i] + str(secrets.randbelow(10))
    return separator.join(picked)


def _strength_color(score: int) -> str:
    return {0: DANGER, 1: DANGER, 2: SECONDARY, 3: ACCENT}.get(score, SUCCESS)


class PasswordGeneratorWindow(ctk.CTkToplevel):
    """Modal password / passphrase generator with copy-to-clipboard."""

    WIDTH = 500

    def __init__(self, master):
        super().__init__(master)
        self.configure(fg_color=BG)
        self.title("Password Generator")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._current = ""
        self._copied_value = None
        self._clear_job = None
        self._status_job = None

        self.mode_var = ctk.StringVar(value="Password")
        self.length_var = ctk.IntVar(value=DEFAULT_LENGTH)
        self.words_var = ctk.IntVar(value=DEFAULT_WORDS)
        self.upper_var = ctk.BooleanVar(value=True)
        self.lower_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.symbols_var = ctk.BooleanVar(value=True)
        self.ambiguous_var = ctk.BooleanVar(value=False)
        self.capitalize_var = ctk.BooleanVar(value=True)
        self.number_var = ctk.BooleanVar(value=True)
        self.status_var = ctk.StringVar(value="")

        self.copy_icon = load_icon(settings.COPY_ICON_FILE, size=ICON_SIZE_SM, tint=TEXT_ON_ACCENT)
        self.refresh_icon = load_icon(settings.GENERATE_ICON_FILE, size=ICON_SIZE_SM, tint=TEXT_PRIMARY)

        self._create_widgets()
        self._show_mode()
        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Control-c>", lambda _e: self._copy())
        self.after(50, lambda: center_over(self, self.master))

    # ── UI ────────────────────────────────────────────────────
    def _create_widgets(self):
        self.grid_columnconfigure(0, weight=1, minsize=self.WIDTH)

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=PAD_X, pady=(PAD_X - 2, PAD_Y))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Generator", font=FONT_HEADING, text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Create a strong, unique credential", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").grid(row=1, column=0, sticky="w")
        self.mode_switch = ctk.CTkSegmentedButton(
            header, values=["Password", "Passphrase"], variable=self.mode_var,
            command=lambda _v: self._show_mode(), font=FONT_SMALL, height=30,
            corner_radius=BUTTON_RADIUS, fg_color=INPUT_BG, unselected_color=INPUT_BG,
            selected_color=SURFACE_ACTIVE, selected_hover_color=SURFACE_ACTIVE,
            unselected_hover_color=SURFACE_HOVER, text_color=TEXT_PRIMARY)
        self.mode_switch.grid(row=0, column=1, rowspan=2, sticky="e")

        # Result card
        card = ctk.CTkFrame(self, **CARD_STYLE)
        card.grid(row=1, column=0, sticky="ew", padx=PAD_X)
        card.grid_columnconfigure(0, weight=1)

        self._mono_fonts = {s: ctk.CTkFont(family=FONT_MONO[0], size=s) for s in (13, 16, 20)}
        self.output = ctk.CTkTextbox(
            card, height=60, wrap="char", activate_scrollbars=False,
            font=self._mono_fonts[20], fg_color=SURFACE,
            text_color=TEXT_PRIMARY, border_width=0, corner_radius=0)
        self.output.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 4))
        tb = self.output._textbox
        tb.configure(cursor="arrow", spacing1=2, spacing3=2, insertwidth=0,
                     selectbackground=SURFACE, inactiveselectbackground=SURFACE)
        self.output.tag_config("digit", foreground=ACCENT)
        self.output.tag_config("symbol", foreground=SECONDARY)
        self.output.configure(state="disabled")

        meter = ctk.CTkFrame(card, fg_color="transparent")
        meter.grid(row=1, column=0, sticky="ew", padx=PAD_Y + 2, pady=(4, PAD_Y))
        meter.grid_columnconfigure(0, weight=1)
        self.strength_bar = ctk.CTkProgressBar(meter, height=4, corner_radius=2, fg_color=BORDER)
        self.strength_bar.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self.strength_lbl = ctk.CTkLabel(meter, text="", font=FONT_SMALL, text_color=TEXT_SECONDARY,
                                         anchor="e")
        self.strength_lbl.grid(row=0, column=1, sticky="e")

        # Options card (one per mode, swapped in row 2)
        self.pw_opts = self._build_password_options()
        self.pp_opts = self._build_passphrase_options()

        # Actions
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=3, column=0, sticky="ew", padx=PAD_X, pady=(PAD_Y + 4, 0))
        actions.grid_columnconfigure((0, 1), weight=1, uniform="a")
        ctk.CTkButton(actions, text="Regenerate", image=self.refresh_icon, compound="left",
                      command=self._generate, **{**BTN_SECONDARY, "height": 40}
                      ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(actions, text="Copy", image=self.copy_icon, compound="left",
                      command=self._copy, **{**BTN_PRIMARY, "height": 40}
                      ).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.status_lbl = ctk.CTkLabel(self, textvariable=self.status_var, font=FONT_SMALL,
                                       text_color=TEXT_MUTED, height=20)
        self.status_lbl.grid(row=4, column=0, pady=(10, PAD_Y))

    def _options_card(self):
        frame = ctk.CTkFrame(self, **CARD_STYLE)
        frame.grid_columnconfigure(0, weight=1)
        return frame

    def _section_label(self, parent, row, text):
        ctk.CTkLabel(parent, text=text.upper(), font=FONT_CAPTION, text_color=TEXT_MUTED,
                     anchor="w").grid(row=row, column=0, sticky="w", padx=PAD_Y + 2, pady=(10, 2))

    def _slider_row(self, parent, row, label, var, lo, hi):
        box = ctk.CTkFrame(parent, fg_color="transparent")
        box.grid(row=row, column=0, sticky="ew", padx=PAD_Y + 2, pady=(PAD_Y - 2, 0))
        box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(box, text=label, font=FONT_BODY, text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="w")
        value = ctk.CTkLabel(box, textvariable=var, font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY,
                             fg_color=INPUT_BG, corner_radius=6, width=44, height=26)
        value.grid(row=0, column=1, sticky="e")
        # A bound variable keeps CTkSlider.destroy() from tripping over a missing trace.
        slider = ctk.CTkSlider(box, from_=lo, to=hi, number_of_steps=hi - lo, variable=var, height=16,
                               command=lambda _v: self._generate())
        slider.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        return slider

    def _switch_row(self, parent, row, text, var, divider=True):
        if divider:
            ctk.CTkFrame(parent, height=1, fg_color=BORDER, corner_radius=0).grid(
                row=row, column=0, sticky="ew", padx=PAD_Y + 2)
        line = ctk.CTkFrame(parent, fg_color="transparent")
        line.grid(row=row + 1, column=0, sticky="ew", padx=PAD_Y + 2, pady=4)
        line.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(line, text=text, font=FONT_BODY, text_color=TEXT_PRIMARY,
                     anchor="w").grid(row=0, column=0, sticky="w")
        sw = ctk.CTkSwitch(line, text="", variable=var, width=40, switch_width=36, switch_height=18,
                           command=lambda v=var: self._on_toggle(v))
        sw.grid(row=0, column=1, sticky="e")
        return sw

    def _build_password_options(self):
        f = self._options_card()
        self._slider_row(f, 0, "Length", self.length_var, SLIDER_MIN, SLIDER_MAX)
        self._section_label(f, 1, "Characters")
        self._switch_row(f, 2, "Uppercase  (A–Z)", self.upper_var, divider=False)
        self._switch_row(f, 4, "Lowercase  (a–z)", self.lower_var)
        self._switch_row(f, 6, "Numbers  (0–9)", self.digits_var)
        self._switch_row(f, 8, "Symbols  (!@#$%^&*)", self.symbols_var)
        self._switch_row(f, 10, "Avoid ambiguous characters  (Il1O0)", self.ambiguous_var)
        ctk.CTkFrame(f, height=6, fg_color="transparent").grid(row=12, column=0)
        return f

    def _build_passphrase_options(self):
        f = self._options_card()
        self._slider_row(f, 0, "Words", self.words_var, MIN_WORDS, MAX_WORDS)
        self._section_label(f, 1, "Options")
        self._switch_row(f, 2, "Capitalize words", self.capitalize_var, divider=False)
        self._switch_row(f, 4, "Include a number", self.number_var)
        ctk.CTkLabel(f, text=f"Words are separated by “{WORD_SEPARATOR}”", font=FONT_SMALL,
                     text_color=TEXT_MUTED, anchor="w").grid(row=6, column=0, sticky="w",
                                                             padx=PAD_Y + 2, pady=(4, PAD_Y))
        return f

    # ── Behaviour ─────────────────────────────────────────────
    def _show_mode(self):
        is_pw = self.mode_var.get() == "Password"
        (self.pp_opts if is_pw else self.pw_opts).grid_remove()
        (self.pw_opts if is_pw else self.pp_opts).grid(row=2, column=0, sticky="ew",
                                                       padx=PAD_X, pady=(12, 0))
        self._generate()

    def _on_toggle(self, var):
        char_vars = (self.upper_var, self.lower_var, self.digits_var, self.symbols_var)
        if var in char_vars and not any(v.get() for v in char_vars):
            var.set(True)  # at least one character class must stay enabled
            self._flash("At least one character type is required.")
            return
        self._generate()

    def _generate(self):
        if self.mode_var.get() == "Password":
            value = generate_password(self.length_var.get(), self.upper_var.get(), self.lower_var.get(),
                                      self.digits_var.get(), self.symbols_var.get(),
                                      self.ambiguous_var.get())
        else:
            value = generate_passphrase(self.words_var.get(), self.capitalize_var.get(),
                                        self.number_var.get())
        self._current = value
        self._render(value)

    def _render(self, value):
        # Scale the mono font down for long values so they fit in two lines.
        size = 20 if len(value) <= 28 else 16 if len(value) <= 44 else 13
        self.output.configure(font=self._mono_fonts[size], state="normal")
        self.output.delete("1.0", "end")
        for ch in value:
            if ch.isdigit():
                self.output.insert("end", ch, "digit")
            elif not ch.isalnum():
                self.output.insert("end", ch, "symbol")
            else:
                self.output.insert("end", ch)
        self.output.configure(state="disabled")

        score, text, _ = check_password_strength(value)
        color = _strength_color(score)
        self.strength_bar.configure(progress_color=color)
        self.strength_bar.set((score + 1) / 5)
        self.strength_lbl.configure(text=f"{text}  ·  {len(value)} chars")

    def _flash(self, message, ms=4000):
        self.status_var.set(message)
        if self._status_job:
            self.after_cancel(self._status_job)
        self._status_job = self.after(ms, lambda: self.status_var.set(""))

    def _copy(self):
        text = self._current
        if not text:
            return
        try:
            pyperclip.copy(text)
            self._copied_value = text
            if self._clear_job:
                self.after_cancel(self._clear_job)
            self._clear_job = self.after(settings.CLIPBOARD_TIMEOUT, self._clear_clipboard)
            if self._status_job:
                self.after_cancel(self._status_job)
                self._status_job = None
            self.status_var.set(f"Copied — clipboard clears in {settings.CLIPBOARD_TIMEOUT // 1000}s")
        except Exception as e:
            logging.error(f"Copy failed: {e}")
            self._flash("Couldn't copy to the clipboard.")

    def _clear_clipboard(self):
        """Clear the clipboard only if it still holds the value we copied."""
        self._clear_job = None
        value, self._copied_value = self._copied_value, None
        if not value:
            return
        try:
            if pyperclip.paste() == value:
                pyperclip.copy('')
                try:
                    self.status_var.set("Clipboard cleared")
                except Exception:
                    pass
        except Exception:
            pass

    def destroy(self):
        for job in ("_clear_job", "_status_job"):
            try:
                if getattr(self, job, None):
                    self.after_cancel(getattr(self, job))
            except Exception:
                pass
        if hasattr(self, '_copied_value'):
            self._clear_clipboard()
        release_grab(self)
        try:
            super().destroy()
        except AttributeError:
            # CustomTkinter CTkSlider destroy bug workaround
            try:
                tk.Toplevel.destroy(self)
            except Exception:
                pass
        except Exception:
            pass

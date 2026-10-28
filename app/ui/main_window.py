# password_manager/app/ui/main_window.py
"""
The vault window (sidebar, item list, Security view) and the add/edit item dialog.
"""
import atexit
import hashlib
import logging
import threading
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from tkinter import messagebox
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import customtkinter as ctk
import pyperclip

from config import settings
from app.core.database import PasswordDatabase
from app.core.encryption import encrypt_data, decrypt_data, DECRYPTION_ERROR
from app.core import breach, phishing
from app.core.favicons import guess_domain, get_logo_async, domain_from_url
from app.core.password_utils import check_password_strength
from app.ui.lock_screen import LockScreen
from app.ui.master_password_prompt import MasterPasswordPrompt, ChangeMasterPasswordDialog
from app.ui.password_generator import PasswordGeneratorWindow
from app.ui.security_questions_setup_dialog import SecurityQuestionsSetupDialog
from app.ui.theme import (BG, SIDEBAR, SURFACE, SURFACE_HOVER, SURFACE_ACTIVE, BORDER, BORDER_STRONG,
                          ACCENT, SECONDARY, SUCCESS, DANGER, DANGER_SOFT,
                          TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED, TEXT_ON_ACCENT,
                          FONT_FAMILY, FONT_HEADING, FONT_SUBHEADING, FONT_BODY,
                          FONT_BODY_BOLD, FONT_SMALL, FONT_CAPTION, FONT_MONO,
                          BUTTON_RADIUS, CORNER_RADIUS, PAD_X,
                          BTN_PRIMARY, BTN_SECONDARY, BTN_GHOST, ENTRY_STYLE, CARD_STYLE)
from app.ui.widgets import (Tooltip, load_icon, draw_icon, center_over, release_grab,
                            set_window_icon)

# ── Local tokens (dashboard-only) ─────────────────────────────
SECONDARY_SOFT = "#2A2213"        # amber-tinted badge background
SUCCESS_SOFT = "#13261B"          # green-tinted badge background
CONTENT_PAD = 32                  # horizontal padding of the content area
SIDEBAR_WIDTH = 224
LIST_RENDER_STEP = 150            # rows rendered at a time (keeps 500+ item vaults snappy)
FONT_SCORE = (FONT_FAMILY, 40, "bold")
FONT_STAT = (FONT_FAMILY, 24, "bold")
FONT_WORDMARK = (FONT_FAMILY, 15, "bold")
FONT_AVATAR = (FONT_FAMILY, 14, "bold")
FONT_BADGE = (FONT_FAMILY, 10, "bold")
LOGO_TILE = "#F3F4F6"             # light tile behind website logos
# Muted, desaturated avatar backgrounds (picked by service-name hash)
AVATAR_COLORS = ("#22324A", "#2B2F4A", "#36294A", "#1F3B3A", "#3A3322", "#3D2630", "#263A2A", "#2E3440")


def parse_utc_timestamp(value) -> Optional[datetime]:
    """Parse an SQLite 'YYYY-MM-DD HH:MM:SS' (UTC) string into an aware UTC datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def password_age_days(cred, now: Optional[datetime] = None) -> Optional[int]:
    """Days since the password was last changed (falls back to updated_at)."""
    changed = parse_utc_timestamp(cred.get('password_changed_at')) or parse_utc_timestamp(cred.get('updated_at'))
    if changed is None:
        return None
    return ((now or datetime.now(timezone.utc)) - changed).days


def credential_matches(query: str, service, username, url, notes_plain) -> bool:
    """Case-insensitive substring match over service, username, url and decrypted notes."""
    q = (query or "").strip().casefold()
    if not q:
        return True
    return any(q in (field or "").casefold() for field in (service, username, url, notes_plain))


def password_policy_checks(pw: str) -> Dict[str, bool]:
    """Minimum 8 characters, no maximum; any non-alphanumeric character counts as special."""
    return {
        'length': len(pw) >= 8,
        'upper': any(ch.isupper() for ch in pw),
        'lower': any(ch.islower() for ch in pw),
        'digit': any(ch.isdigit() for ch in pw),
        'special': any(not ch.isalnum() for ch in pw),
    }


def _avatar_color(name: str) -> str:
    """Stable avatar background colour for a service name."""
    digest = hashlib.md5((name or "?").casefold().encode('utf-8')).digest()
    return AVATAR_COLORS[digest[0] % len(AVATAR_COLORS)]


def _domain_of(url: str) -> str:
    """Host part of a URL without a leading 'www.' ('' if unparsable)."""
    try:
        netloc = urlparse(url if "://" in url else f"https://{url}").netloc
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def run_in_thread(widget, work, on_done, on_progress=None, poll_ms: int = 100) -> None:
    """Runs work(report) in a daemon thread and delivers results on the Tk thread.

    ``work`` receives a ``report(done, total)`` callable. ``on_progress(done, total)``
    and finally ``on_done(result, error)`` are invoked from ``widget.after`` polling,
    so Tk is never touched from the worker. Polling stops if the widget is destroyed.
    """
    box: Dict = {}

    def report(done, total):
        box['progress'] = (done, total)

    def target():
        try:
            box['result'] = (work(report), None)
        except Exception as exc:     # delivered to on_done
            box['result'] = (None, exc)

    threading.Thread(target=target, daemon=True).start()

    def poll():
        try:
            if not widget.winfo_exists():
                return
        except Exception:
            return
        progress = box.pop('progress', None)
        if progress and on_progress:
            on_progress(*progress)
        if 'result' in box:
            on_done(*box.pop('result'))
        else:
            widget.after(poll_ms, poll)

    widget.after(poll_ms, poll)


def _host_parts(url: str) -> Tuple[str, str, str, str]:
    """(host, registrable domain, label, unicode host) for a URL; empty strings if it has no host."""
    host = (domain_from_url((url or "").strip()) or "").lower().rstrip(".")
    if not host:
        return "", "", "", ""
    try:
        uhost = host.encode("ascii").decode("idna") if "xn--" in host else host
    except (UnicodeError, ValueError):
        uhost = host
    _, label, _ = phishing.split_domain(uhost)
    return host, phishing.registrable_domain(host), label, uhost


def _deletion_variants(word: str, depth: int = 2) -> set:
    """All strings obtainable from word by deleting up to `depth` characters."""
    out = {word}
    frontier = {word}
    for _ in range(depth):
        frontier = {w[:i] + w[i + 1:] for w in frontier for i in range(len(w))}
        out |= frontier
    return out


def scan_phishing(urls: Dict[int, str], cache: Dict) -> Dict[int, "phishing.Finding"]:
    """Worst lookalike finding per item id (items without findings are omitted).

    Each URL is checked against the vault domains of all *other* items (its own
    occurrence is excluded so a saved phishing domain cannot whitelist itself).
    Only vault domains that could possibly produce a finding (same label or skeleton,
    shared token, or within edit distance 2) are passed on, which keeps the trusted
    set small and shared between items so the analysis stays fast for large vaults.
    Results are memoised in ``cache`` keyed by (url, relevant vault-domain set).
    """
    parts = {cid: _host_parts(url) for cid, url in urls.items() if url}
    counts = Counter(p[1] for p in parts.values() if "." in p[1])
    by_label: Dict[str, set] = {}
    by_skel: Dict[str, set] = {}
    by_variant: Dict[str, set] = {}     # SymSpell-style deletion index (edit distance <= 2)
    for reg in counts:
        label = phishing.split_domain(reg)[1]
        by_label.setdefault(label, set()).add(reg)
        by_skel.setdefault(phishing.skeleton(label), set()).add(reg)
        for v in _deletion_variants(label):
            by_variant.setdefault(v, set()).add(reg)
    results = {}
    for cid, (host, reg, label, uhost) in parts.items():
        if not host:
            continue
        sub = phishing.split_domain(uhost)[0]
        tokens = {t for part in sub.split(".") + [label] for t in part.split("-") if t}
        skel = phishing.skeleton(label)
        cand = set(by_label.get(label, ())) | by_skel.get(skel, set())
        for t in tokens:
            cand |= by_label.get(t, set())
        for v in _deletion_variants(label) | _deletion_variants(skel):
            cand |= by_variant.get(v, set())
        cand.discard(reg)
        if counts.get(reg, 0) > 1:      # another item saves the same domain -> trusted
            cand.add(reg)
        relevant = sorted(cand)
        key = (urls[cid], frozenset(relevant))
        if key not in cache:
            try:
                cache[key] = phishing.worst(phishing.analyze_url(urls[cid], relevant))
            except Exception:
                logging.exception("Phishing analysis failed")
                cache[key] = None
        if cache[key] is not None:
            results[cid] = cache[key]
    return results


# Last value the app put on the clipboard (module-level so the atexit handler can see it)
_last_copied = {'value': None}


def _clear_clipboard_if_ours():
    """atexit hook: empties the clipboard if it still holds a value this app copied."""
    value = _last_copied.get('value')
    if not value:
        return
    try:
        if pyperclip.paste() == value:
            pyperclip.copy('')
    except Exception:
        pass
    _last_copied['value'] = None


atexit.register(_clear_clipboard_if_ours)


def _avatar(parent, service: str, size: int = 36,
            font=FONT_AVATAR) -> Tuple[ctk.CTkFrame, ctk.CTkLabel]:
    """Fixed-size initial circle; returns (frame, label)."""
    frame = ctk.CTkFrame(parent, width=size, height=size, corner_radius=size // 2,
                         fg_color=_avatar_color(service), border_width=0)
    frame.pack_propagate(False)
    frame.grid_propagate(False)
    label = ctk.CTkLabel(frame, text=((service or "?")[:1] or "?").upper(), font=font,
                         text_color=TEXT_PRIMARY, fg_color="transparent", width=1, height=1)
    label.place(relx=0.5, rely=0.5, anchor="center")
    return frame, label


def _badge(parent, text: str, fg: str, text_color: str) -> ctk.CTkLabel:
    """Small pill-shaped status label."""
    return ctk.CTkLabel(parent, text=text, font=FONT_BADGE, fg_color=fg, text_color=text_color,
                        corner_radius=10, height=20, padx=8)


class StatCard(ctk.CTkFrame):
    """Compact metric tile: caption, large value, optional hint line."""

    def __init__(self, parent, title: str, value, color: str = TEXT_PRIMARY, hint: str = ""):
        super().__init__(parent, **CARD_STYLE)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text=title.upper(), font=FONT_CAPTION, text_color=TEXT_MUTED,
                     anchor="w").grid(row=0, column=0, padx=18, pady=(16, 2), sticky="w")
        ctk.CTkLabel(self, text=str(value), font=FONT_STAT, text_color=color, anchor="w").grid(
            row=1, column=0, padx=18, pady=0, sticky="w")
        ctk.CTkLabel(self, text=hint, font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").grid(
            row=2, column=0, padx=18, pady=(0, 14), sticky="w")


class PasswordStrengthChart(ctk.CTkFrame):
    """Password strength distribution as thin horizontal bars."""
    def __init__(self, parent, credentials):
        super().__init__(parent, **CARD_STYLE)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text="Strength distribution", font=FONT_SUBHEADING,
                     text_color=TEXT_PRIMARY).grid(row=0, column=0, padx=22, pady=(20, 2), sticky="w")
        ctk.CTkLabel(self, text="Based on length and character variety", font=FONT_SMALL,
                     text_color=TEXT_MUTED).grid(row=1, column=0, padx=22, pady=(0, 12), sticky="w")

        strength_counts = Counter(cred.get('strength', 0) for cred in credentials)
        total = sum(strength_counts.values()) or 1
        strength_labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
        strength_colors = [DANGER, DANGER, SECONDARY, ACCENT, SUCCESS]

        for i, (label, color) in enumerate(zip(strength_labels, strength_colors)):
            count = strength_counts.get(i, 0)
            fraction = count / total

            row_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0, border_width=0)
            row_frame.grid(row=i + 2, column=0, padx=22, pady=5, sticky="ew")
            row_frame.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(row_frame, text=label, width=86, anchor="w",
                         font=FONT_SMALL, text_color=TEXT_SECONDARY).grid(row=0, column=0)
            bar = ctk.CTkProgressBar(row_frame, height=6, corner_radius=3, fg_color=SURFACE_ACTIVE,
                                     progress_color=color if count else SURFACE_ACTIVE)
            bar.set(fraction)
            bar.grid(row=0, column=1, sticky="ew", padx=12)
            ctk.CTkLabel(row_frame, text=f"{count}", width=32, anchor="e",
                         font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY if count else TEXT_MUTED).grid(row=0, column=2)
        ctk.CTkFrame(self, height=14, fg_color="transparent").grid(row=8, column=0)


class RecentActivityChart(ctk.CTkFrame):
    """Most recently added items."""
    def __init__(self, parent, credentials):
        super().__init__(parent, **CARD_STYLE)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text="Recently added", font=FONT_SUBHEADING,
                     text_color=TEXT_PRIMARY).grid(row=0, column=0, padx=22, pady=(20, 2), sticky="w")
        ctk.CTkLabel(self, text="Latest items in your vault", font=FONT_SMALL,
                     text_color=TEXT_MUTED).grid(row=1, column=0, padx=22, pady=(0, 8), sticky="w")

        sorted_creds = sorted(credentials, key=lambda x: x.get('created_at') or '', reverse=True)[:5]
        if not sorted_creds:
            ctk.CTkLabel(self, text="No activity yet", font=FONT_BODY,
                         text_color=TEXT_MUTED).grid(row=2, column=0, padx=22, pady=30, sticky="w")
            return

        for i, cred in enumerate(sorted_creds):
            service = cred.get('service') or 'Unknown'
            date_obj = parse_utc_timestamp(cred.get('created_at'))
            date_str = date_obj.astimezone().strftime("%b %d, %Y") if date_obj else "Recently"

            item = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0, border_width=0)
            item.grid(row=i + 2, column=0, padx=22, pady=3, sticky="ew")
            item.grid_columnconfigure(1, weight=1)
            _avatar(item, service, 26, FONT_BADGE)[0].grid(row=0, column=0, sticky="w", padx=(0, 12))
            ctk.CTkLabel(item, text=service, font=FONT_BODY, text_color=TEXT_PRIMARY,
                         anchor="w").grid(row=0, column=1, sticky="w")
            ctk.CTkLabel(item, text=date_str, font=FONT_SMALL, text_color=TEXT_MUTED,
                         anchor="e").grid(row=0, column=2, sticky="e")
        ctk.CTkFrame(self, height=14, fg_color="transparent").grid(row=8, column=0)


class NavItem(ctk.CTkFrame):
    """Sidebar navigation entry with an accent indicator bar."""
    def __init__(self, parent, text, icon_kind, command):
        super().__init__(parent, fg_color="transparent", corner_radius=0, border_width=0)
        self._icon = draw_icon(icon_kind, TEXT_SECONDARY, (16, 16)) if icon_kind else None
        self._icon_active = draw_icon(icon_kind, TEXT_PRIMARY, (16, 16)) if icon_kind else None
        self.bar = ctk.CTkFrame(self, width=3, height=20, corner_radius=2, fg_color=SIDEBAR)
        self.bar.pack(side="left", padx=(0, 9))
        self.btn = ctk.CTkButton(self, text=f"  {text}", image=self._icon, compound="left", anchor="w",
                                 command=command, fg_color="transparent", hover_color=SURFACE_HOVER,
                                 text_color=TEXT_SECONDARY, corner_radius=BUTTON_RADIUS, height=36,
                                 font=FONT_BODY, border_width=0)
        self.btn.pack(side="left", fill="x", expand=True, padx=(0, 12))

    def set_active(self, active: bool):
        self.bar.configure(fg_color=ACCENT if active else SIDEBAR)
        self.btn.configure(fg_color=SURFACE_ACTIVE if active else "transparent",
                           hover_color=SURFACE_ACTIVE if active else SURFACE_HOVER,
                           text_color=TEXT_PRIMARY if active else TEXT_SECONDARY,
                           image=self._icon_active if active else self._icon)


class MainWindow(ctk.CTkToplevel):
    """The unlocked vault: navigation sidebar, item list and Security view."""

    def __init__(self, master, db: PasswordDatabase, encryption_key: bytes):
        super().__init__(master)
        self.db = db
        self.encryption_key = encryption_key
        self.configure(fg_color=BG)
        self.grab_set()
        self.title(settings.APP_NAME)
        self.geometry("1240x780")
        self.minsize(1000, 640)
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        self.current_credentials: Dict[int, Dict] = {}
        self.clipboard_clear_job = None
        self._search_job = None
        self.sort_options_map = {
            "Service (A-Z)": ("service", "ASC"),
            "Service (Z-A)": ("service", "DESC"),
            "Username (A-Z)": ("username", "ASC"),
            "Username (Z-A)": ("username", "DESC"),
            "Date Added (Newest)": ("created_at", "DESC"),
            "Date Added (Oldest)": ("created_at", "ASC"),
            "Date Modified (Newest)": ("updated_at", "DESC"),
            "Date Modified (Oldest)": ("updated_at", "ASC"),
            "Favorites First": ("is_favorite", "DESC"),
        }
        self.sort_options_list = list(self.sort_options_map.keys())
        self.current_sort_selection = self.sort_options_list[0]
        self.autolock_timer_id = None
        self.lock_screen = None
        # Metadata for every credential (encrypted fields + strength/digest/age only; never plaintext)
        self._all_creds: List[Dict] = []
        self._visible_creds: List[Dict] = []
        self._render_limit = LIST_RENDER_STEP
        self._reuse_counts: Counter = Counter()
        self.current_view = "all"
        self._security_dirty = True
        # Breach check: {cid: times seen} for breached items only (never plaintext); opt-in, memory only
        self._breach_results: Dict[int, int] = {}
        self._breach_checked_at: Optional[datetime] = None
        self._breach_unchecked = 0            # items whose lookup failed in the last run
        self._breach_running = False
        self._breach_progress: Tuple[int, int] = (0, 0)
        self._breach_error: Optional[str] = None
        self._breach_gen = 0                  # bumped on lock so in-flight results are discarded
        self._breach_card = None
        # Phishing guard: worst finding per cid, recomputed on load (memoised per url + vault set)
        self._phish_findings: Dict[int, "phishing.Finding"] = {}
        self._phish_cache: Dict = {}
        self._issue_filter: Optional[str] = None   # "breached" / "suspicious" list filter

        self.after(1, self._initialize_ui)

    def _initialize_ui(self):
        try:
            sm = (16, 16)
            self.add_icon = draw_icon('plus', TEXT_ON_ACCENT, (14, 14))
            self.search_icon = draw_icon('search', TEXT_MUTED, sm)
            self.copy_icon = load_icon(settings.COPY_ICON_FILE, size=sm, tint=TEXT_MUTED)
            self.edit_icon = load_icon(settings.EDIT_ICON_FILE, size=sm, tint=TEXT_MUTED)
            self.delete_icon = load_icon(settings.DELETE_ICON_FILE, size=sm, tint=TEXT_MUTED)
            self.delete_icon_hot = load_icon(settings.DELETE_ICON_FILE, size=sm, tint=DANGER)
            self.view_icon = load_icon(settings.VIEW_ICON_FILE, size=sm, tint=TEXT_MUTED)
            self.user_icon = draw_icon('user', TEXT_MUTED, sm)
            self.fav_icon = (load_icon(settings.FAVORITE_ICON_FILE, size=sm, tint=SECONDARY)
                             or draw_icon('star', SECONDARY, sm))
            self.not_fav_icon = (load_icon(settings.NOT_FAVORITE_ICON_FILE, size=sm, tint=TEXT_MUTED)
                                 or draw_icon('star_outline', TEXT_MUTED, sm))
            self._setup_ui()
            self.load_and_display_credentials()
            set_window_icon(self)
            self.after(50, lambda: center_over(self, self.master, require_viewable=False))
            self._setup_activity_bindings()
            self._reset_autolock_timer()
        except Exception as e:
            logging.exception("MW: FAILED during _initialize_ui")
            messagebox.showerror("UI Error", f"Failed to initialize:\n{e}", parent=self)
            self.destroy()

    # ── Auto-lock ──────────────────────────────────────────────
    def _setup_activity_bindings(self):
        self.bind_all("<KeyPress>", self._user_activity)
        self.bind_all("<ButtonPress>", self._user_activity)
        self.bind_all("<Motion>", self._user_activity)

    def _user_activity(self, event=None):
        if self.lock_screen is None or not self.lock_screen.winfo_exists():
            self._reset_autolock_timer()

    def _reset_autolock_timer(self):
        if self.autolock_timer_id is not None:
            self.after_cancel(self.autolock_timer_id)
        try:
            timeout = int(settings.AUTOLOCK_TIMEOUT_MS)
            if timeout <= 0:
                return
        except (ValueError, TypeError):
            timeout = 300000
        self.autolock_timer_id = self.after(timeout, self._lock_application)

    def _lock_application(self):
        if self.lock_screen and self.lock_screen.winfo_exists():
            return
        try:
            if self.clipboard_clear_job:
                self.after_cancel(self.clipboard_clear_job)
                self._clear_clipboard()
            # Close open dialogs (they may show plaintext), hide the vault and drop the key
            for child in self.winfo_children():
                if isinstance(child, ctk.CTkToplevel):
                    child.destroy()
            self.encryption_key = None
            self.current_credentials.clear()
            self._all_creds = []
            self._visible_creds = []
            self._reuse_counts = Counter()
            self._reset_breach_state()
            self._phish_findings = {}
            self._phish_cache = {}
            if self._issue_filter:
                self._issue_filter = None
                self.page_title.configure(text="Favorites" if self.current_view == "favorites" else "All Items")
            for w in self.scrollable_frame.winfo_children():
                w.destroy()
            self._clear_security_view()
            release_grab(self)
            self.withdraw()
            self.lock_screen = LockScreen(master=self, db=self.db, unlock_callback=self._unlock_application)
        except Exception as e:
            logging.error(f"Auto-lock error: {e}")

    def _unlock_application(self, vault_key: bytes):
        self.encryption_key = vault_key
        self.deiconify()
        self.load_and_display_credentials(self.search_var.get())
        self.grab_set()
        self.focus_force()
        self._reset_autolock_timer()

    # ── Layout ─────────────────────────────────────────────────
    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=0)
        self.grid_columnconfigure(2, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._setup_sidebar()
        ctk.CTkFrame(self, width=1, fg_color=BORDER, corner_radius=0).grid(row=0, column=1, rowspan=2, sticky="ns")

        self.content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0, border_width=0)
        self.content.grid(row=0, column=2, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self._setup_items_page()
        self._setup_security_page()
        self._setup_status_bar()
        self._show_view("all", reload=False)

        self.bind("<Control-f>", lambda e: self._focus_search())
        self.bind("<Control-n>", lambda e: self._add_credential_dialog())

    def _setup_sidebar(self):
        sb = ctk.CTkFrame(self, width=SIDEBAR_WIDTH, fg_color=SIDEBAR, corner_radius=0, border_width=0)
        sb.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sb.grid_propagate(False)
        sb.pack_propagate(False)

        brand = ctk.CTkFrame(sb, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(22, 26))
        ctk.CTkLabel(brand, text="", image=draw_icon('lock_solid', TEXT_ON_ACCENT, (16, 16)),
                     width=30, height=30, corner_radius=8, fg_color=ACCENT).pack(side="left")
        ctk.CTkLabel(brand, text="PyPass", font=FONT_WORDMARK, text_color=TEXT_PRIMARY).pack(
            side="left", padx=(10, 0))
        ctk.CTkLabel(brand, text="Manager", font=(FONT_FAMILY, 15), text_color=TEXT_MUTED).pack(
            side="left", padx=(4, 0))

        ctk.CTkLabel(sb, text="VAULT", font=FONT_CAPTION, text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=24, pady=(0, 6))
        self.nav_items = {
            "all": NavItem(sb, "All Items", 'grid', lambda: self._show_view("all")),
            "favorites": NavItem(sb, "Favorites", 'star_outline', lambda: self._show_view("favorites")),
            "security": NavItem(sb, "Security", 'shield', lambda: self._show_view("security")),
        }
        for item in self.nav_items.values():
            item.pack(fill="x", pady=1)

        ctk.CTkLabel(sb, text="TOOLS", font=FONT_CAPTION, text_color=TEXT_MUTED, anchor="w").pack(
            fill="x", padx=24, pady=(18, 6))
        self.gen_btn = NavItem(sb, "Password Generator", 'sparkle', self._open_password_generator)
        self.gen_btn.pack(fill="x", pady=1)

        # Bottom section
        bottom = ctk.CTkFrame(sb, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", pady=(0, 16))
        ctk.CTkFrame(bottom, height=1, fg_color=BORDER, corner_radius=0).pack(fill="x", padx=16, pady=(0, 10))
        self.emergency_btn = NavItem(bottom, "Emergency Access", 'lifebuoy', self._open_emergency_access)
        self.emergency_btn.pack(fill="x", pady=1)
        self.security_q_btn = NavItem(bottom, "Security Questions", 'help', self._open_security_questions)
        self.security_q_btn.pack(fill="x", pady=1)
        self.change_master_btn = NavItem(bottom, "Change Master Password", 'key', self._change_master_password)
        self.change_master_btn.pack(fill="x", pady=1)
        self.lock_btn = NavItem(bottom, "Lock", 'lock', self._lock_application)
        self.lock_btn.pack(fill="x", pady=1)

    def _page_header(self, parent, title, subtitle):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, padx=CONTENT_PAD, pady=(28, 0), sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        title_lbl = ctk.CTkLabel(header, text=title, font=FONT_HEADING, text_color=TEXT_PRIMARY, anchor="w")
        title_lbl.grid(row=0, column=0, sticky="w")
        sub_lbl = ctk.CTkLabel(header, text=subtitle, font=FONT_BODY, text_color=TEXT_MUTED, anchor="w")
        sub_lbl.grid(row=1, column=0, sticky="w", pady=(0, 0))
        return header, title_lbl, sub_lbl

    def _setup_items_page(self):
        page = ctk.CTkFrame(self.content, fg_color=BG, corner_radius=0)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(2, weight=1)
        self.items_page = page

        header, self.page_title, self.count_label = self._page_header(page, "All Items", "")
        self.add_btn = ctk.CTkButton(header, text="New Item", image=self.add_icon, compound="left",
                                     width=124, command=self._add_credential_dialog, **BTN_PRIMARY)
        self.add_btn.grid(row=0, column=1, rowspan=2, sticky="e")

        # Toolbar: search + sort
        bar = ctk.CTkFrame(page, fg_color="transparent")
        bar.grid(row=1, column=0, padx=CONTENT_PAD, pady=(20, 14), sticky="ew")
        bar.grid_columnconfigure(0, weight=1)

        search_box = ctk.CTkFrame(bar, fg_color=ENTRY_STYLE["fg_color"], border_color=ENTRY_STYLE["border_color"],
                                  border_width=1, corner_radius=BUTTON_RADIUS, height=40)
        search_box.grid(row=0, column=0, sticky="ew")
        search_box.grid_columnconfigure(1, weight=1)
        self.search_box = search_box
        ctk.CTkLabel(search_box, text="", image=self.search_icon, width=20).grid(row=0, column=0, padx=(14, 4), pady=1)

        self.search_var = ctk.StringVar()
        entry_style = {**ENTRY_STYLE, "border_width": 0, "height": 36, "corner_radius": 0}
        self.search_entry = ctk.CTkEntry(search_box, placeholder_text="Search by name, username, website or notes",
                                         textvariable=self.search_var, **entry_style)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4), pady=2)
        self.search_entry.bind("<Return>", self._perform_search)
        self.search_entry.bind("<Escape>", lambda e: self.search_var.set(""))
        self.search_entry.bind("<FocusIn>", lambda e: search_box.configure(border_color=ACCENT))
        self.search_entry.bind("<FocusOut>", lambda e: search_box.configure(border_color=ENTRY_STYLE["border_color"]))
        self.search_var.trace_add("write", self._on_search_change)
        # CTkEntry hides its placeholder when a textvariable is bound, so draw our own
        self._search_placeholder = ctk.CTkLabel(self.search_entry, text="Search by name, username, website or notes",
                                                font=FONT_BODY, text_color=TEXT_MUTED, fg_color=ENTRY_STYLE["fg_color"],
                                                height=20, anchor="w")
        self._search_placeholder.place(x=8, rely=0.5, anchor="w")
        self._search_placeholder.bind("<Button-1>", lambda e: self.search_entry.focus_set())
        self.search_var.trace_add("write", lambda *a: self._search_placeholder.place_forget()
                                  if self.search_var.get() else self._search_placeholder.place(x=8, rely=0.5, anchor="w"))
        ctk.CTkLabel(search_box, text="Ctrl+F", font=FONT_SMALL, text_color=TEXT_MUTED).grid(
            row=0, column=2, padx=(4, 14))

        ctk.CTkLabel(bar, text="Sort", font=FONT_SMALL, text_color=TEXT_MUTED).grid(row=0, column=1, padx=(16, 8))
        self.sort_menu = ctk.CTkOptionMenu(bar, values=self.sort_options_list, width=196, height=40,
                                           fg_color=SURFACE, button_color=SURFACE, button_hover_color=SURFACE_HOVER,
                                           text_color=TEXT_PRIMARY, font=FONT_BODY, corner_radius=BUTTON_RADIUS,
                                           dropdown_fg_color=SURFACE, dropdown_hover_color=SURFACE_HOVER,
                                           dropdown_text_color=TEXT_PRIMARY, dropdown_font=FONT_BODY,
                                           command=self._on_sort_change)
        self.sort_menu.set(self.current_sort_selection)
        self.sort_menu.grid(row=0, column=2, sticky="e")

        # Items list (one card)
        self.scrollable_frame = ctk.CTkScrollableFrame(page, fg_color=SURFACE, corner_radius=CORNER_RADIUS,
                                                       border_width=1, border_color=BORDER,
                                                       scrollbar_fg_color=SURFACE,
                                                       scrollbar_button_color=BORDER,
                                                       scrollbar_button_hover_color=BORDER_STRONG)
        self.scrollable_frame.grid(row=2, column=0, padx=CONTENT_PAD, pady=(0, 20), sticky="nsew")
        self.scrollable_frame.grid_columnconfigure(0, weight=1)

    def _setup_security_page(self):
        page = ctk.CTkFrame(self.content, fg_color=BG, corner_radius=0)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=1)
        self.security_page = page
        self._page_header(page, "Security", "Health check of the passwords in your vault")

        scroll = ctk.CTkScrollableFrame(page, fg_color=BG, corner_radius=0,
                                        scrollbar_fg_color=BG, scrollbar_button_color=BORDER,
                                        scrollbar_button_hover_color=BORDER_STRONG)
        scroll.grid(row=1, column=0, padx=(CONTENT_PAD - 6, CONTENT_PAD - 14), pady=(14, 12), sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)
        self.analytics_container = scroll
        page.grid_remove()

    def _setup_status_bar(self):
        bar = ctk.CTkFrame(self, height=28, fg_color=SIDEBAR, corner_radius=0, border_width=0)
        bar.grid(row=1, column=2, sticky="ew")
        bar.grid_propagate(False)
        bar.grid_columnconfigure(1, weight=1)
        ctk.CTkFrame(bar, width=6, height=6, corner_radius=3, fg_color=SUCCESS).grid(row=0, column=0, padx=(CONTENT_PAD, 8), pady=11)
        self.status_bar = ctk.CTkLabel(bar, text="Ready", anchor="w", height=26, font=FONT_SMALL,
                                       text_color=TEXT_MUTED)
        self.status_bar.grid(row=0, column=1, sticky="w")
        try:
            mins = max(1, int(settings.AUTOLOCK_TIMEOUT_MS) // 60000)
            lock_txt = f"Vault unlocked  ·  Auto-lock after {mins} min" if int(settings.AUTOLOCK_TIMEOUT_MS) > 0 else "Vault unlocked"
        except (ValueError, TypeError):
            lock_txt = "Vault unlocked"
        ctk.CTkLabel(bar, text=lock_txt, height=26, font=FONT_SMALL, text_color=TEXT_MUTED).grid(
            row=0, column=2, padx=CONTENT_PAD, sticky="e")

    # ── Navigation ─────────────────────────────────────────────
    def _show_view(self, view, reload=True):
        self.current_view = view
        self._issue_filter = None
        for key, item in self.nav_items.items():
            item.set_active(key == view)
        if view == "security":
            self.items_page.grid_remove()
            self.security_page.grid()
            if self._security_dirty:
                self._update_analytics(self._all_creds)
        else:
            self.security_page.grid_remove()
            self.items_page.grid()
            self.page_title.configure(text="Favorites" if view == "favorites" else "All Items")
            self._render_limit = LIST_RENDER_STEP
            if reload:
                self._apply_filter_and_render()

    def _focus_search(self):
        if self.current_view == "security":
            self._show_view("all")
        self.search_entry.focus_set()
        return "break"

    def _on_sort_change(self, selected):
        self.current_sort_selection = selected
        self.load_and_display_credentials(self.search_var.get())

    def _perform_search(self, event=None):
        if self._search_job:
            self.after_cancel(self._search_job)
            self._search_job = None
        self.load_and_display_credentials(self.search_var.get())

    def _on_search_change(self, *args):
        if self._search_job:
            self.after_cancel(self._search_job)
        self._search_job = self.after(300, lambda: self.load_and_display_credentials(self.search_var.get()))

    def _set_status(self, message, duration=0):
        if hasattr(self, 'status_bar') and self.status_bar and self.status_bar.winfo_exists():
            self.status_bar.configure(text=message, text_color=TEXT_SECONDARY)
        if duration > 0:
            self.after(duration, lambda m=message: self._reset_status(m))

    def _reset_status(self, original):
        if hasattr(self, 'status_bar') and self.status_bar and self.status_bar.winfo_exists():
            if self.status_bar.cget("text") == original:
                self.status_bar.configure(text="Ready", text_color=TEXT_MUTED)

    def _update_dashboard_stats(self, credentials):
        """Update the header item count for the current list view."""
        if not hasattr(self, 'count_label'):
            return
        total = len(self._all_creds)
        shown = len(credentials)
        if self._issue_filter:
            text = f"{shown} item{'s' if shown != 1 else ''} need{'s' if shown == 1 else ''} attention"
        elif self.current_view == "favorites":
            text = f"{shown} favorite{'s' if shown != 1 else ''}"
        elif self.search_var.get().strip():
            text = f"{shown} of {total} items match"
        else:
            text = f"{total} item{'s' if total != 1 else ''}"
        self.count_label.configure(text=text)

    # ── Data loading / rendering ───────────────────────────────
    def load_and_display_credentials(self, search_query: str = "") -> None:
        """Reloads all items from the database and re-renders the current view."""
        sort_col, sort_order = self.sort_options_map.get(self.current_sort_selection, ("service", "ASC"))

        try:
            db_creds = self.db.get_all_credentials(sort_by=sort_col, sort_order=sort_order)
            self.current_credentials.clear()

            for cred in db_creds:
                cid = cred['id']
                enc_pass = cred['encrypted_password']
                cred['age_days'] = password_age_days(cred)
                dec_pass = decrypt_data(enc_pass, self.encryption_key) if self.encryption_key else DECRYPTION_ERROR
                if dec_pass == DECRYPTION_ERROR:
                    cred['decrypt_failed'] = True
                    cred['strength'] = 0
                    cred['pw_digest'] = None
                else:
                    cred['decrypt_failed'] = False
                    cred['strength'] = check_password_strength(dec_pass)[0]
                    # Keyed digest used only to detect reuse; plaintext is never kept
                    cred['pw_digest'] = hashlib.blake2b(dec_pass.encode('utf-8'), key=self.encryption_key[:64],
                                                        digest_size=16).digest()
                del dec_pass

                self.current_credentials[cid] = {
                    'service': cred['service'], 'username': cred['username'], 'url': cred.get('url', ''),
                    'encrypted_password': enc_pass, 'notes': cred.get('notes', ''),
                    'is_favorite': bool(cred.get('is_favorite', 0)),
                    'strength': cred['strength'], 'pw_digest': cred['pw_digest'],
                }

            self._all_creds = db_creds
            self._reuse_counts = Counter(c['pw_digest'] for c in db_creds if c.get('pw_digest'))
            self._phish_findings = scan_phishing(
                {c['id']: (c.get('url') or '').strip() for c in db_creds}, self._phish_cache)
            self._breach_results = {cid: n for cid, n in self._breach_results.items()
                                    if cid in self.current_credentials}
            self._security_dirty = True
            self._apply_filter_and_render(search_query)
            if self.current_view == "security":
                self._update_analytics(db_creds)
        except Exception as e:
            logging.exception("Failed to load credentials.")
            messagebox.showerror("Error", f"Failed to load:\n{e}", parent=self)

    def _apply_filter_and_render(self, search_query=None):
        if search_query is None:
            search_query = self.search_var.get()
        creds = self._all_creds
        if self.current_view == "favorites":
            creds = [c for c in creds if c.get('is_favorite')]
        if self._issue_filter == "breached":
            creds = [c for c in creds if self._breach_results.get(c['id'])]
        elif self._issue_filter == "suspicious":
            creds = [c for c in creds if c['id'] in self._phish_findings]
        if search_query and search_query.strip():
            # Notes are encrypted, so SQL can't search them: filter here (order is preserved)
            creds = [c for c in creds
                     if credential_matches(search_query, c.get('service'), c.get('username'),
                                           c.get('url'), self._decrypt_notes(c.get('notes')))]
        self._visible_creds = creds
        self._render_list(search_query)
        self._update_dashboard_stats(creds)

    def _render_list(self, search_query=""):
        for w in self.scrollable_frame.winfo_children():
            w.destroy()
        try:
            self.scrollable_frame._parent_canvas.yview_moveto(0)
        except Exception:
            pass

        creds = self._visible_creds
        if not creds:
            self._render_empty_state(search_query)
            return

        for idx, cred in enumerate(creds[:self._render_limit]):
            self._build_row(idx, cred)
        self._add_show_more_button()

    def _show_more(self):
        self._render_limit += LIST_RENDER_STEP
        start = self._render_limit - LIST_RENDER_STEP
        for w in self.scrollable_frame.grid_slaves(row=start + 1):
            w.destroy()
        for idx, cred in enumerate(self._visible_creds[start:self._render_limit], start=start):
            self._build_row(idx, cred)
        self._add_show_more_button()

    def _add_show_more_button(self):
        """Adds the 'Show N more' button below the rendered rows if any are still hidden."""
        remaining = len(self._visible_creds) - self._render_limit
        if remaining > 0:
            ctk.CTkButton(self.scrollable_frame, text=f"Show {min(remaining, LIST_RENDER_STEP)} more  ({remaining} hidden)",
                          command=self._show_more, **{**BTN_GHOST, "text_color": ACCENT}).grid(
                row=self._render_limit + 1, column=0, pady=(6, 10))

    def _render_empty_state(self, search_query):
        box = ctk.CTkFrame(self.scrollable_frame, fg_color="transparent")
        box.grid(row=0, column=0, pady=(110, 40))
        q = (search_query or "").strip()
        if q:
            icon, title = draw_icon('grid', TEXT_MUTED, (28, 28)), f"No matches for “{q}”"
            body = "Try a different name, username, website or keyword from your notes."
            action = ("Clear search", lambda: self.search_var.set(""), BTN_SECONDARY)
        elif self._issue_filter and self._all_creds:
            icon, title = draw_icon('shield', TEXT_MUTED, (28, 28)), "Nothing to fix here"
            body = "None of your items currently have this issue."
            action = ("Browse all items", lambda: self._show_view("all"), BTN_SECONDARY)
        elif self.current_view == "favorites" and self._all_creds:
            icon, title = draw_icon('star_outline', TEXT_MUTED, (28, 28)), "No favorites yet"
            body = "Star the items you use most and they will appear here."
            action = ("Browse all items", lambda: self._show_view("all"), BTN_SECONDARY)
        else:
            icon, title = draw_icon('lock', TEXT_MUTED, (28, 28)), "No items yet"
            body = "Your vault is empty. Add your first login to get started."
            action = ("Add your first login", self._add_credential_dialog, BTN_PRIMARY)
        circle = ctk.CTkFrame(box, width=56, height=56, corner_radius=28, fg_color=SURFACE_ACTIVE)
        circle.pack(pady=(0, 16))
        circle.pack_propagate(False)
        ctk.CTkLabel(circle, text="", image=icon, width=28, height=28).place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(box, text=title, font=FONT_SUBHEADING, text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(box, text=body, font=FONT_BODY, text_color=TEXT_MUTED).pack(pady=(4, 18))
        ctk.CTkButton(box, text=action[0], command=action[1], **{**action[2], "width": 170}).pack()

    def _build_row(self, idx: int, cred: Dict):
        """Renders one item row: avatar/logo, name and username, badges and action buttons."""
        cid = cred['id']
        service = cred['service'] or ""
        username = cred['username'] or ""
        url = cred.get('url') or ''
        failed = cred.get('decrypt_failed', False)

        row =ctk.CTkFrame(self.scrollable_frame, fg_color=SURFACE, corner_radius=BUTTON_RADIUS,
                           border_width=0, height=60)
        row.grid(row=idx + 1, column=0, padx=(8, 6), pady=(8 if idx == 0 else 1, 1), sticky="ew")
        row.grid_columnconfigure(1, weight=1)

        avatar, avatar_lbl = _avatar(row, service)
        avatar.grid(row=0, column=0, rowspan=2, padx=(14, 14), pady=12)
        get_logo_async(guess_domain(service, url),
                       lambda img, f=avatar, l=avatar_lbl: self.after(0, self._update_favicon, img, f, l))

        name = ctk.CTkLabel(row, text=service, anchor="w", font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY, height=20)
        name.grid(row=0, column=1, sticky="sw", pady=(11, 0))
        domain = _domain_of(url) if url else ""
        sub_text = f"{username}   ·   {domain}" if domain else username
        sub = ctk.CTkLabel(row, text=sub_text, anchor="w", font=FONT_SMALL, text_color=TEXT_MUTED, height=18)
        sub.grid(row=1, column=1, sticky="nw", pady=(0, 11))
        if url:
            name.configure(cursor="hand2")
            name.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))
            Tooltip(name, f"Open {url}")

        badges = ctk.CTkFrame(row, fg_color="transparent", width=1, height=1)
        badges.grid(row=0, column=2, rowspan=2, padx=(8, 12))
        self._add_row_badges(badges, cred)

        actions = ctk.CTkFrame(row, fg_color="transparent", width=1, height=1)
        actions.grid(row=0, column=3, rowspan=2, padx=(0, 10))
        self._add_row_actions(actions, cred)

        self._bind_row_hover(row, (row, avatar, avatar_lbl, name, sub, badges, actions), actions)
        if not failed:
            for w in (row, avatar, sub):
                w.bind("<Double-Button-1>", lambda e, i=cid: self._edit_credential(i), add="+")

    def _add_row_badges(self, badges: ctk.CTkFrame, cred: Dict):
        """Decryption-failed / Reused / Weak / password-age badges."""
        finding = self._phish_findings.get(cred['id'])
        if finding is not None:
            high = finding.severity == phishing.HIGH
            sus = _badge(badges, "Suspicious", DANGER_SOFT if high else SECONDARY_SOFT,
                         DANGER if high else SECONDARY)
            sus.pack(side="left", padx=3)
            Tooltip(sus, finding.message)
        if cred.get('decrypt_failed', False):
            _badge(badges, "Decryption failed", DANGER_SOFT, DANGER).pack(side="left", padx=3)
        else:
            seen = self._breach_results.get(cred['id'])
            if seen:
                b = _badge(badges, "Breached", DANGER_SOFT, DANGER)
                b.pack(side="left", padx=3)
                Tooltip(b, f"Seen {breach.format_count(seen)} times in known data breaches. "
                            "Change this password.")
            if cred.get('pw_digest') and self._reuse_counts.get(cred['pw_digest'], 0) > 1:
                _badge(badges, "Reused", SECONDARY_SOFT, SECONDARY).pack(side="left", padx=3)
            if cred.get('strength', 0) < 3:
                _badge(badges, "Weak", DANGER_SOFT, DANGER).pack(side="left", padx=3)
            days_old = cred.get('age_days')
            if days_old is not None and days_old > 90:
                fg, fgc = (DANGER_SOFT, DANGER) if days_old > 180 else (SECONDARY_SOFT, SECONDARY)
                age = _badge(badges, f"{days_old} days", fg, fgc)
                age.pack(side="left", padx=3)
                Tooltip(age, f"Password last changed {days_old} days ago")

    def _add_row_actions(self, actions: ctk.CTkFrame, cred: Dict):
        """Subdued ghost icon buttons: copy, reveal, edit, favorite, delete."""
        cid = cred['id']
        service = cred['service'] or ""
        username = cred['username'] or ""
        is_fav = bool(cred.get('is_favorite', 0))
        btn_state = "disabled" if cred.get('decrypt_failed', False) else "normal"
        ghost = {**BTN_GHOST, "width": 32, "height": 32, "text": "", "hover_color": SURFACE_ACTIVE}
        specs = [
            (self.user_icon, "Copy username", lambda u=username: self._copy_to_clipboard(u, "Username"), btn_state),
            (self.copy_icon, "Copy password", lambda i=cid: self._copy_password(i), btn_state),
            (self.view_icon, "Reveal password", lambda i=cid: self._view_password(i), btn_state),
            (self.edit_icon, "Edit", lambda i=cid: self._edit_credential(i), btn_state),
            (self.fav_icon if is_fav else self.not_fav_icon,
             "Remove from favorites" if is_fav else "Add to favorites", lambda i=cid: self._toggle_favorite(i), "normal"),
        ]
        for image, tip, cmd, state in specs:
            b = ctk.CTkButton(actions, image=image, command=cmd, state=state, **ghost)
            b.pack(side="left", padx=1)
            Tooltip(b, tip)
        del_btn = ctk.CTkButton(actions, image=self.delete_icon, **{**ghost, "hover_color": DANGER_SOFT},
                                command=lambda i=cid, s=service: self._delete_credential(i, s))
        del_btn.pack(side="left", padx=(1, 0))
        del_btn.bind("<Enter>", lambda e, b=del_btn: b.configure(image=self.delete_icon_hot), add="+")
        del_btn.bind("<Leave>", lambda e, b=del_btn: b.configure(image=self.delete_icon), add="+")
        Tooltip(del_btn, "Delete")

    @staticmethod
    def _bind_row_hover(row: ctk.CTkFrame, parts, actions: ctk.CTkFrame):
        """Highlights `row` while the pointer is anywhere over it (including its child widgets)."""
        def on_enter(_e=None, r=row):
            if r.cget("fg_color") != SURFACE_HOVER:
                r.configure(fg_color=SURFACE_HOVER)

        def on_leave(_e=None, r=row):
            try:
                x, y = r.winfo_pointerxy()
                w = r.winfo_containing(x, y)
                if w is not None and str(w).startswith(str(r)):
                    return
                r.configure(fg_color=SURFACE)
            except Exception:
                pass

        for w in parts:
            w.bind("<Enter>", on_enter, add="+")
            w.bind("<Leave>", on_leave, add="+")
        for w in actions.winfo_children():
            w.bind("<Leave>", on_leave, add="+")

    def _update_favicon(self, img, frame: ctk.CTkFrame, label: ctk.CTkLabel):
        """Swap the initial avatar for the site's logo on a light tile (logos are drawn for light backgrounds)."""
        if img is None or not label.winfo_exists():
            return
        logo = ctk.CTkImage(light_image=img, dark_image=img, size=(22, 22))
        frame.configure(fg_color=LOGO_TILE)
        label.configure(text="", image=logo)

    # ── Security view ──────────────────────────────────────────
    def _clear_security_view(self):
        container = getattr(self, 'analytics_container', None)
        if container is not None and container.winfo_exists():
            for widget in container.winfo_children():
                widget.destroy()
        self._security_dirty = True

    def _update_analytics(self, credentials: List[Dict]):
        """Populate the Security view: score, metric tiles, charts and recommendations."""
        container = getattr(self, 'analytics_container', None)
        if container is None or not container.winfo_exists():
            return
        for widget in container.winfo_children():
            widget.destroy()
        self._security_dirty = False

        stats = self._security_stats(credentials, self._breach_results, self._phish_findings,
                                     self._breach_checked_at is not None)
        self._build_score_card(container, stats)
        self._build_metric_tiles(container, stats)

        self._breach_card = ctk.CTkFrame(container, **CARD_STYLE)
        self._breach_card.grid(row=2, column=0, padx=6, pady=8, sticky="ew")
        self._render_breach_card()

        charts = ctk.CTkFrame(container, fg_color="transparent")
        charts.grid(row=3, column=0, sticky="ew")
        charts.grid_columnconfigure(0, weight=3, uniform="charts")
        charts.grid_columnconfigure(1, weight=2, uniform="charts")
        PasswordStrengthChart(charts, credentials).grid(row=0, column=0, padx=6, pady=8, sticky="nsew")
        RecentActivityChart(charts, credentials).grid(row=0, column=1, padx=6, pady=8, sticky="nsew")

        self._build_recommendations(container, stats)

    @staticmethod
    def _security_stats(credentials: List[Dict], breached: Optional[Dict[int, int]] = None,
                        suspicious: Optional[Dict] = None, breach_checked: bool = False) -> Dict:
        """Counts used by the Security view (total, weak, reused, old, no_url, breached,
        suspicious, healthy, score). Breached / suspicious items are never counted as healthy."""
        breached = breached or {}
        suspicious = suspicious or {}
        total = len(credentials)
        digests = Counter(c['pw_digest'] for c in credentials if c.get('pw_digest'))
        reused = sum(n for n in digests.values() if n > 1)
        old = sum(1 for c in credentials if (c.get('age_days') or 0) > 180)
        no_url = sum(1 for c in credentials if not (c.get('url') or '').strip())
        weak = sum(1 for c in credentials if c.get('strength', 0) < 3)
        n_breached = sum(1 for c in credentials if breached.get(c['id']))
        n_suspicious = sum(1 for c in credentials if c['id'] in suspicious)
        n_suspicious_high = sum(1 for c in credentials
                                if c['id'] in suspicious and suspicious[c['id']].severity == phishing.HIGH)
        healthy = sum(1 for c in credentials
                      if c.get('strength', 0) >= 3 and (c.get('age_days') or 0) <= 180
                      and c.get('pw_digest') and digests.get(c['pw_digest'], 0) <= 1
                      and not breached.get(c['id']) and c['id'] not in suspicious)
        score = round(100 * healthy / total) if total else 100
        return dict(total=total, reused=reused, old=old, no_url=no_url, weak=weak,
                    breached=n_breached, suspicious=n_suspicious, suspicious_high=n_suspicious_high,
                    breach_checked=breach_checked, healthy=healthy, score=score)

    @staticmethod
    def _build_score_card(container, stats: Dict):
        """Large percentage, verdict badge and progress bar."""
        score, healthy, total = stats['score'], stats['healthy'], stats['total']
        score_color = SUCCESS if score >= 80 else SECONDARY if score >= 50 else DANGER
        verdict = ("Excellent" if score >= 90 else "Good" if score >= 80 else
                   "Needs attention" if score >= 50 else "At risk")

        sc = ctk.CTkFrame(container, **CARD_STYLE)
        sc.grid(row=0, column=0, padx=6, pady=(0, 8), sticky="ew")
        sc.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(sc, text=f"{score}%", font=FONT_SCORE, text_color=score_color, width=120,
                     anchor="w").grid(row=0, column=0, rowspan=3, padx=(26, 18), pady=22, sticky="w")
        title_row = ctk.CTkFrame(sc, fg_color="transparent")
        title_row.grid(row=0, column=1, sticky="sw", pady=(22, 0), padx=(0, 26))
        ctk.CTkLabel(title_row, text="Security score", font=FONT_SUBHEADING, text_color=TEXT_PRIMARY).pack(side="left")
        soft = SUCCESS_SOFT if score >= 80 else SECONDARY_SOFT if score >= 50 else DANGER_SOFT
        _badge(title_row, verdict, soft, score_color).pack(side="left", padx=(10, 0))
        detail = ("strong, unique, not breached and changed within the last 180 days"
                  if stats.get('breach_checked') else "strong, unique and changed within the last 180 days")
        ctk.CTkLabel(sc, text=f"{healthy} of {total} items are {detail}.",
                     font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").grid(row=1, column=1, sticky="w", padx=(0, 26))
        pb = ctk.CTkProgressBar(sc, height=6, corner_radius=3, fg_color=SURFACE_ACTIVE, progress_color=score_color)
        pb.set(score / 100)
        pb.grid(row=2, column=1, sticky="ew", padx=(0, 26), pady=(10, 22))

    @staticmethod
    def _build_metric_tiles(container, stats: Dict):
        """Row of StatCards: weak, reused, breached, suspicious, old and missing-URL counts."""
        weak, reused = stats['weak'], stats['reused']
        old, no_url = stats['old'], stats['no_url']
        breached, suspicious = stats.get('breached', 0), stats.get('suspicious', 0)
        cards = ctk.CTkFrame(container, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew")
        if stats.get('breach_checked'):
            breach_tile = ("Breached", breached, DANGER if breached else TEXT_PRIMARY, "Found in data leaks")
        else:
            breach_tile = ("Breached", "—", TEXT_MUTED, "Not checked yet")
        sus_color = (DANGER if stats.get('suspicious_high') else SECONDARY) if suspicious else TEXT_PRIMARY
        tiles = [
            ("Weak", weak, DANGER if weak else TEXT_PRIMARY, "Strength below fair"),
            ("Reused", reused, SECONDARY if reused else TEXT_PRIMARY, "Share a password"),
            breach_tile,
            ("Suspicious", suspicious, sus_color, "Lookalike websites"),
            ("Older than 180d", old, SECONDARY if old else TEXT_PRIMARY, "Not rotated recently"),
            ("Missing URL", no_url, TEXT_SECONDARY if no_url else TEXT_PRIMARY, "No website saved"),
        ]
        for i, (title, value, color, hint) in enumerate(tiles):
            cards.grid_columnconfigure(i, weight=1, uniform="tiles")
            StatCard(cards, title, value, color, hint).grid(row=0, column=i, padx=6, pady=8, sticky="ew")

    def _build_recommendations(self, container, stats: Dict[str, int]):
        """Card listing actionable tips derived from the security stats."""
        total, weak, reused = stats['total'], stats['weak'], stats['reused']
        old, no_url = stats['old'], stats['no_url']
        breached, suspicious = stats.get('breached', 0), stats.get('suspicious', 0)
        rec = ctk.CTkFrame(container, **CARD_STYLE)
        rec.grid(row=4, column=0, padx=6, pady=(8, 16), sticky="ew")
        rec.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(rec, text="Recommendations", font=FONT_SUBHEADING, text_color=TEXT_PRIMARY).grid(
            row=0, column=0, columnspan=3, padx=22, pady=(20, 10), sticky="w")
        tips = []
        if breached:
            tips.append((DANGER, f"{breached} password{'s' if breached != 1 else ''} found in data breaches",
                         "Attackers try leaked passwords first. Change them as soon as possible.",
                         ("Show items", lambda: self._show_issue_items("breached"))))
        if suspicious:
            tips.append((DANGER if stats.get('suspicious_high') else SECONDARY,
                         f"{suspicious} item{'s' if suspicious != 1 else ''} with a lookalike website",
                         "The saved address imitates a well-known site. Check it before signing in.",
                         ("Show items", lambda: self._show_issue_items("suspicious"))))
        if reused:
            tips.append((SECONDARY, f"{reused} items share a password with another item",
                         "Give every account its own unique password.", None))
        if weak:
            tips.append((DANGER, f"{weak} weak password{'s' if weak != 1 else ''}",
                         "Replace them with long, randomly generated passwords.",
                         ("Open generator", self._open_password_generator)))
        if old:
            tips.append((SECONDARY, f"{old} password{'s' if old != 1 else ''} older than 180 days",
                         "Rotate passwords for important accounts regularly.", None))
        if no_url:
            tips.append((TEXT_MUTED, f"{no_url} item{'s' if no_url != 1 else ''} without a website",
                         "Adding a URL makes items easier to find and open.", None))
        if not tips:
            tips.append((SUCCESS, "No issues found" if total else "Nothing to review yet",
                         "Your passwords look healthy." if total else "Add items to see a security report.", None))
        tips.append(self._emergency_tip())
        for i, (color, head, body, action) in enumerate(tips):
            r = 1 + i
            if i:
                ctk.CTkFrame(rec, height=1, fg_color=BORDER, corner_radius=0).grid(
                    row=r * 2 - 1, column=0, columnspan=3, padx=22, sticky="ew")
            ctk.CTkFrame(rec, width=8, height=8, corner_radius=4, fg_color=color).grid(
                row=r * 2, column=0, padx=(24, 14), pady=(18, 0), sticky="n")
            txt = ctk.CTkFrame(rec, fg_color="transparent")
            txt.grid(row=r * 2, column=1, sticky="w", pady=10)
            ctk.CTkLabel(txt, text=head, font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY, anchor="w", height=20).pack(anchor="w")
            ctk.CTkLabel(txt, text=body, font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w", height=18).pack(anchor="w")
            if action:
                ctk.CTkButton(rec, text=action[0], command=action[1],
                              **{**BTN_SECONDARY, "height": 32, "width": 130}).grid(row=r * 2, column=2, padx=22)
        ctk.CTkFrame(rec, width=1, height=10, fg_color="transparent").grid(row=99, column=0)

    def _emergency_tip(self) -> tuple:
        """Recommendation row describing the Emergency Access setup."""
        try:
            status = self.db.emergency_access_status()
        except Exception:
            logging.exception("Could not read emergency access status.")
            status = None
        if not status:
            return (ACCENT, "Set up Emergency Access",
                    "Let trusted people recover your vault together if you ever lose access.",
                    ("Set up", self._open_emergency_access))
        created = ""
        try:
            created = datetime.fromisoformat(status.get('created_at', '')).strftime("%b %d, %Y")
        except (ValueError, TypeError):
            pass
        head = f"Emergency Access: {status['threshold']} of {status['shares']} trustees"
        if created:
            head += f"  ·  set up {created}"
        return (SUCCESS, head, f"Any {status['threshold']} trustees together can recover this vault.",
                ("Manage", self._open_emergency_access))

    def _show_issue_items(self, issue: str):
        """Show only breached or suspicious items in the item list."""
        self._show_view("all", reload=False)
        self._issue_filter = issue
        self.page_title.configure(text="Breached items" if issue == "breached" else "Suspicious items")
        self._apply_filter_and_render()

    # ── Breach check ───────────────────────────────────────────
    def _reset_breach_state(self):
        """Forget all breach results and abandon any check in flight (called on lock)."""
        self._breach_gen += 1
        self._breach_results = {}
        self._breach_checked_at = None
        self._breach_unchecked = 0
        self._breach_running = False
        self._breach_progress = (0, 0)
        self._breach_error = None

    def _render_breach_card(self):
        """(Re)draws the Breach check card from the current breach state."""
        card = self._breach_card
        if card is None or not card.winfo_exists():
            return
        for w in card.winfo_children():
            w.destroy()
        card.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, padx=22, pady=(20, 0), sticky="ew")
        head.grid_columnconfigure(0, weight=1)
        title_row = ctk.CTkFrame(head, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(title_row, text="Breach check", font=FONT_SUBHEADING, text_color=TEXT_PRIMARY).pack(side="left")
        n = len(self._breach_results)
        if self._breach_checked_at is not None and not self._breach_running:
            if n:
                _badge(title_row, f"{n} breached", DANGER_SOFT, DANGER).pack(side="left", padx=(10, 0))
            elif not self._breach_unchecked:
                _badge(title_row, "No breaches found", SUCCESS_SOFT, SUCCESS).pack(side="left", padx=(10, 0))
        ctk.CTkLabel(head, text="Only the first 5 characters of each password's SHA-1 hash leave this device.",
                     font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w").grid(row=1, column=0, sticky="w")
        btn_text = ("Checking…" if self._breach_running else
                    "Check again" if self._breach_checked_at else "Check for breaches")
        btn_style = BTN_SECONDARY if self._breach_checked_at else BTN_PRIMARY
        ctk.CTkButton(head, text=btn_text, command=self._start_breach_check,
                      state="disabled" if self._breach_running or not self.encryption_key else "normal",
                      **{**btn_style, "height": 34, "width": 156}).grid(row=0, column=1, rowspan=2, sticky="e")

        status = ctk.CTkFrame(card, fg_color="transparent")
        status.grid(row=1, column=0, padx=22, pady=(12, 0), sticky="ew")
        status.grid_columnconfigure(0, weight=1)
        if self._breach_running:
            done, total = self._breach_progress
            ctk.CTkLabel(status, text=f"Checking {done} of {total}…" if total else "Preparing…",
                         font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w", height=18).grid(row=0, column=0, sticky="w")
            bar = ctk.CTkProgressBar(status, height=6, corner_radius=3, fg_color=SURFACE_ACTIVE, progress_color=ACCENT)
            bar.set(done / total if total else 0)
            bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        else:
            if self._breach_error:
                err = ctk.CTkFrame(status, fg_color=DANGER_SOFT, corner_radius=BUTTON_RADIUS)
                err.grid(row=1, column=0, sticky="ew", pady=(0, 6))
                ctk.CTkLabel(err, text="", image=draw_icon('warning', DANGER, (14, 14)), width=14).pack(
                    side="left", padx=(12, 8), pady=8)
                ctk.CTkLabel(err, text=self._breach_error, font=FONT_SMALL, text_color=DANGER,
                             anchor="w", height=18).pack(side="left", pady=8)
            if self._breach_checked_at:
                when = self._breach_checked_at.astimezone().strftime("%b %d, %I:%M %p").replace(" 0", " ")
                text = f"Last checked {when}"
                if self._breach_unchecked:
                    text += f"  ·  {self._breach_unchecked} item{'s' if self._breach_unchecked != 1 else ''} couldn't be checked"
            else:
                text = "Not checked yet. Checking needs an internet connection."
            ctk.CTkLabel(status, text=text, font=FONT_SMALL, text_color=TEXT_MUTED, anchor="w",
                         height=18).grid(row=2, column=0, sticky="w")

        rows = sorted(((cid, cnt) for cid, cnt in self._breach_results.items() if cid in self.current_credentials),
                      key=lambda kv: -kv[1])
        if rows and not self._breach_running:
            lst = ctk.CTkFrame(card, fg_color="transparent")
            lst.grid(row=2, column=0, padx=22, pady=(10, 0), sticky="ew")
            lst.grid_columnconfigure(1, weight=1)
            shown = rows[:8]
            for i, (cid, count) in enumerate(shown):
                cred = self.current_credentials[cid]
                ctk.CTkFrame(lst, height=1, fg_color=BORDER, corner_radius=0).grid(
                    row=i * 2, column=0, columnspan=4, sticky="ew")
                _avatar(lst, cred['service'], 28, FONT_BADGE)[0].grid(row=i * 2 + 1, column=0, padx=(0, 12), pady=8)
                txt = ctk.CTkFrame(lst, fg_color="transparent")
                txt.grid(row=i * 2 + 1, column=1, sticky="w")
                ctk.CTkLabel(txt, text=cred['service'] or "", font=FONT_BODY_BOLD, text_color=TEXT_PRIMARY,
                             anchor="w", height=18).pack(anchor="w")
                ctk.CTkLabel(txt, text=cred['username'] or "", font=FONT_SMALL, text_color=TEXT_MUTED,
                             anchor="w", height=16).pack(anchor="w")
                ctk.CTkLabel(lst, text=f"Seen {breach.format_count(count)} times", font=FONT_SMALL,
                             text_color=DANGER, width=120, anchor="e").grid(row=i * 2 + 1, column=2, padx=(12, 14))
                ctk.CTkButton(lst, text="Change password", command=lambda c=cid: self._edit_credential(c),
                              **{**BTN_SECONDARY, "height": 30, "width": 132}).grid(row=i * 2 + 1, column=3)
            if len(rows) > len(shown):
                ctk.CTkButton(lst, text=f"Show all {len(rows)} breached items",
                              command=lambda: self._show_issue_items("breached"),
                              **{**BTN_GHOST, "text_color": ACCENT, "height": 28}).grid(
                    row=99, column=0, columnspan=4, sticky="w", pady=(4, 0))
        ctk.CTkFrame(card, width=1, height=18, fg_color="transparent").grid(row=9, column=0)

    def _start_breach_check(self):
        """Checks every password against HIBP in a worker thread (k-anonymity range API)."""
        if self._breach_running or not self.encryption_key:
            return
        passwords: Dict[int, str] = {}
        snapshot: Dict[int, bytes] = {}
        for cid, cred in self.current_credentials.items():
            pw = self._decrypt_password(cid)
            if pw is not None:
                passwords[cid] = pw
                snapshot[cid] = cred['encrypted_password']
        if not passwords:
            self._set_status("Nothing to check.", 3000)
            return
        gen = self._breach_gen
        self._breach_running = True
        self._breach_error = None
        self._breach_progress = (0, len(passwords))
        self._set_status("Checking passwords against known data breaches…")
        self._render_breach_card()

        def work(report):
            try:
                return breach.check_many(passwords, progress=report)
            finally:
                passwords.clear()     # drop the transient plaintext as soon as the lookups finish

        run_in_thread(self, work,
                      lambda result, error: self._on_breach_done(gen, snapshot, result, error),
                      on_progress=lambda done, total: self._on_breach_progress(gen, done, total))

    def _on_breach_progress(self, gen: int, done: int, total: int):
        if gen != self._breach_gen:
            return
        self._breach_progress = (done, total)
        self._render_breach_card()

    def _on_breach_done(self, gen: int, snapshot: Dict[int, bytes], result, error):
        if gen != self._breach_gen:     # vault was locked meanwhile: discard
            return
        self._breach_running = False
        if error is not None or not result or all(v is None for v in result.values()):
            if error is not None:
                logging.warning("Breach check failed: %s", error)
            self._breach_error = "Couldn't reach Have I Been Pwned. Check your internet connection and try again."
            self._set_status("Breach check failed: you appear to be offline.", 5000)
            self._render_breach_card()
            return
        self._breach_error = None
        self._breach_checked_at = datetime.now(timezone.utc)
        # Ignore results for items that were edited or deleted while the check ran
        current = {cid: count for cid, count in result.items()
                   if cid in self.current_credentials
                   and self.current_credentials[cid]['encrypted_password'] == snapshot.get(cid)}
        self._breach_unchecked = sum(1 for v in current.values() if v is None)
        self._breach_results = {cid: count for cid, count in current.items() if count}
        n = len(self._breach_results)
        self._set_status(f"Breach check complete: {n} breached password{'s' if n != 1 else ''} found."
                         if n else "Breach check complete: no breached passwords found.", 5000)
        self._security_dirty = True
        self._apply_filter_and_render()
        if self.current_view == "security":
            self._update_analytics(self._all_creds)

    # ── Actions ────────────────────────────────────────────────
    def _open_emergency_access(self):
        try:
            from app.ui.emergency_dialogs import EmergencySetupDialog
        except Exception as e:
            logging.exception("Could not load emergency access dialogs.")
            messagebox.showerror("Error", f"Emergency Access is unavailable:\n{e}", parent=self)
            return
        release_grab(self)
        try:
            dialog = EmergencySetupDialog(parent=self, db=self.db, vault_key=self.encryption_key)
            self.wait_window(dialog)
        except Exception as e:
            logging.exception("Failed to open emergency access dialog.")
            messagebox.showerror("Error", f"Could not open Emergency Access:\n{e}", parent=self)
        finally:
            if self.winfo_exists():
                self.after(50, self.grab_set)
                self._security_dirty = True
                if self.current_view == "security" and self.encryption_key:
                    self._update_analytics(self._all_creds)
    def _toggle_favorite(self, cid):
        try:
            self.db.toggle_favorite_status(cid)
            self.load_and_display_credentials(self.search_var.get())
        except Exception as e:
            messagebox.showerror("Error", f"Could not toggle favorite:\n{e}", parent=self)

    def _copy_to_clipboard(self, text, label):
        if not text:
            self._set_status(f"{label} is empty.", 3000)
            return
        try:
            if self.clipboard_clear_job:
                self.after_cancel(self.clipboard_clear_job)
            pyperclip.copy(text)
            _last_copied['value'] = text
            timeout_s = settings.CLIPBOARD_TIMEOUT // 1000
            self._set_status(f"{label} copied to clipboard  ·  clears in {timeout_s}s", settings.CLIPBOARD_TIMEOUT)
            self.clipboard_clear_job = self.after(settings.CLIPBOARD_TIMEOUT, self._clear_clipboard)
        except Exception as e:
            self._set_status(f"Copy failed: {e}", 3000)

    def _clear_clipboard(self):
        try:
            value = _last_copied.get('value')
            if value and pyperclip.paste() == value:
                pyperclip.copy('')
                self._set_status("Clipboard cleared.", 3000)
            _last_copied['value'] = None
        except Exception:
            pass
        self.clipboard_clear_job = None

    def _decrypt_password(self, cid) -> Optional[str]:
        cred = self.current_credentials.get(cid)
        if not cred or not self.encryption_key:
            return None
        password = decrypt_data(cred['encrypted_password'], self.encryption_key)
        return None if password == DECRYPTION_ERROR else password

    def _encrypt_notes(self, notes: str) -> str:
        return encrypt_data(notes, self.encryption_key).decode('utf-8') if notes else ""

    def _decrypt_notes(self, notes) -> str:
        if not notes:
            return ""
        if isinstance(notes, bytes):
            notes = notes.decode('utf-8', 'replace')
        if notes.startswith("gAAAAA"):  # Fernet token prefix
            plain = decrypt_data(notes.encode('utf-8'), self.encryption_key)
            if plain != DECRYPTION_ERROR:
                return plain
        return notes  # Legacy plaintext note; it is encrypted on the next save

    def _copy_password(self, cid):
        password = self._decrypt_password(cid)
        if password is None:
            self._set_status("Password could not be decrypted.", 3000)
            return
        self._copy_to_clipboard(password, "Password")

    def _view_password(self, cid):
        release_grab(self)
        try:
            entered = MasterPasswordPrompt(self, heading="Enter Master Password to view").get_password()
        finally:
            self.after(50, self.grab_set)
        if not entered:
            return
        try:
            if self.db.verify_master_password(entered):
                password = self._decrypt_password(cid)
                if password is not None:
                    messagebox.showinfo(f"Password — {self.current_credentials[cid]['service']}", password, parent=self)
                else:
                    messagebox.showwarning("Unavailable", "Password could not be decrypted.", parent=self)
            else:
                wait = self.db.lockout_remaining()
                messagebox.showerror("Failed", f"Too many attempts. Try again in {wait}s." if wait else "Incorrect master password.", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Verification error:\n{e}", parent=self)

    def _change_master_password(self):
        release_grab(self)
        try:
            values = ChangeMasterPasswordDialog(self).get_input()
        finally:
            self.after(50, self.grab_set)
        if not values:
            return
        current, new = values
        if not self.db.verify_master_password(current):
            wait = self.db.lockout_remaining()
            messagebox.showerror("Failed", f"Too many attempts. Try again in {wait}s." if wait else "Incorrect current master password.", parent=self)
            return
        try:
            self.db.change_master_password(self.encryption_key, new)
            messagebox.showinfo("Done", "Master password changed.\nYour stored passwords are unchanged.", parent=self)
        except ValueError as e:
            messagebox.showerror("Error", str(e), parent=self)
        except Exception as e:
            logging.exception("Failed to change master password.")
            messagebox.showerror("Error", f"Could not change master password:\n{e}", parent=self)

    def _open_security_questions(self):
        release_grab(self)
        try:
            dialog =SecurityQuestionsSetupDialog(parent=self, db=self.db, vault_key=self.encryption_key)
            self.wait_window(dialog)
        except Exception as e:
            logging.exception("Failed to open security questions dialog.")
            messagebox.showerror("Error", f"Could not open security questions:\n{e}", parent=self)
        finally:
            if self.winfo_exists():
                self.after(50, self.grab_set)

    def _vault_urls(self, exclude: Optional[int] = None) -> List[str]:
        """Saved URLs of all items except `exclude` (used as trusted domains by the phishing guard)."""
        return [c['url'] for cid, c in self.current_credentials.items()
                if cid != exclude and (c.get('url') or '').strip()]

    def _add_credential_dialog(self):
        result = None
        grabbed = False
        try:
            self.grab_release()
            grabbed = True
            dialog = CredentialDialog(parent=self, title="New Item", vault_urls=self._vault_urls())
            result = dialog.get_input()
        except Exception as e:
            messagebox.showerror("Error", f"Could not open dialog:\n{e}", parent=self)
        finally:
            if grabbed:
                self.after(50, self.grab_set)
        if result:
            service, username, password, notes, url = result
            try:
                enc = encrypt_data(password, self.encryption_key)
                self.db.add_credential(service, username, enc, self._encrypt_notes(notes), url)
                self.load_and_display_credentials("")
                if self.search_var.get():
                    self.search_var.set("")
                self._set_status(f"'{service}' added.", 3000)
            except ValueError as e:
                messagebox.showerror("Error", str(e), parent=self)
            except Exception as e:
                messagebox.showerror("Error", f"Could not save:\n{e}", parent=self)

    def _edit_credential(self, cid):
        cred = self.current_credentials.get(cid)
        password = self._decrypt_password(cid)
        if not cred or password is None:
            messagebox.showerror("Error", "Credential not found or could not be decrypted.", parent=self)
            return
        result = None
        grabbed = False
        try:
            self.grab_release()
            grabbed = True
            dialog = CredentialDialog(parent=self, title="Edit Item",
                                      initial_service=cred['service'], initial_username=cred['username'],
                                      initial_password=password, initial_notes=self._decrypt_notes(cred['notes']),
                                      initial_url=cred.get('url', ''),
                                      vault_urls=self._vault_urls(exclude=cid))
            result = dialog.get_input()
        except Exception as e:
            messagebox.showerror("Error", f"Could not open dialog:\n{e}", parent=self)
        finally:
            if grabbed:
                self.after(50, self.grab_set)
        if result:
            service, username, new_password, notes, url = result
            try:
                # Only re-encrypt when the password actually changed, so its age is preserved
                enc = encrypt_data(new_password, self.encryption_key) if new_password != password else None
                del password, new_password
                self.db.update_credential(cid, service, username, enc, self._encrypt_notes(notes), url)
                if enc is not None:
                    self._breach_results.pop(cid, None)   # old result no longer applies
                self.load_and_display_credentials(self.search_var.get())
                self._set_status(f"'{service}' updated.", 3000)
            except Exception as e:
                messagebox.showerror("Error", f"Could not update:\n{e}", parent=self)

    def _delete_credential(self, cid, service):
        user = self.current_credentials.get(cid, {}).get('username', '?')
        grabbed = False
        try:
            self.grab_release()
            grabbed = True
        except Exception:
            pass
        confirm = messagebox.askyesno("Delete item",
                                      f"Delete this item? This cannot be undone.\n\nService: {service}\nUsername: {user}",
                                      icon='warning', parent=self)
        if grabbed:
            self.after(50, self.grab_set)
        if confirm:
            try:
                self.db.delete_credential(cid)
                self.current_credentials.pop(cid, None)
                self.load_and_display_credentials(self.search_var.get())
                self._set_status(f"'{service}' deleted.", 3000)
            except Exception as e:
                messagebox.showerror("Error", f"Could not delete:\n{e}", parent=self)

    def _open_password_generator(self):
        try:
            self.grab_release()
            gen = PasswordGeneratorWindow(self)
            gen.focus()
        except Exception as e:
            messagebox.showerror("Error", f"Could not open generator:\n{e}", parent=self)
            self.after(50, self.grab_set)

    def _on_closing(self):
        if self.clipboard_clear_job:
            self.after_cancel(self.clipboard_clear_job)
            self._clear_clipboard()
        release_grab(self)
        self.destroy()

    def destroy(self):
        if hasattr(self, 'autolock_timer_id') and self.autolock_timer_id is not None:
            self.after_cancel(self.autolock_timer_id)
        super().destroy()


class CredentialDialog(ctk.CTkToplevel):
    """Add/edit item dialog. get_input() returns (service, username, password, notes, url) or None."""

    STRENGTH_WORDS = {0: "Too weak", 1: "Too weak", 2: "Weak", 3: "Fair", 4: "Good", 5: "Strong"}

    def __init__(self, parent, title: str, initial_service: str = "", initial_username: str = "",
                 initial_password: str = "", initial_notes: str = "", initial_url: str = "",
                 vault_urls: Optional[List[str]] = None):
        super().__init__(parent)
        self.configure(fg_color=SURFACE)
        self.vault_urls = list(vault_urls or [])     # other items' URLs (trusted by the phishing guard)
        self._url_job = None
        self._breach_token = 0
        self.dialog_title = title
        self.initial_service = initial_service
        self.initial_username = initial_username
        self.initial_password = initial_password
        self.initial_notes = initial_notes
        self.initial_url = initial_url
        self.result: Optional[tuple] = None
        self._password_visible = False
        self.grab_set()
        self.title(title)
        self.geometry("520x700")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.password_var = ctk.StringVar(value=initial_password)
        self.password_var.trace_add("write", self._update_strength)
        self.after(1, self._create_widgets)

    def _field_label(self, parent, text, optional=False):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=(14, 6))
        ctk.CTkLabel(row, text=text.upper(), font=FONT_CAPTION, text_color=TEXT_SECONDARY, height=14).pack(side="left")
        if optional:
            ctk.CTkLabel(row, text="Optional", font=FONT_SMALL, text_color=TEXT_MUTED, height=14).pack(side="right")

    def _create_widgets(self):
        try:
            icon_size = (16, 16)
            self.visible_icon = load_icon(settings.VISIBLE_ICON_FILE, size=icon_size, tint=TEXT_SECONDARY)
            self.hidden_icon = load_icon(settings.HIDDEN_ICON_FILE, size=icon_size, tint=TEXT_SECONDARY)

            is_edit = bool(self.initial_service)
            # Header
            head = ctk.CTkFrame(self, fg_color="transparent")
            head.pack(fill="x", padx=PAD_X + 4, pady=(24, 0))
            ctk.CTkLabel(head, text=self.dialog_title, font=FONT_HEADING, text_color=TEXT_PRIMARY,
                         anchor="w").pack(anchor="w")
            ctk.CTkLabel(head, text="Update the details of this login." if is_edit else
                         "Save a login to your encrypted vault.",
                         font=FONT_BODY, text_color=TEXT_MUTED, anchor="w").pack(anchor="w")

            # Footer (packed before the body so it is always visible)
            footer = ctk.CTkFrame(self, fg_color=BG, corner_radius=0, height=68)
            footer.pack(side="bottom", fill="x")
            footer.pack_propagate(False)
            ctk.CTkFrame(self, height=1, fg_color=BORDER, corner_radius=0).pack(side="bottom", fill="x")
            ctk.CTkButton(footer, text="Save" if is_edit else "Save item", width=112, command=self._save,
                          **BTN_PRIMARY).pack(side="right", padx=(8, PAD_X + 4), pady=16)
            ctk.CTkButton(footer, text="Cancel", width=96, command=self._cancel,
                          **BTN_SECONDARY).pack(side="right", pady=16)

            body = ctk.CTkFrame(self, fg_color="transparent")
            body.pack(fill="both", expand=True, padx=PAD_X + 4, pady=(6, 18))

            self._field_label(body, "Name")
            self.service_entry = ctk.CTkEntry(body, placeholder_text="e.g. GitHub", **ENTRY_STYLE)
            self.service_entry.pack(fill="x")
            self.service_entry.insert(0, self.initial_service)

            self._field_label(body, "Username or email")
            self.username_entry = ctk.CTkEntry(body, placeholder_text="name@company.com", **ENTRY_STYLE)
            self.username_entry.pack(fill="x")
            self.username_entry.insert(0, self.initial_username)

            self._field_label(body, "Password")
            pw_row = ctk.CTkFrame(body, fg_color="transparent")
            pw_row.pack(fill="x")
            pw_row.grid_columnconfigure(0, weight=1)
            self.password_entry = ctk.CTkEntry(pw_row, show="•", textvariable=self.password_var,
                                               **{**ENTRY_STYLE, "font": FONT_MONO})
            self.password_entry.grid(row=0, column=0, sticky="ew")
            self.toggle_btn = ctk.CTkButton(pw_row, text="" if self.hidden_icon else "Show", image=self.hidden_icon,
                                            command=self._toggle_visibility,
                                            **{**BTN_SECONDARY, "width": 40, "height": 40})
            self.toggle_btn.grid(row=0, column=1, padx=(8, 0))
            Tooltip(self.toggle_btn, "Show / hide password")

            meter = ctk.CTkFrame(body, fg_color="transparent")
            meter.pack(fill="x", pady=(10, 0))
            meter.grid_columnconfigure(0, weight=1)
            self.strength_bar = ctk.CTkProgressBar(meter, height=4, corner_radius=2,
                                                   fg_color=SURFACE_ACTIVE, progress_color=ACCENT)
            self.strength_bar.grid(row=0, column=0, sticky="ew", padx=(0, 12))
            self.strength_bar.set(0)
            self.strength_label = ctk.CTkLabel(meter, text="", width=70, anchor="e", height=16,
                                               font=FONT_BADGE, text_color=TEXT_MUTED)
            self.strength_label.grid(row=0, column=1, sticky="e")
            self.breach_link = ctk.CTkLabel(meter, text="", height=16, font=FONT_SMALL,
                                            text_color=ACCENT, cursor="hand2")
            self.breach_link.grid(row=0, column=2, sticky="e", padx=(12, 0))
            self.breach_link.bind("<Button-1>", lambda e: self._check_breach())
            Tooltip(self.breach_link, "Checks Have I Been Pwned. Only the first 5 characters of the "
                                      "password's SHA-1 hash leave this device.")

            self.rules_frame = ctk.CTkFrame(body, fg_color="transparent")
            self.rules_frame.pack(fill="x", pady=(6, 0))
            self.rule_labels = {}
            self._rule_texts = {}
            rules_text = [
                ('length', "8+ characters"),
                ('upper', "Uppercase"),
                ('lower', "Lowercase"),
                ('digit', "Number"),
                ('special', "Symbol"),
            ]
            for i, (key, text) in enumerate(rules_text):
                lbl = ctk.CTkLabel(self.rules_frame, text=text, font=FONT_SMALL, text_color=TEXT_MUTED,
                                   anchor="w", height=18)
                lbl.pack(side="left", padx=(0, 14))
                self.rule_labels[key] = lbl
                self._rule_texts[key] = text

            self._field_label(body, "Website", optional=True)
            self.url_entry = ctk.CTkEntry(body, placeholder_text="https://", **ENTRY_STYLE)
            self.url_entry.pack(fill="x")
            self.url_entry.insert(0, self.initial_url)
            self.url_entry.bind("<KeyRelease>", self._schedule_url_check, add="+")
            self.url_entry.bind("<<Paste>>", self._schedule_url_check, add="+")
            self.url_entry.bind("<FocusOut>", lambda e: self._check_url(), add="+")
            self.url_warning = ctk.CTkFrame(body, fg_color=SECONDARY_SOFT, corner_radius=BUTTON_RADIUS)
            self.url_warning.grid_columnconfigure(1, weight=1)
            self.url_warning_icon = ctk.CTkLabel(self.url_warning, text="", width=16)
            self.url_warning_icon.grid(row=0, column=0, rowspan=2, padx=(12, 10), pady=10, sticky="n")
            self.url_warning_head = ctk.CTkLabel(self.url_warning, text="", font=FONT_BODY_BOLD, anchor="w",
                                                 justify="left", height=18, wraplength=400)
            self.url_warning_head.grid(row=0, column=1, sticky="w", pady=(9, 0), padx=(0, 12))
            self.url_warning_body = ctk.CTkLabel(self.url_warning, text="", font=FONT_SMALL, anchor="w",
                                                 justify="left", text_color=TEXT_SECONDARY, height=16,
                                                 wraplength=400)
            self.url_warning_body.grid(row=1, column=1, sticky="w", pady=(0, 9), padx=(0, 12))
            self._url_warning_icons = {phishing.HIGH: draw_icon('warning', DANGER, (16, 16)),
                                       phishing.MEDIUM: draw_icon('warning', SECONDARY, (16, 16))}

            self._field_label(body, "Notes", optional=True)
            self.notes_box = ctk.CTkTextbox(body, height=84, wrap="word", font=FONT_BODY, border_width=1,
                                            corner_radius=BUTTON_RADIUS)
            self.notes_box.pack(fill="both", expand=True)
            if self.initial_notes:
                self.notes_box.insert("1.0", self.initial_notes)

            self.service_entry.focus()
            if self.initial_service:
                self.service_entry.select_range(0, 'end')
            self.bind("<Return>", lambda e: None if e.widget == getattr(self.notes_box, "_textbox", None) else self._save())
            self.bind("<Escape>", lambda e: self._cancel())
            self.after(50, lambda: center_over(self, self.master, require_viewable=False))
            self._update_strength()
            self._check_url()
        except Exception as e:
            logging.exception("CredentialDialog: FAILED _create_widgets")
            messagebox.showerror("Error", f"Failed to create dialog:\n{e}", parent=self)
            self.after(10, self.destroy)

    def _update_strength(self, *args):
        if not hasattr(self, 'strength_bar') or not self.strength_bar.winfo_exists():
            return
        pw = self.password_var.get()
        checks = password_policy_checks(pw)

        for key, passed in checks.items():
            if key in self.rule_labels:
                self.rule_labels[key].configure(
                    text=f"✓ {self._rule_texts[key]}" if passed else self._rule_texts[key],
                    text_color=SUCCESS if passed else TEXT_MUTED)

        score = sum(checks.values())
        # Any earlier breach result belonged to a different password
        self._breach_token += 1
        if hasattr(self, 'breach_link') and self.breach_link.winfo_exists():
            self.breach_link.configure(text="Check if breached" if pw else "", text_color=ACCENT, cursor="hand2")
        if not pw:
            self.strength_bar.set(0)
            self.strength_label.configure(text="")
            return
        self.strength_bar.set(score / 5.0)
        color = DANGER if score <= 2 else SECONDARY if score == 3 else ACCENT if score == 4 else SUCCESS
        self.strength_bar.configure(progress_color=color)
        self.strength_label.configure(text=self.STRENGTH_WORDS[score].upper(), text_color=color)

    def _check_breach(self):
        """Looks up the typed password in HIBP (k-anonymity) off the Tk thread; shows the result inline."""
        pw = self.password_var.get()
        if not pw or self.breach_link.cget("cursor") != "hand2":
            return
        self._breach_token += 1
        token = self._breach_token
        self.breach_link.configure(text="Checking…", text_color=TEXT_MUTED, cursor="")

        def done(count, error):
            if token != self._breach_token or not self.breach_link.winfo_exists():
                return
            if error is not None:
                logging.warning("Breach check failed: %s", error)
                self.breach_link.configure(text="Couldn't check (offline?)  ·  Retry", text_color=TEXT_MUTED,
                                           cursor="hand2")
            elif count:
                self.breach_link.configure(text=f"Seen {breach.format_count(count)} times in breaches",
                                           text_color=DANGER, cursor="")
            else:
                self.breach_link.configure(text="Not found in known breaches", text_color=SUCCESS, cursor="")

        run_in_thread(self, lambda report: breach.pwned_count(pw), done)

    def _url_finding(self) -> Optional["phishing.Finding"]:
        """Worst lookalike finding for the Website field, checked against the other items' domains."""
        url = self.url_entry.get().strip()
        if not url:
            return None
        try:
            return phishing.worst(phishing.analyze_url(url, self.vault_urls))
        except Exception:
            logging.exception("Phishing analysis failed")
            return None

    def _schedule_url_check(self, event=None):
        if self._url_job:
            self.after_cancel(self._url_job)
        self._url_job = self.after(350, self._check_url)

    def _check_url(self):
        """Shows or hides the lookalike-domain warning banner under the Website field."""
        self._url_job = None
        if not hasattr(self, 'url_warning') or not self.url_warning.winfo_exists():
            return
        finding = self._url_finding()
        if finding is None:
            self.url_warning.pack_forget()
            return
        high = finding.severity == phishing.HIGH
        color = DANGER if high else SECONDARY
        if finding.lookalike_of:
            head = f"This looks like {finding.lookalike_of} — check the address carefully."
        else:
            head = "This address may be impersonating another site."
        self.url_warning.configure(fg_color=DANGER_SOFT if high else SECONDARY_SOFT)
        self.url_warning_icon.configure(image=self._url_warning_icons[finding.severity if high else phishing.MEDIUM])
        self.url_warning_head.configure(text=head, text_color=color)
        self.url_warning_body.configure(text=finding.message)
        if not self.url_warning.winfo_manager():
            self.url_warning.pack(fill="x", pady=(8, 0), after=self.url_entry)

    def _toggle_visibility(self):
        self._password_visible = not self._password_visible
        self.password_entry.configure(show="" if self._password_visible else "•")
        icon = self.visible_icon if self._password_visible else self.hidden_icon
        if icon:
            self.toggle_btn.configure(image=icon)
        else:
            self.toggle_btn.configure(text="Hide" if self._password_visible else "Show")

    def _save(self):
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        url = self.url_entry.get().strip()
        password = self.password_var.get()
        notes = self.notes_box.get("1.0", "end-1c").strip()

        if not service or not username or not password:
            messagebox.showwarning("Required", "Name, username and password are required.", parent=self)
            self.lift()
            self.focus()
            return

        checks = password_policy_checks(password)
        if not checks['length']:
            messagebox.showwarning("Too Short", "Password must be at least 8 characters long.", parent=self)
            self.lift()
            self.focus()
            return
        if not all(checks.values()):
            missing = [name for key, name in (('upper', "uppercase letter"), ('lower', "lowercase letter"),
                                              ('digit', "number"), ('special', "symbol"))
                       if not checks[key]]
            if not messagebox.askyesno("Weak Password",
                                       "This password has no " + ", ".join(missing) + ".\n\nSave anyway?",
                                       icon='warning', parent=self):
                self.lift()
                self.focus()
                return

        finding = self._url_finding()
        if finding is not None and finding.severity == phishing.HIGH:
            if not messagebox.askyesno("Suspicious website",
                                       f"{finding.message}.\n\nPhishing sites copy real addresses "
                                       "with small changes. Save anyway?",
                                       icon='warning', parent=self):
                self.lift()
                self.url_entry.focus_set()
                return

        self.result = (service, username, password, notes, url)
        self._close()

    def _cancel(self, event=None):
        self.result = None
        self._close()

    def _close(self):
        if self._url_job:
            self.after_cancel(self._url_job)
            self._url_job = None
        self._breach_token += 1
        release_grab(self)
        try:
            self.destroy()
        except Exception:
            pass

    def get_input(self) -> Optional[tuple]:
        """Blocks until the dialog closes; returns the entered values, or None if cancelled."""
        self.wait_window()
        if self.master and self.master.winfo_exists():
            self.master.focus_force()
        return self.result

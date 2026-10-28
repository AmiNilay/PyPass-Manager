# password_manager/app/ui/theme.py
"""
Centralized design tokens for the PyPass Manager graphite theme.
Import this in every UI file for consistent styling.
"""


# ── Core Palette ──────────────────────────────────────────────
# Graphite neutrals with a single trust-blue accent. Colours are
# chosen for WCAG AA contrast of text on BG / SURFACE.
BG              = "#0E1014"       # app background
SIDEBAR         = "#0B0D10"       # navigation rail
SURFACE         = "#161920"       # cards, dialogs
SURFACE_HOVER   = "#1E222B"       # row / ghost-button hover
SURFACE_ACTIVE  = "#252A35"       # selected nav item
BORDER          = "#262B35"
BORDER_STRONG   = "#343A47"

ACCENT          = "#3B82F6"       # primary actions
ACCENT_HOVER    = "#2F6FDB"
ACCENT_SOFT     = "#172338"       # tinted backgrounds (badges, focus)
SECONDARY       = "#F5A524"       # favourites, warnings
SUCCESS         = "#22C55E"
DANGER          = "#EF4444"
DANGER_HOVER    = "#D63B3B"
DANGER_SOFT     = "#2A1618"

TEXT_PRIMARY      = "#E8EAED"
TEXT_SECONDARY    = "#A1A8B5"
TEXT_MUTED        = "#6B7280"
TEXT_ON_ACCENT    = "#FFFFFF"

INPUT_BG         = "#12151B"
INPUT_BORDER     = "#2C323D"


# ── Typography ────────────────────────────────────────────────
# Segoe UI Variable ships with Windows 11; Tk falls back to Segoe UI.
FONT_FAMILY      = "Segoe UI"
FONT_DISPLAY     = (FONT_FAMILY, 26, "bold")
FONT_HEADING     = (FONT_FAMILY, 20, "bold")
FONT_SUBHEADING  = (FONT_FAMILY, 15, "bold")
FONT_BODY        = (FONT_FAMILY, 13)
FONT_BODY_BOLD   = (FONT_FAMILY, 13, "bold")
FONT_SMALL       = (FONT_FAMILY, 11)
FONT_CAPTION     = (FONT_FAMILY, 10, "bold")   # uppercase section labels
FONT_MONO        = ("Cascadia Mono", 13)

# ── Dimensions ────────────────────────────────────────────────
CORNER_RADIUS    = 12
BUTTON_RADIUS    = 8
BUTTON_HEIGHT    = 36
INPUT_HEIGHT     = 40
PAD_X            = 24
PAD_Y            = 16
ICON_SIZE_SM     = (16, 16)


# ── Button presets ────────────────────────────────────────────
# Usage: ctk.CTkButton(parent, text="Save", **BTN_PRIMARY)
BTN_PRIMARY = dict(fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=TEXT_ON_ACCENT,
                   corner_radius=BUTTON_RADIUS, height=BUTTON_HEIGHT, font=FONT_BODY_BOLD,
                   border_width=0)
BTN_SECONDARY = dict(fg_color=SURFACE, hover_color=SURFACE_HOVER, text_color=TEXT_PRIMARY,
                     corner_radius=BUTTON_RADIUS, height=BUTTON_HEIGHT, font=FONT_BODY,
                     border_width=1, border_color=BORDER_STRONG)
BTN_GHOST = dict(fg_color="transparent", hover_color=SURFACE_HOVER, text_color=TEXT_SECONDARY,
                 corner_radius=BUTTON_RADIUS, height=BUTTON_HEIGHT, font=FONT_BODY,
                 border_width=0)
BTN_DANGER = dict(fg_color=DANGER, hover_color=DANGER_HOVER, text_color=TEXT_ON_ACCENT,
                  corner_radius=BUTTON_RADIUS, height=BUTTON_HEIGHT, font=FONT_BODY_BOLD,
                  border_width=0)
ENTRY_STYLE = dict(fg_color=INPUT_BG, border_color=INPUT_BORDER, text_color=TEXT_PRIMARY,
                   placeholder_text_color=TEXT_MUTED, corner_radius=BUTTON_RADIUS,
                   height=INPUT_HEIGHT, border_width=1, font=FONT_BODY)
CARD_STYLE = dict(fg_color=SURFACE, corner_radius=CORNER_RADIUS, border_width=1,
                  border_color=BORDER)


def apply_widget_defaults() -> None:
    """
    Call ONCE after CTk root is created.
    Patches the global CTk theme so every widget picks up our
    palette without needing to specify colors on each instance.
    """
    from customtkinter import ThemeManager

    theme = ThemeManager.theme

    # ── CTk (root) ──
    theme["CTk"]["fg_color"] = [BG, BG]

    # ── CTkFrame ──
    theme["CTkFrame"]["fg_color"] = [SURFACE, SURFACE]
    theme["CTkFrame"]["top_fg_color"] = [SURFACE, SURFACE]
    theme["CTkFrame"]["border_color"] = [BORDER, BORDER]

    # ── CTkButton ──
    theme["CTkButton"]["fg_color"] = [ACCENT, ACCENT]
    theme["CTkButton"]["hover_color"] = [ACCENT_HOVER, ACCENT_HOVER]
    theme["CTkButton"]["text_color"] = [TEXT_ON_ACCENT, TEXT_ON_ACCENT]
    theme["CTkButton"]["text_color_disabled"] = [TEXT_MUTED, TEXT_MUTED]
    theme["CTkButton"]["corner_radius"] = BUTTON_RADIUS
    theme["CTkButton"]["border_width"] = 0

    # ── CTkEntry ──
    theme["CTkEntry"]["fg_color"] = [INPUT_BG, INPUT_BG]
    theme["CTkEntry"]["border_color"] = [INPUT_BORDER, INPUT_BORDER]
    theme["CTkEntry"]["text_color"] = [TEXT_PRIMARY, TEXT_PRIMARY]
    theme["CTkEntry"]["placeholder_text_color"] = [TEXT_MUTED, TEXT_MUTED]
    theme["CTkEntry"]["corner_radius"] = BUTTON_RADIUS

    # ── CTkLabel ──
    theme["CTkLabel"]["text_color"] = [TEXT_PRIMARY, TEXT_PRIMARY]

    # ── CTkCheckBox ──
    theme["CTkCheckBox"]["fg_color"] = [ACCENT, ACCENT]
    theme["CTkCheckBox"]["hover_color"] = [ACCENT_HOVER, ACCENT_HOVER]
    theme["CTkCheckBox"]["text_color"] = [TEXT_SECONDARY, TEXT_SECONDARY]
    theme["CTkCheckBox"]["border_color"] = [BORDER_STRONG, BORDER_STRONG]
    theme["CTkCheckBox"]["checkmark_color"] = [TEXT_ON_ACCENT, TEXT_ON_ACCENT]
    theme["CTkCheckBox"]["corner_radius"] = 4

    # ── CTkSwitch ──
    theme["CTkSwitch"]["fg_color"] = [BORDER_STRONG, BORDER_STRONG]
    theme["CTkSwitch"]["progress_color"] = [ACCENT, ACCENT]
    theme["CTkSwitch"]["button_color"] = [TEXT_PRIMARY, TEXT_PRIMARY]
    theme["CTkSwitch"]["text_color"] = [TEXT_SECONDARY, TEXT_SECONDARY]

    # ── CTkSlider ──
    theme["CTkSlider"]["fg_color"] = [BORDER, BORDER]
    theme["CTkSlider"]["progress_color"] = [ACCENT, ACCENT]
    theme["CTkSlider"]["button_color"] = [TEXT_PRIMARY, TEXT_PRIMARY]
    theme["CTkSlider"]["button_hover_color"] = [ACCENT_HOVER, ACCENT_HOVER]

    # ── CTkOptionMenu ──
    theme["CTkOptionMenu"]["fg_color"] = [SURFACE_HOVER, SURFACE_HOVER]
    theme["CTkOptionMenu"]["button_color"] = [SURFACE_ACTIVE, SURFACE_ACTIVE]
    theme["CTkOptionMenu"]["button_hover_color"] = [BORDER_STRONG, BORDER_STRONG]
    theme["CTkOptionMenu"]["text_color"] = [TEXT_PRIMARY, TEXT_PRIMARY]
    theme["CTkOptionMenu"]["text_color_disabled"] = [TEXT_MUTED, TEXT_MUTED]

    # ── CTkProgressBar ──
    theme["CTkProgressBar"]["fg_color"] = [BORDER, BORDER]
    theme["CTkProgressBar"]["progress_color"] = [ACCENT, ACCENT]

    # ── CTkScrollableFrame ──
    theme["CTkScrollableFrame"]["fg_color"] = [BG, BG]
    theme["CTkScrollableFrame"]["label_fg_color"] = [SURFACE, SURFACE]
    theme["CTkScrollableFrame"]["scrollbar_fg_color"] = [SURFACE, SURFACE]
    theme["CTkScrollableFrame"]["scrollbar_button_color"] = [BORDER, BORDER]
    theme["CTkScrollableFrame"]["scrollbar_button_hover_color"] = [BORDER_STRONG, BORDER_STRONG]
    theme["CTkScrollableFrame"]["label_text_color"] = [TEXT_PRIMARY, TEXT_PRIMARY]

    # ── CTkTextbox ──
    theme["CTkTextbox"]["fg_color"] = [INPUT_BG, INPUT_BG]
    theme["CTkTextbox"]["text_color"] = [TEXT_PRIMARY, TEXT_PRIMARY]
    theme["CTkTextbox"]["scrollbar_fg_color"] = [SURFACE, SURFACE]
    theme["CTkTextbox"]["scrollbar_button_color"] = [BORDER, BORDER]
    theme["CTkTextbox"]["scrollbar_button_hover_color"] = [BORDER_STRONG, BORDER_STRONG]
    theme["CTkTextbox"]["border_color"] = [INPUT_BORDER, INPUT_BORDER]

    # ── CTkToplevel ──
    theme["CTkToplevel"]["fg_color"] = [BG, BG]
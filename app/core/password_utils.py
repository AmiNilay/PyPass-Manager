"""Password strength estimation."""

import re
from typing import Tuple

# (score, label, color) for each points bucket, checked in order.
_STRENGTH_LEVELS = (
    (1, 0, "Very Weak", "#d9534f"),    # red
    (2, 1, "Weak", "#f0ad4e"),         # orange
    (3, 2, "Moderate", "#f0ad4e"),     # orange
    (4, 3, "Strong", "#5bc0de"),       # blue
)
_VERY_STRONG = (4, "Very Strong", "#5cb85c")  # green
_EMPTY = (0, "Empty", "#868e96")  # grey


def check_password_strength(password: str) -> Tuple[int, str, str]:
    """Rates a password by length and character variety.

    Returns:
        (score, text, color): score is 0 (Very Weak) to 4 (Very Strong), text is
        its label ("Empty" for an empty password) and color a suggested hex color.
    """
    if not password:
        return _EMPTY

    length = len(password)
    points = sum(length >= n for n in (8, 12, 16))

    variety = sum(
        bool(re.search(pattern, password))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^a-zA-Z0-9]")
    )
    points += sum(variety >= n for n in (2, 3, 4))

    for max_points, score, text, color in _STRENGTH_LEVELS:
        if points <= max_points:
            return score, text, color
    return _VERY_STRONG

# password_manager/app/core/password_utils.py
import random
import string
import re # Import regular expressions for character checks

def generate_local_password(length: int = 16, use_uppercase: bool = True, use_digits: bool = True, use_symbols: bool = True) -> str:
    """Generates a random password locally based on specified criteria."""
    if length < 4: length = 4 # Ensure minimum length
    character_pool = string.ascii_lowercase
    required_chars = [random.choice(string.ascii_lowercase)]
    if use_uppercase: character_pool += string.ascii_uppercase; required_chars.append(random.choice(string.ascii_uppercase))
    if use_digits: character_pool += string.digits; required_chars.append(random.choice(string.digits))
    if use_symbols: character_pool += string.punctuation; required_chars.append(random.choice(string.punctuation))
    if not character_pool: return ""

    password_chars = required_chars[:] # Start with required characters
    remaining_length = length - len(password_chars)
    if remaining_length > 0:
        password_chars.extend(random.choice(character_pool) for _ in range(remaining_length))

    random.shuffle(password_chars)
    return "".join(password_chars)

# --- NEW: Password Strength Checker ---
def check_password_strength(password: str) -> tuple[int, str, str]:
    """
    Checks password strength based on simple criteria.

    Returns:
        A tuple containing:
        - score (int): 0 (Very Weak) to 4 (Very Strong). Range: 0-4.
        - text (str): Description ("Very Weak", "Weak", "Moderate", "Strong", "Very Strong").
        - color (str): A suggested color ('#d9534f', '#f0ad4e', '#5bc0de', '#5cb85c').
    """
    score = 0
    text = "Very Weak"
    color = "#d9534f" # Default Red (Bootstrap danger)
    length = len(password)

    if not password:
        return 0, "Empty", "#868e96" # Grey for empty

    # --- Scoring Logic (Example - can be adjusted) ---
    points = 0
    # Length bonus
    if length >= 8: points += 1
    if length >= 12: points += 1
    if length >= 16: points += 1

    # Character type presence bonus
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    # More permissive symbol check
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    if variety_count >= 2: points += 1
    if variety_count >= 3: points += 1
    if variety_count >= 4: points += 1 # Bonus for all 4 types

    # --- Map points to score (0-4) and text/color ---
    # Example mapping: Adjust thresholds as needed
    if points <= 1: # Very weak (e.g., < 8 chars OR just one type)
        score = 0
        text = "Very Weak"
        color = "#d9534f" # Red
    elif points <= 2: # Weak (e.g., >= 8 chars, maybe 2 types)
        score = 1
        text = "Weak"
        color = "#f0ad4e" # Orange
    elif points <= 3: # Moderate (e.g., >= 8 chars, 3 types OR >=12 chars, 2 types)
        score = 2
        text = "Moderate"
        color = "#f0ad4e" # Orange (or maybe #5bc0de - info blue)
    elif points <= 4: # Strong (e.g., >=12 chars, 3 types)
        score = 3
        text = "Strong"
        color = "#5bc0de" # Blue
    else: # Very Strong (e.g., >=12 chars, 4 types OR >=16 chars, 3+ types)
        score = 4
        text = "Very Strong"
        color = "#5cb85c" # Green

    return score, text, color
# --- End NEW ---
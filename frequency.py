"""
frequency.py — Letter Frequency Analysis & Confidence Scoring
CipherShift: Where statistics do the heavy lifting so you don't have to.

Fun fact: 'E' is the most common letter in English.
Less fun fact: You'll be thinking about this forever now.
"""

import numpy as np
from collections import Counter

# Expected English letter frequencies (A-Z), source: Cornell/Lewand
# The holy grail of frequency analysis — don't touch these numbers
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253,
    'E': 0.12702, 'F': 0.02228, 'G': 0.02015, 'H': 0.06094,
    'I': 0.06966, 'J': 0.00153, 'K': 0.00772, 'L': 0.04025,
    'M': 0.02406, 'N': 0.06749, 'O': 0.07507, 'P': 0.01929,
    'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150,
    'Y': 0.01974, 'Z': 0.00074
}

LETTERS = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')


def get_letter_frequencies(text: str) -> dict:
    """
    Calculate letter frequency distribution of given text (0.0 - 1.0 per letter).
    Non-alpha characters are ignored because spaces aren't a cipher unit.
    Returns a dict with all 26 letters, even if count is 0.
    """
    text_upper = text.upper()
    alpha_only = [c for c in text_upper if c.isalpha()]

    if not alpha_only:
        return {letter: 0.0 for letter in LETTERS}

    counts = Counter(alpha_only)
    total = len(alpha_only)

    return {letter: counts.get(letter, 0) / total for letter in LETTERS}


def chi_squared_score(text: str) -> float:
    """
    Compute chi-squared statistic comparing text frequency to English.
    Lower score = closer to English = better match.

    This is the number that separates 'solved it' from 'try another shift'.
    """
    observed = get_letter_frequencies(text)
    total_alpha = sum(1 for c in text.upper() if c.isalpha())

    if total_alpha == 0:
        return float('inf')

    chi2 = 0.0
    for letter in LETTERS:
        expected_count = ENGLISH_FREQ[letter] * total_alpha
        observed_count = observed[letter] * total_alpha
        if expected_count > 0:
            chi2 += ((observed_count - expected_count) ** 2) / expected_count

    return chi2


def compute_confidence(text: str) -> float:
    """
    Convert chi-squared score into a human-readable confidence percentage (0-100).

    Thresholds were tuned empirically on CTF cipher challenges.
    If you're getting 100% on garbage text, something's wrong — or it's ROT13.
    Especially ROT13. It's always ROT13.

    Returns float in range [0.0, 100.0]
    """
    alpha_chars = [c for c in text if c.isalpha()]
    if len(alpha_chars) < 3:
        # Can't meaningfully analyze < 3 letters. Short texts are chaos.
        return 0.0

    chi2 = chi_squared_score(text)

    # Sigmoid-like normalization: chi2 of ~0 → 100%, chi2 of ~500+ → ~0%
    # Scale factor tuned for typical Caesar-length ciphertexts
    confidence = 100.0 * np.exp(-chi2 / 50.0)

    return round(min(max(confidence, 0.0), 100.0), 2)


def index_of_coincidence(text: str) -> float:
    """
    Compute the Index of Coincidence (IoC) for the text.

    English plaintext: IoC ≈ 0.065
    Random text: IoC ≈ 0.038
    Caesar cipher of English: also ≈ 0.065 (shift doesn't change IoC)
    Vigenère cipher: IoC drops toward random range

    Used for Vigenère detection — if IoC is too low, Caesar won't save you.
    Time to switch tools. RIP.
    """
    text_upper = ''.join(c for c in text.upper() if c.isalpha())
    n = len(text_upper)

    if n < 2:
        return 0.0

    counts = Counter(text_upper)
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)

    return numerator / denominator if denominator > 0 else 0.0

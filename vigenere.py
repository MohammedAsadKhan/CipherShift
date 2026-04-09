"""
vigenere.py — Vigenère Cipher Cracker
CipherShift: Now with polyalphabetic support, because apparently one alphabet wasn't enough.

Works best on: medium-length English or French ciphertext (100+ chars)
If this fails: try dcode.fr or CyberChef. No shame. We built this for easy-medium CTF challenges.
"""

from frequency import index_of_coincidence, ENGLISH_FREQ
from collections import Counter
import numpy as np

# ── Language Frequency Tables ─────────────────────────────────────────────────

FRENCH_FREQ = {
    'A': 0.07636, 'B': 0.00901, 'C': 0.03260, 'D': 0.03669, 'E': 0.14715,
    'F': 0.01066, 'G': 0.00866, 'H': 0.00737, 'I': 0.07529, 'J': 0.00613,
    'K': 0.00049, 'L': 0.05456, 'M': 0.02968, 'N': 0.07095, 'O': 0.05796,
    'P': 0.02521, 'Q': 0.01362, 'R': 0.06553, 'S': 0.07948, 'T': 0.07244,
    'U': 0.06311, 'V': 0.01838, 'W': 0.00074, 'X': 0.00427, 'Y': 0.00128,
    'Z': 0.00326
}

LANGUAGE_PROFILES = {
    'english': ENGLISH_FREQ,
    'french': FRENCH_FREQ,
}

LETTERS = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')

# IoC targets per language
IOC_TARGETS = {
    'english': 0.0655,
    'french':  0.0778,
}

# ── Key Length Detection ───────────────────────────────────────────────────────

def kasiski_key_lengths(ciphertext: str, max_key_len: int = 12) -> list[int]:
    """
    Use Index of Coincidence across key length candidates to rank likely key lengths.

    For each candidate length L, split text into L columns (every L-th character).
    The correct key length will make each column look like a Caesar-shifted
    mono-alphabetic distribution → high average IoC.

    Returns a ranked list of candidate key lengths (most likely first).
    """
    text = ''.join(c.upper() for c in ciphertext if c.isalpha())
    if len(text) < 20:
        return [1]

    scores = []
    for key_len in range(1, min(max_key_len + 1, len(text) // 2)):
        columns = [''.join(text[i::key_len]) for i in range(key_len)]
        avg_ioc = np.mean([index_of_coincidence(col) for col in columns if len(col) > 1])
        scores.append((key_len, avg_ioc))

    # Sort by how close the average IoC is to 0.065 (English mono-alpha target)
    scores.sort(key=lambda x: abs(x[1] - 0.065))
    return [s[0] for s in scores]


def detect_language(ciphertext: str) -> str:
    """
    Rough language detection based on IoC of the raw ciphertext.
    French plaintext has a higher IoC target than English.
    Only useful as a hint — not authoritative.

    Returns 'french' or 'english'.
    """
    # Can't detect from ciphertext directly (it's encrypted), so we use
    # heuristics: if the ciphertext IoC is closer to French target, lean French.
    # In practice, for CTFs, trust the challenge description.
    ioc = index_of_coincidence(ciphertext)
    en_diff = abs(ioc - IOC_TARGETS['english'])
    fr_diff = abs(ioc - IOC_TARGETS['french'])
    return 'french' if fr_diff < en_diff else 'english'


# ── Column Caesar Cracking ─────────────────────────────────────────────────────

def crack_column(column: str, freq_table: dict) -> tuple[int, float]:
    """
    Given a single column of ciphertext (every key_len-th character),
    find the Caesar shift that best matches the target language frequency table.

    Returns (best_shift, confidence_score).
    """
    column = column.upper()
    n = len(column)
    if n == 0:
        return 0, 0.0

    counts = Counter(column)
    best_shift = 0
    best_score = float('inf')  # chi-squared: lower is better

    for shift in range(26):
        chi2 = 0.0
        for i, letter in enumerate(LETTERS):
            # What letter maps TO 'letter' under this shift?
            original = LETTERS[(i - shift) % 26]
            observed = counts.get(original, 0) / n
            expected = freq_table.get(letter, 0.0001)
            chi2 += ((observed - expected) ** 2) / expected
        if chi2 < best_score:
            best_score = chi2
            best_shift = shift

    # Invert to confidence: lower chi2 = higher confidence
    confidence = round(100.0 * np.exp(-best_score / 30.0), 2)
    return best_shift, confidence


# ── Main Cracker ──────────────────────────────────────────────────────────────

def crack_vigenere(ciphertext: str, language: str = 'auto', max_key_len: int = 12) -> dict:
    """
    Attempt to crack a Vigenère cipher using IoC-based key length detection
    and per-column frequency analysis.

    Args:
        ciphertext: The encrypted text
        language: 'english', 'french', or 'auto' (auto-detect)
        max_key_len: Maximum key length to try (default 12)

    Returns a result dict:
    {
        'success': bool,
        'key': str,
        'decoded': str,
        'key_length': int,
        'confidence': float,
        'language': str,
        'fallback_message': str or None   # set if confidence is low
    }

    Works best on: 100+ character ciphertext, English or French, key length ≤ 12
    If confidence is low, we'll tell you to try CyberChef. No judgment.
    """
    text_alpha = ''.join(c.upper() for c in ciphertext if c.isalpha())

    # ── Guard: too short ──────────────────────────────────────────────────────
    if len(text_alpha) < 30:
        return {
            'success': False,
            'key': None,
            'decoded': None,
            'key_length': None,
            'confidence': 0.0,
            'language': language,
            'fallback_message': (
                "Text too short for reliable Vigenère analysis (need 30+ letters). "
                "Try CyberChef if you know the key."
            )
        }

    # ── Language selection ────────────────────────────────────────────────────
    if language == 'auto':
        language = detect_language(ciphertext)
    freq_table = LANGUAGE_PROFILES.get(language, ENGLISH_FREQ)

    # ── Key length detection ──────────────────────────────────────────────────
    candidate_lengths = kasiski_key_lengths(ciphertext, max_key_len=max_key_len)
    best_key_len = candidate_lengths[0]

    # ── Per-column crack ──────────────────────────────────────────────────────
    columns = [''.join(text_alpha[i::best_key_len]) for i in range(best_key_len)]
    key_shifts = []
    col_confidences = []

    for col in columns:
        shift, conf = crack_column(col, freq_table)
        key_shifts.append(shift)
        col_confidences.append(conf)

    key = ''.join(LETTERS[s] for s in key_shifts)
    avg_confidence = round(float(np.mean(col_confidences)), 2)

    # ── Decode ────────────────────────────────────────────────────────────────
    decoded = vigenere_decode(ciphertext, key)

    # ── Confidence assessment ─────────────────────────────────────────────────
    fallback = None
    if avg_confidence < 40:
        fallback = (
            f"Low confidence ({avg_confidence:.1f}%). CipherShift works best on easy-medium "
            f"challenges with 100+ characters. For harder/shorter ciphertexts, "
            f"try: dcode.fr/vigenere-cipher (best for French), or CyberChef."
        )
    elif avg_confidence < 60:
        fallback = (
            f"Medium confidence ({avg_confidence:.1f}%). Result may be partially correct — "
            f"check the output manually. If it looks like gibberish, try dcode.fr."
        )

    return {
        'success': avg_confidence >= 40,
        'key': key,
        'decoded': decoded,
        'key_length': best_key_len,
        'confidence': avg_confidence,
        'language': language,
        'fallback_message': fallback
    }


def vigenere_decode(ciphertext: str, key: str) -> str:
    """
    Decode a Vigenère cipher given the key.
    Preserves case and non-alpha characters.
    """
    key = key.upper()
    result = []
    key_idx = 0

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            decoded_char = chr((ord(char.upper()) - ord('A') - shift) % 26 + ord('A'))
            result.append(decoded_char if char.isupper() else decoded_char.lower())
            key_idx += 1
        else:
            result.append(char)

    return ''.join(result)


def vigenere_encode(plaintext: str, key: str) -> str:
    """
    Encode plaintext with a Vigenère cipher using the given key.
    """
    key = key.upper()
    result = []
    key_idx = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            base_char = char.upper()
            encoded = chr((ord(base_char) - ord('A') + shift) % 26 + ord('A'))
            result.append(encoded if char.isupper() else encoded.lower())
            key_idx += 1
        else:
            result.append(char)

    return ''.join(result)

"""
analyzer.py — Core Caesar Cipher Logic
CipherShift: Because manually testing 25 shifts is a war crime.
"""

from frequency import compute_confidence, ENGLISH_FREQ
from double_encode import detect_double_encoding, detect_rot13, detect_vigenere


def caesar_shift(text: str, shift: int) -> str:
    """
    Apply a Caesar cipher shift to text.
    Positive shift = encrypt, negative shift = decrypt (or shift 26-n).
    Preserves case, non-alpha characters untouched.
    """
    result = []
    shift = shift % 26  # normalize, because someone will definitely pass in 27

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26
            result.append(chr(base + shifted))
        else:
            result.append(char)

    return ''.join(result)


def encrypt(text: str, shift: int) -> str:
    """Encrypt plaintext with a given shift."""
    return caesar_shift(text, shift)


def decrypt(text: str, shift: int) -> str:
    """Decrypt ciphertext with a known shift."""
    return caesar_shift(text, -shift)


def brute_force(ciphertext: str) -> list[dict]:
    """
    Try all 25 shifts and rank them by confidence score.

    Returns a list of dicts sorted by confidence descending:
    [{ 'shift': int, 'text': str, 'confidence': float }, ...]

    Shift 0 is technically valid but boring — we include it anyway.
    """
    results = []
    for shift in range(26):
        decoded = caesar_shift(ciphertext, -shift)
        confidence = compute_confidence(decoded)
        results.append({
            'shift': shift,
            'text': decoded,
            'confidence': confidence
        })

    # Sort by confidence, highest first
    results.sort(key=lambda x: x['confidence'], reverse=True)
    return results


def auto_crack(ciphertext: str) -> dict:
    """
    Automatically determine the most likely shift using frequency analysis.

    Returns the best result with full metadata:
    {
        'shift': int,
        'decoded': str,
        'confidence': float,
        'all_results': list,
        'is_rot13': bool,
        'double_encode': dict or None,
        'vigenere_flag': bool
    }
    """
    all_results = brute_force(ciphertext)
    best = all_results[0]

    return {
        'shift': best['shift'],
        'decoded': best['text'],
        'confidence': best['confidence'],
        'all_results': all_results,
        'is_rot13': detect_rot13(ciphertext),
        'double_encode': detect_double_encoding(ciphertext),
        'vigenere_flag': detect_vigenere(ciphertext)
    }

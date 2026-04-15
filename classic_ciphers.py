"""
classic_ciphers.py — Atbash, Rail Fence, Playfair
CipherShift: Now handling the ciphers that show up right after the Caesar ones in CTFs.

Atbash: A=Z, B=Y, you get it. It's its own inverse. Very dramatic.
Rail Fence: A transposition cipher written in a zigzag. CTF authors love it.
Playfair: A digraph cipher from 1854. Can't auto-crack it — we'll be honest about that.
"""

import numpy as np
from frequency import compute_confidence
from itertools import combinations

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


# ─────────────────────────────────────────────────────────────────────────────
# ATBASH
# ─────────────────────────────────────────────────────────────────────────────

def atbash_decode(text: str) -> str:
    """
    Atbash cipher: A↔Z, B↔Y, C↔X, etc.
    It's its own inverse — encode and decode are identical operations.
    Preserves case and non-alpha characters.
    """
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decoded = chr(base + (25 - (ord(char.upper()) - ord('A'))))
            result.append(decoded)
        else:
            result.append(char)
    return ''.join(result)


def crack_atbash(ciphertext: str) -> dict:
    """
    Auto-crack Atbash. Since it's self-inverse, there's only one possibility.
    We just decode and score it.

    Returns:
    {
        'success': bool,
        'decoded': str,
        'confidence': float,
        'fallback_message': str or None
    }
    """
    decoded = atbash_decode(ciphertext)
    confidence = compute_confidence(decoded)

    fallback = None
    if confidence < 40:
        fallback = (
            f"Low confidence ({confidence:.1f}%). Atbash decoded text doesn't look like English. "
            "The input may not be Atbash, or it might be a different language. "
            "Try CyberChef: https://gchq.github.io/CyberChef"
        )

    return {
        'success': confidence >= 40,
        'decoded': decoded,
        'confidence': confidence,
        'fallback_message': fallback
    }


# ─────────────────────────────────────────────────────────────────────────────
# RAIL FENCE
# ─────────────────────────────────────────────────────────────────────────────

def rail_fence_decode(ciphertext: str, rails: int) -> str:
    """
    Decode a Rail Fence cipher with a known number of rails.

    Rail Fence works by writing plaintext in a zigzag pattern across N rails,
    then reading off each rail left to right. Decoding reverses this.
    """
    text = [c for c in ciphertext if c.isalpha()]
    n = len(text)

    if rails <= 1 or rails >= n:
        return ciphertext

    # Build the zigzag pattern to know how many chars go on each rail
    pattern = _build_rail_pattern(n, rails)

    # Count chars per rail
    rail_lengths = [0] * rails
    for r in pattern:
        rail_lengths[r] += 1

    # Slice ciphertext into rail segments
    rails_text = []
    idx = 0
    for length in rail_lengths:
        rails_text.append(list(text[idx:idx + length]))
        idx += length

    # Read off in zigzag order
    rail_indices = [0] * rails
    result = []
    for r in pattern:
        result.append(rails_text[r][rail_indices[r]])
        rail_indices[r] += 1

    # Re-insert non-alpha characters at their original positions
    return _reinsert_nonalpha(ciphertext, ''.join(result))


def rail_fence_encode(plaintext: str, rails: int) -> str:
    """
    Encode plaintext with Rail Fence cipher using given number of rails.
    """
    text = [c for c in plaintext if c.isalpha()]
    n = len(text)

    if rails <= 1 or rails >= n:
        return plaintext

    pattern = _build_rail_pattern(n, rails)

    # Group characters by rail
    rail_chars = [[] for _ in range(rails)]
    for i, r in enumerate(pattern):
        rail_chars[r].append(text[i])

    return ''.join(''.join(rail) for rail in rail_chars)


def _build_rail_pattern(n: int, rails: int) -> list:
    """Build the zigzag rail assignment for n characters across given rails."""
    pattern = []
    rail = 0
    direction = 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return pattern


def _reinsert_nonalpha(original: str, alpha_result: str) -> str:
    """Re-insert non-alpha characters from original into the decoded alpha result."""
    result = []
    alpha_iter = iter(alpha_result)
    for char in original:
        if char.isalpha():
            try:
                result.append(next(alpha_iter))
            except StopIteration:
                break
        else:
            result.append(char)
    return ''.join(result)


def crack_rail_fence(ciphertext: str, max_rails: int = 10) -> dict:
    """
    Brute force Rail Fence by trying rails 2 through max_rails.
    Ranks results by confidence score, returns best result.

    Returns:
    {
        'success': bool,
        'rails': int,
        'decoded': str,
        'confidence': float,
        'all_results': list of {rails, text, confidence},
        'fallback_message': str or None
    }
    """
    results = []
    for r in range(2, max_rails + 1):
        decoded = rail_fence_decode(ciphertext, r)
        confidence = compute_confidence(decoded)
        results.append({
            'rails': r,
            'text': decoded,
            'confidence': confidence
        })

    results.sort(key=lambda x: x['confidence'], reverse=True)
    best = results[0]

    fallback = None
    if best['confidence'] < 40:
        fallback = (
            f"Low confidence ({best['confidence']:.1f}%) even for best rail count. "
            "Rail Fence brute force works best on longer English text. "
            "Try CyberChef: https://gchq.github.io/CyberChef"
        )

    return {
        'success': best['confidence'] >= 40,
        'rails': best['rails'],
        'decoded': best['text'],
        'confidence': best['confidence'],
        'all_results': results,
        'fallback_message': fallback
    }


# ─────────────────────────────────────────────────────────────────────────────
# PLAYFAIR
# ─────────────────────────────────────────────────────────────────────────────

def _build_playfair_square(key: str) -> list:
    """
    Build a 5x5 Playfair key square from the given key.
    J is merged with I (standard convention).
    """
    key = key.upper().replace('J', 'I')
    seen = []
    for char in key + LETTERS:
        if char.isalpha() and char != 'J' and char not in seen:
            seen.append(char)
    return [seen[i:i+5] for i in range(0, 25, 5)]


def _playfair_position(square: list, char: str) -> tuple:
    """Find row, col of a character in the Playfair square."""
    for r, row in enumerate(square):
        if char in row:
            return r, row.index(char)
    return None


def _playfair_process_digraphs(text: str) -> list:
    """
    Split text into Playfair digraphs.
    - Remove non-alpha, uppercase, replace J with I
    - Insert X between repeated letters in a pair
    - Pad with X if odd length
    """
    text = ''.join(c for c in text.upper() if c.isalpha()).replace('J', 'I')
    digraphs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 >= len(text):
            digraphs.append((a, 'X'))
            break
        b = text[i + 1]
        if a == b:
            digraphs.append((a, 'X'))
            i += 1
        else:
            digraphs.append((a, b))
            i += 2
    return digraphs


def playfair_decode(ciphertext: str, key: str) -> str:
    """
    Decode a Playfair cipher with a known key.

    Rules (reversed for decoding):
    - Same row: shift left
    - Same col: shift up
    - Rectangle: swap columns
    """
    square = _build_playfair_square(key)
    digraphs = _playfair_process_digraphs(ciphertext)
    result = []

    for a, b in digraphs:
        ra, ca = _playfair_position(square, a)
        rb, cb = _playfair_position(square, b)

        if ra == rb:
            # Same row — shift left (decode)
            result.append(square[ra][(ca - 1) % 5])
            result.append(square[rb][(cb - 1) % 5])
        elif ca == cb:
            # Same column — shift up (decode)
            result.append(square[(ra - 1) % 5][ca])
            result.append(square[(rb - 1) % 5][cb])
        else:
            # Rectangle — swap columns
            result.append(square[ra][cb])
            result.append(square[rb][ca])

    return ''.join(result)


def playfair_encode(plaintext: str, key: str) -> str:
    """
    Encode plaintext with a Playfair cipher using the given key.
    """
    square = _build_playfair_square(key)
    digraphs = _playfair_process_digraphs(plaintext)
    result = []

    for a, b in digraphs:
        ra, ca = _playfair_position(square, a)
        rb, cb = _playfair_position(square, b)

        if ra == rb:
            result.append(square[ra][(ca + 1) % 5])
            result.append(square[rb][(cb + 1) % 5])
        elif ca == cb:
            result.append(square[(ra + 1) % 5][ca])
            result.append(square[(rb + 1) % 5][cb])
        else:
            result.append(square[ra][cb])
            result.append(square[rb][ca])

    return ''.join(result)


def crack_playfair(ciphertext: str, key: str = None) -> dict:
    """
    Playfair crack handler.

    If key is provided: decode and return with confidence score.
    If no key: be honest — auto-cracking Playfair is computationally hard
    and out of scope. Redirect to CyberChef/dcode.fr.

    Returns:
    {
        'success': bool,
        'decoded': str or None,
        'confidence': float,
        'key': str or None,
        'fallback_message': str or None
    }
    """
    if not key:
        return {
            'success': False,
            'decoded': None,
            'confidence': 0.0,
            'key': None,
            'fallback_message': (
                "Playfair auto-crack is not supported — it requires a key. "
                "If you have the key, re-run with -k YOURKEY. "
                "Otherwise try: https://www.dcode.fr/playfair-cipher "
                "or CyberChef: https://gchq.github.io/CyberChef"
            )
        }

    decoded = playfair_decode(ciphertext, key)
    confidence = compute_confidence(decoded)

    fallback = None
    if confidence < 40:
        fallback = (
            f"Low confidence ({confidence:.1f}%). Key may be wrong, or "
            "the ciphertext might not be Playfair. "
            "Double-check your key or try: https://www.dcode.fr/playfair-cipher"
        )

    return {
        'success': confidence >= 40,
        'decoded': decoded,
        'confidence': confidence,
        'key': key.upper(),
        'fallback_message': fallback
    }

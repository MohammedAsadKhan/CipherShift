"""
encodings.py — Encoding Detection & Decoder
CipherShift: Because half of CTF "ciphers" are just Base64 with extra steps.

Supports: Base64, Hex, Binary, ROT47
Also handles recursive/nested encodings — because yes, people do that.

"It's just Base64." — Me, at 2am, right before it turned out to be Base64 of Hex of ROT47.
"""

import base64
import re
import string
from frequency import compute_confidence

MAX_DECODE_DEPTH = 5  # Don't recurse forever. That way lies madness.


# ─────────────────────────────────────────────────────────────────────────────
# INDIVIDUAL DECODERS
# ─────────────────────────────────────────────────────────────────────────────

def try_base64(text: str) -> str | None:
    """
    Attempt to decode text as Base64.
    Returns decoded string if successful and result is printable ASCII, else None.
    """
    text = text.strip()

    # Base64 strings are typically a multiple of 4 chars (with = padding)
    # and only contain A-Z, a-z, 0-9, +, /, =
    b64_pattern = re.compile(r'^[A-Za-z0-9+/=\s]+$')
    if not b64_pattern.match(text):
        return None

    # Pad if needed
    padded = text.replace(' ', '')
    padding = len(padded) % 4
    if padding:
        padded += '=' * (4 - padding)

    try:
        decoded_bytes = base64.b64decode(padded)
        decoded = decoded_bytes.decode('utf-8', errors='replace')
        # Check it's actually readable — not binary garbage
        printable_ratio = sum(1 for c in decoded if c in string.printable) / max(len(decoded), 1)
        if printable_ratio >= 0.85:
            return decoded
    except Exception:
        pass

    return None


def try_hex(text: str) -> str | None:
    """
    Attempt to decode text as hexadecimal.
    Handles both plain hex (48656c6c6f) and space-separated (48 65 6c).
    Returns decoded string if successful, else None.
    """
    text = text.strip().replace(' ', '').replace('\n', '')

    # Must be even-length hex string
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    if not hex_pattern.match(text) or len(text) % 2 != 0:
        return None

    try:
        decoded_bytes = bytes.fromhex(text)
        decoded = decoded_bytes.decode('utf-8', errors='replace')
        printable_ratio = sum(1 for c in decoded if c in string.printable) / max(len(decoded), 1)
        if printable_ratio >= 0.85:
            return decoded
    except Exception:
        pass

    return None


def try_binary(text: str) -> str | None:
    """
    Attempt to decode text as binary (space-separated 8-bit groups).
    e.g. '01001000 01100101 01101100 01101100 01101111'

    Returns decoded string if successful, else None.
    """
    text = text.strip()

    # Binary: groups of 8 bits separated by spaces (or just one long binary string)
    # Remove spaces and check it's only 0s and 1s
    no_spaces = text.replace(' ', '').replace('\n', '')
    if not re.match(r'^[01]+$', no_spaces):
        return None

    # Must be divisible by 8
    if len(no_spaces) % 8 != 0:
        return None

    try:
        chars = []
        for i in range(0, len(no_spaces), 8):
            byte = no_spaces[i:i + 8]
            chars.append(chr(int(byte, 2)))
        decoded = ''.join(chars)
        printable_ratio = sum(1 for c in decoded if c in string.printable) / max(len(decoded), 1)
        if printable_ratio >= 0.85:
            return decoded
    except Exception:
        pass

    return None


def try_rot47(text: str) -> str | None:
    """
    Apply ROT47 to text and return result if it scores well for English.

    ROT47 rotates all printable ASCII characters (33-126) by 47.
    Unlike ROT13, it covers digits and symbols too — common in CTFs.

    Returns decoded string if confidence is reasonable, else None.
    """
    result = []
    for char in text:
        code = ord(char)
        if 33 <= code <= 126:
            result.append(chr(33 + (code - 33 + 47) % 94))
        else:
            result.append(char)
    decoded = ''.join(result)

    # Only return if it looks like English text
    confidence = compute_confidence(decoded)
    if confidence >= 30:
        return decoded
    return None


def try_base32(text: str) -> str | None:
    """
    Attempt to decode text as Base32.
    Base32 uses A-Z and 2-7, with = padding.
    """
    text = text.strip().replace(' ', '')
    b32_pattern = re.compile(r'^[A-Z2-7=]+$')
    if not b32_pattern.match(text.upper()):
        return None

    try:
        padding = len(text) % 8
        if padding:
            text += '=' * (8 - padding)
        decoded_bytes = base64.b32decode(text.upper())
        decoded = decoded_bytes.decode('utf-8', errors='replace')
        printable_ratio = sum(1 for c in decoded if c in string.printable) / max(len(decoded), 1)
        if printable_ratio >= 0.85:
            return decoded
    except Exception:
        pass

    return None


# ─────────────────────────────────────────────────────────────────────────────
# ENCODING TYPE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_encoding_type(text: str) -> str | None:
    """
    Heuristic detection of encoding type based on character set and structure.
    Returns the most likely encoding name, or None if unrecognized.

    Order matters — binary is most specific, hex is more specific than base64.
    """
    text_clean = text.strip().replace(' ', '').replace('\n', '')

    # Binary: only 0s and 1s, length divisible by 8
    if re.match(r'^[01]+$', text_clean) and len(text_clean) % 8 == 0:
        return 'binary'

    # Hex: only hex chars, even length
    if re.match(r'^[0-9a-fA-F]+$', text_clean) and len(text_clean) % 2 == 0:
        # Disambiguate from Base64: hex chars are a subset of base64
        # If it's all lowercase hex or has no letters above F, it's hex
        if re.match(r'^[0-9a-f]+$', text_clean) or re.match(r'^[0-9A-F]+$', text_clean):
            return 'hex'

    # Base32: uppercase A-Z and 2-7 with possible = padding
    if re.match(r'^[A-Z2-7]+=*$', text_clean) and len(text_clean.rstrip('=')) % 8 in (0, 2, 4, 5, 7):
        return 'base32'

    # Base64: A-Z, a-z, 0-9, +, /, =
    if re.match(r'^[A-Za-z0-9+/=]+$', text_clean):
        return 'base64'

    # ROT47: printable ASCII heavy with no obvious pattern
    # (we try it by decode attempt, not heuristic)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# CASCADE DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

def detect_and_decode(text: str, depth: int = 0) -> dict:
    """
    Cascade encoding detection and decoding.
    Tries: Binary → Hex → Base32 → Base64 → ROT47
    Recursively decodes layers up to MAX_DECODE_DEPTH.

    Returns:
    {
        'detected': bool,
        'encoding_chain': list of str (e.g. ['base64', 'hex']),
        'decoded': str,
        'layers': int,
        'confidence': float,
        'fallback_message': str or None
    }
    """
    if depth >= MAX_DECODE_DEPTH:
        return {
            'detected': False,
            'encoding_chain': [],
            'decoded': text,
            'layers': depth,
            'confidence': compute_confidence(text),
            'fallback_message': f"Reached maximum decode depth ({MAX_DECODE_DEPTH}). Possible infinite loop or unknown encoding."
        }

    # Try each encoding in cascade order
    attempts = [
        ('binary',  try_binary),
        ('hex',     try_hex),
        ('base32',  try_base32),
        ('base64',  try_base64),
        ('rot47',   try_rot47),
    ]

    for enc_name, decoder in attempts:
        result = decoder(text)
        if result is not None and result != text:
            # Successfully decoded one layer — check if result is itself encoded
            inner = detect_and_decode(result, depth + 1)

            if inner['detected']:
                # There's another layer underneath
                return {
                    'detected': True,
                    'encoding_chain': [enc_name] + inner['encoding_chain'],
                    'decoded': inner['decoded'],
                    'layers': inner['layers'] + 1,
                    'confidence': inner['confidence'],
                    'fallback_message': inner.get('fallback_message')
                }
            else:
                # This is the final decoded result
                confidence = compute_confidence(result)
                return {
                    'detected': True,
                    'encoding_chain': [enc_name],
                    'decoded': result,
                    'layers': 1,
                    'confidence': confidence,
                    'fallback_message': None
                }

    # Nothing decoded successfully
    confidence = compute_confidence(text)
    fallback = None
    if confidence < 30:
        fallback = (
            "No supported encoding detected. Text doesn't look like Base64, Hex, Binary, or ROT47. "
            "Try CyberChef's 'Magic' operation: https://gchq.github.io/CyberChef — "
            "it handles dozens of encodings automatically."
        )

    return {
        'detected': False,
        'encoding_chain': [],
        'decoded': text,
        'layers': 0,
        'confidence': confidence,
        'fallback_message': fallback
    }


def decode_encoding(text: str, encoding: str) -> dict:
    """
    Force-decode with a specific encoding type.
    Use when you already know what you're dealing with.

    Returns:
    {
        'success': bool,
        'encoding': str,
        'decoded': str or None,
        'confidence': float,
        'fallback_message': str or None
    }
    """
    decoders = {
        'base64': try_base64,
        'hex':    try_hex,
        'binary': try_binary,
        'rot47':  try_rot47,
        'base32': try_base32,
    }

    decoder = decoders.get(encoding.lower())
    if not decoder:
        return {
            'success': False,
            'encoding': encoding,
            'decoded': None,
            'confidence': 0.0,
            'fallback_message': f"Unknown encoding '{encoding}'. Supported: base64, hex, binary, rot47, base32"
        }

    result = decoder(text)
    if result is None:
        return {
            'success': False,
            'encoding': encoding,
            'decoded': None,
            'confidence': 0.0,
            'fallback_message': (
                f"Failed to decode as {encoding}. Input may be malformed or not actually {encoding}. "
                "Try CyberChef: https://gchq.github.io/CyberChef"
            )
        }

    confidence = compute_confidence(result)
    return {
        'success': True,
        'encoding': encoding,
        'decoded': result,
        'confidence': confidence,
        'fallback_message': None
    }

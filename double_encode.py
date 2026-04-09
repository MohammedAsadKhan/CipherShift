"""
double_encode.py — Advanced Detection: Double Encoding, ROT13, Vigenère
CipherShift: For when one layer of encryption wasn't enough to feel clever.

To the CTF authors who double-encode Caesar ciphers:
We see you. We forgive you. We've automated defeating you.
"""

from frequency import compute_confidence, index_of_coincidence


# IOC thresholds — tuned for English Caesar vs. polyalphabetic ciphers
IOC_ENGLISH_MIN = 0.055   # Below this: suspicious, possibly Vigenère
IOC_ENGLISH_TARGET = 0.065  # English IoC bullseye
IOC_RANDOM = 0.038          # Fully random text IoC


def detect_rot13(ciphertext: str) -> bool:
    """
    Check if the text is ROT13 encoded (Caesar shift of exactly 13).

    ROT13 is the 'Hello World' of obfuscation — technically encryption,
    practically just vibes. If confidence with shift=13 is high, it's ROT13.

    Returns True if ROT13 is a strong candidate.
    """
    from analyzer import caesar_shift
    decoded = caesar_shift(ciphertext, -13)
    confidence = compute_confidence(decoded)
    return confidence >= 60.0  # 60% threshold: it's probably ROT13


def detect_vigenere(ciphertext: str) -> bool:
    """
    Flag whether the ciphertext is likely a Vigenère cipher rather than Caesar.

    Uses the Index of Coincidence:
    - Caesar shifts don't change IoC (it stays ≈ 0.065 for English)
    - Vigenère polyalphabetic substitution flattens the distribution → lower IoC

    If IoC drops significantly below English norms, Caesar cracking is futile.
    You need a different tool. Go open CyberChef. It's okay.

    Returns True if Vigenère is suspected (i.e., this tool probably can't help you).
    """
    text_alpha = ''.join(c for c in ciphertext if c.isalpha())
    if len(text_alpha) < 20:
        # Too short to make a reliable IoC determination
        # Short texts have high IoC variance regardless
        return False

    ioc = index_of_coincidence(ciphertext)
    return ioc < IOC_ENGLISH_MIN


def detect_double_encoding(ciphertext: str) -> dict | None:
    """
    Check whether decoding the ciphertext with the best shift reveals
    *another* Caesar-encoded layer underneath.

    CTF authors think this is clever. It is not. We've automated it.

    Returns a dict if double encoding is detected:
    {
        'detected': True,
        'first_shift': int,
        'second_shift': int,
        'intermediate': str,
        'final': str,
        'confidence': float
    }

    Returns None if no double encoding detected. (Normal human behavior.)
    """
    from analyzer import brute_force, caesar_shift

    # Layer 1: find the best shift for the original ciphertext
    layer1_results = brute_force(ciphertext)
    best_l1 = layer1_results[0]

    # Only proceed if layer 1 decode has decent confidence (otherwise it's
    # just garbage all the way down)
    if best_l1['confidence'] < 30.0:
        return None

    intermediate = best_l1['text']

    # Layer 2: try brute-forcing the intermediate text
    layer2_results = brute_force(intermediate)
    best_l2 = layer2_results[0]

    # Double encoding detected if:
    # 1. Layer 2 shift is non-zero (shift 0 = already decoded, not double encoded)
    # 2. Layer 2 confidence is meaningfully higher than layer 1
    # 3. Layer 2 gives a significant confidence boost
    if best_l2['shift'] == 0:
        return None

    confidence_boost = best_l2['confidence'] - best_l1['confidence']

    if best_l2['confidence'] >= 65.0 and confidence_boost >= 15.0:
        return {
            'detected': True,
            'first_shift': best_l1['shift'],
            'second_shift': best_l2['shift'],
            'intermediate': intermediate,
            'final': best_l2['text'],
            'confidence': best_l2['confidence']
        }

    return None


def get_detection_summary(ciphertext: str) -> dict:
    """
    Run all detection checks and return a full summary.
    Convenience wrapper for use in app.py.

    Returns:
    {
        'rot13': bool,
        'vigenere_flag': bool,
        'double_encode': dict or None
    }
    """
    return {
        'rot13': detect_rot13(ciphertext),
        'vigenere_flag': detect_vigenere(ciphertext),
        'double_encode': detect_double_encoding(ciphertext)
    }

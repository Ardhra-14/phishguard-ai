"""
IDN homograph detector — Phase 1.

Catches Unicode "confusable" characters (Cyrillic, Greek, etc.) that are
visually near-identical to Latin letters and are used to register
lookalike domains — e.g. "sbi" with a Cyrillic 'а' (U+0430) standing in
for the Latin 'a'. Also flags raw punycode ("xn--") labels.
"""
import unicodedata

# A small curated confusables map: look-alike character -> canonical ASCII
# letter. Not exhaustive (the full Unicode confusables table has thousands
# of entries) but covers the characters seen most often in real IDN
# phishing campaigns.
_CONFUSABLES: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ѡ": "w", "ᴠ": "v",
    "ⅼ": "l", "ⅰ": "i", "０": "0", "１": "1",
    "α": "a", "ο": "o", "ν": "v", "κ": "k", "β": "b", "ρ": "p",
}


def _is_ascii(ch: str) -> bool:
    return ord(ch) < 128


def detect_idn_homograph(domain: str) -> dict:
    """
    Returns:
        {
          "is_homograph": bool,
          "confusable_chars": [{"char", "codepoint", "looks_like", "script"}, ...],
          "risk_score": float 0-1,
          "punycode_flag": bool,
        }
    """
    domain = domain.strip().lower()
    punycode_flag = "xn--" in domain

    confusable_chars = []
    for ch in domain:
        if _is_ascii(ch) or ch in ".-_0123456789":
            continue
        if ch in _CONFUSABLES:
            try:
                script = unicodedata.name(ch, "UNKNOWN")
            except ValueError:
                script = "UNKNOWN"
            confusable_chars.append({
                "char": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "looks_like": _CONFUSABLES[ch],
                "script": script,
            })

    is_homograph = bool(confusable_chars) or punycode_flag

    if confusable_chars:
        risk_score = min(0.5 + 0.15 * len(confusable_chars), 1.0)
    elif punycode_flag:
        risk_score = 0.6
    else:
        risk_score = 0.0

    return {
        "is_homograph": is_homograph,
        "confusable_chars": confusable_chars,
        "risk_score": round(risk_score, 4),
        "punycode_flag": punycode_flag,
    }

"""
Image feature extraction - Phase 4 (Visual Detection).

Given a screenshot (raw image bytes), extracts visual/textual signals used
to judge whether a page looks like a phishing login/verification page:

- OCR text extraction (Tesseract) - what does the page actually say?
- Suspicious keyword matching - urgency/credential-harvesting language
- Login-form heuristics - password/OTP-related text + input-like shapes
- Button/CTA detection - "Verify", "Login", "Update", "Confirm" etc.

This does NOT do brand-logo matching (see brand_similarity.py) - this
module is about generic phishing "shape", regardless of which brand is
being impersonated.
"""
import io

import cv2
import numpy as np
import pytesseract
from PIL import Image

URGENCY_KEYWORDS = [
    "verify your account", "account suspended", "unusual activity",
    "immediate action", "within 24 hours", "your account will be",
    "confirm your identity", "security alert", "act now", "urgent",
]

CREDENTIAL_KEYWORDS = [
    "password", "otp", "one time password", "cvv", "pin", "card number",
    "username", "login id", "aadhaar", "upi pin",
]

ACTION_BUTTON_KEYWORDS = [
    "verify", "login", "log in", "sign in", "update", "confirm",
    "submit", "continue", "proceed", "validate",
]


def _extract_text(image: np.ndarray) -> str:
    """Run Tesseract OCR on the image and return lowercased extracted text."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    text = pytesseract.image_to_string(thresh)
    return text.lower()


def _find_keyword_hits(text: str, keywords: list[str]) -> list[str]:
    """Return which keywords from the list actually appear in the OCR text."""
    return [kw for kw in keywords if kw in text]


def _detect_input_like_boxes(image: np.ndarray) -> int:
    """
    Rough heuristic count of rectangular, input-field-like shapes.

    Real DOM inspection isn't available from a static screenshot, so this
    approximates it via edge detection looking for thin, wide rectangles
    (typical input-box proportions). This is a heuristic signal, not a
    precise count - combined with OCR keyword hits for scoring.
    """
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 50, 150)
    contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)

    box_count = 0
    img_h, img_w = gray.shape[:2]

    for cnt in contours:
        x, y, w, h = cv2.boundingRect(cnt)
        if w == 0 or h == 0:
            continue
        aspect_ratio = w / h
        is_input_shaped = 3.0 <= aspect_ratio <= 12.0
        is_reasonable_size = (0.15 * img_w <= w <= 0.9 * img_w) and (15 <= h <= 60)
        if is_input_shaped and is_reasonable_size:
            box_count += 1

    return box_count


def extract_image_features(screenshot_bytes: bytes) -> dict:
    """
    Main entry point: takes raw screenshot bytes, returns a flat feature dict.
    """
    pil_image = Image.open(io.BytesIO(screenshot_bytes)).convert("RGB")
    image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)

    text = _extract_text(image)

    urgency_hits = _find_keyword_hits(text, URGENCY_KEYWORDS)
    credential_hits = _find_keyword_hits(text, CREDENTIAL_KEYWORDS)
    action_hits = _find_keyword_hits(text, ACTION_BUTTON_KEYWORDS)
    input_box_count = _detect_input_like_boxes(image)

    has_password_signal = any(
        kw in text for kw in ["password", "otp", "pin", "cvv"]
    )

    login_form_detected = input_box_count >= 1 and has_password_signal

    reasons = []
    if urgency_hits:
        reasons.append(f"Urgency language detected: {', '.join(urgency_hits[:3])}")
    if credential_hits:
        reasons.append(f"Credential-related fields mentioned: {', '.join(credential_hits[:3])}")
    if login_form_detected:
        reasons.append("Login/credential form structure detected")
    if action_hits:
        reasons.append(f"Action buttons present: {', '.join(set(action_hits[:3]))}")

    return {
        "ocr_text_length": len(text),
        "urgency_keyword_hits": urgency_hits,
        "credential_keyword_hits": credential_hits,
        "action_button_hits": action_hits,
        "input_box_count": input_box_count,
        "has_password_field_signal": has_password_signal,
        "login_form_detected": login_form_detected,
        "reasons": reasons,
    }

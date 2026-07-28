"""
DOM analyzer - Phase 4 (Visual Detection).

Analyzes the ACTUAL rendered HTML of a page (via BeautifulSoup) to detect
real login/credential-harvesting form structure - not a screenshot-based
guess.
"""
from bs4 import BeautifulSoup

URGENCY_KEYWORDS = [
    "verify your account", "account suspended", "unusual activity",
    "immediate action", "within 24 hours", "your account will be",
    "confirm your identity", "security alert", "act now", "urgent",
]

ACTION_BUTTON_KEYWORDS = [
    "verify", "login", "log in", "sign in", "update", "confirm",
    "submit", "continue", "proceed", "validate",
]


def analyze_dom(html_content: str) -> dict:
    soup = BeautifulSoup(html_content, "lxml")

    password_inputs = soup.find_all("input", {"type": "password"})
    text_inputs = soup.find_all("input", {"type": ["text", "email", "tel", None]})
    forms = soup.find_all("form")

    page_text = soup.get_text(separator=" ", strip=True).lower()

    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in page_text]

    button_texts = []
    for el in soup.find_all(["button", "input"]):
        if el.name == "input" and el.get("type") not in ("submit", "button"):
            continue
        text = el.get_text(strip=True) if el.name == "button" else el.get("value", "")
        if text:
            button_texts.append(text.lower())
    combined_button_text = " ".join(button_texts)
    action_hits = [kw for kw in ACTION_BUTTON_KEYWORDS if kw in combined_button_text]

    form_action_domains = []
    for form in forms:
        action = form.get("action", "")
        if action and action.startswith("http"):
            form_action_domains.append(action)

    has_password_field = len(password_inputs) > 0
    login_form_detected = has_password_field and len(forms) > 0

    reasons = []
    if login_form_detected:
        reasons.append(
            f"Real login form detected ({len(password_inputs)} password field(s) "
            f"in {len(forms)} form(s))"
        )
    if urgency_hits:
        reasons.append(f"Urgency language in page text: {chr(44).join(urgency_hits[:3])}")
    if action_hits:
        reasons.append(f"Action buttons present: {chr(44).join(set(action_hits[:3]))}")

    return {
        "password_field_count": len(password_inputs),
        "text_input_count": len(text_inputs),
        "form_count": len(forms),
        "has_password_field": has_password_field,
        "login_form_detected": login_form_detected,
        "action_button_hits": action_hits,
        "urgency_text_hits": urgency_hits,
        "form_action_domains": form_action_domains,
        "reasons": reasons,
    }

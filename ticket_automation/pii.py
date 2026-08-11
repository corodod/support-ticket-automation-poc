from __future__ import annotations

import re


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+7|8)[\s()-]*\d{3}[\s()-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\d)"
)
CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
SECRET_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|access[_ -]?token|secret|токен|пароль)\s*[:=]\s*"
    r"[A-Za-zА-Яа-яЁё0-9_./+-]{6,}\b"
)


def is_luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _card_matches(text: str) -> tuple[re.Match[str], ...]:
    return tuple(
        match for match in CARD_CANDIDATE_RE.finditer(text) if is_luhn_valid(match.group())
    )


def detect_pii(text: str) -> tuple[str, ...]:
    found: list[str] = []
    if EMAIL_RE.search(text):
        found.append("email")
    if PHONE_RE.search(text):
        found.append("phone")
    if _card_matches(text):
        found.append("card_number")
    if SECRET_RE.search(text):
        found.append("credential")
    return tuple(found)


def redact_pii(text: str) -> str:
    redacted = EMAIL_RE.sub("[EMAIL]", text)
    redacted = PHONE_RE.sub("[PHONE]", redacted)
    redacted = SECRET_RE.sub("[CREDENTIAL]", redacted)
    matches = _card_matches(redacted)
    for match in reversed(matches):
        redacted = redacted[: match.start()] + "[CARD_NUMBER]" + redacted[match.end() :]
    return redacted

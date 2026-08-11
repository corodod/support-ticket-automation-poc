from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?7|8)[\s()-]*\d{3}[\s()-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}(?!\d)")
LABELED_PHONE_RE = re.compile(
    r"(?ix)\b(?:телефон|тел\.?|phone)\s*[:=]?\s*(?<!\d)(?:\d[\s()-]*){10}(?!\d)"
)
CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[\s.\-/·–—−]{0,3}){12,18}\d(?!\d)")
PASSPORT_RE = re.compile(
    r"""(?ix)
    \b(?:
        (?:паспорт(?:\s+рф)?|passport)\s*[:№#=-]?\s*
        (?:серия\s*[:№#=-]?\s*)?\d{2}\s?\d{2}
        (?:\s*[,;]?\s*(?:номер|number|no\.?|№)\s*[:№#=-]?\s*|[\s-]*)\d{6}
        |
        серия\s*[:№#=-]?\s*\d{2}\s?\d{2}\s*[,;]?\s*
        (?:номер|№)\s*[:№#=-]?\s*\d{6}
    )(?!\d)
    """
)
SNILS_CANDIDATE_RE = re.compile(r"(?<!\d)\d{3}[- ]\d{3}[- ]\d{3}[ -]\d{2}(?!\d)")
SNILS_LABELED_RE = re.compile(r"(?i)\bснилс\s*[:№#=-]?\s*(?:\d{3}[- ]?){2}\d{3}[ -]?\d{2}(?!\d)")
SECRET_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|access[_ -]?token|token|secret|токен|пароль|password|pass)"
    r"\s*[:=]\s*(?:[\"'][^\"'\r\n]{4,128}[\"']|[^\s,;]{4,128})"
)
NATURAL_SECRET_RE = re.compile(
    r"(?ix)\b(?:"
    r"(?:мой|моя|my)\s+(?:пароль|password|pass)\s*"
    r"(?:(?:[-—:=№#])\s*|это\s+)?"
    r"(?:[\"'][^\"'\r\n]{4,128}[\"']|[A-Za-zА-Яа-яЁё0-9_!@#$%^&*+=-]{4,128})"
    r"|(?:пароль|password|pass)\s*(?:(?:[-—:=№#])\s*|это\s+)?"
    r"(?:\d{4,12}|(?=[A-Za-zА-Яа-яЁё0-9_!@#$%^&*+=-]{4,128}\b)"
    r"(?=[^\s,;]*\d)[A-Za-zА-Яа-яЁё0-9_!@#$%^&*+=-]{4,128})"
    r")"
)
ONE_TIME_CODE_RE = re.compile(
    r"(?ix)\b(?:otp|пин|pin|одноразов\w*\s+код|код\s+подтвержден\w*)"
    r"\s*(?:(?:[-—:=№#])\s*|это\s+)?(?<!\d)(?:\d[\s-]?){3,7}\d"
    r"(?![\s-]?\d)"
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


def is_snils_valid(value: str) -> bool:
    digits = "".join(char for char in value if char.isdigit())
    if len(digits) != 11 or len(set(digits[:9])) == 1:
        return False
    weighted_sum = sum(int(digit) * weight for digit, weight in zip(digits[:9], range(9, 0, -1)))
    if weighted_sum < 100:
        expected = weighted_sum
    elif weighted_sum in (100, 101):
        expected = 0
    else:
        expected = weighted_sum % 101
        if expected == 100:
            expected = 0
    return int(digits[-2:]) == expected


def _valid_card_matches(text: str) -> tuple[re.Match[str], ...]:
    return tuple(
        match for match in CARD_CANDIDATE_RE.finditer(text) if is_luhn_valid(match.group())
    )


def detect_pii(text: str) -> tuple[str, ...]:
    found: list[str] = []
    if EMAIL_RE.search(text):
        found.append("email")
    if PHONE_RE.search(text) or LABELED_PHONE_RE.search(text):
        found.append("phone")
    if PASSPORT_RE.search(text):
        found.append("russian_passport")
    if SNILS_LABELED_RE.search(text) or any(
        is_snils_valid(match.group()) for match in SNILS_CANDIDATE_RE.finditer(text)
    ):
        found.append("snils")
    if _valid_card_matches(text):
        found.append("card_number")
    elif CARD_CANDIDATE_RE.search(text):
        found.append("long_numeric_identifier")
    if SECRET_RE.search(text) or NATURAL_SECRET_RE.search(text):
        found.append("credential")
    if ONE_TIME_CODE_RE.search(text):
        found.append("one_time_code")
    return tuple(found)


def redact_pii(text: str) -> str:
    redacted = EMAIL_RE.sub("[EMAIL]", text)
    redacted = LABELED_PHONE_RE.sub("[PHONE]", redacted)
    redacted = PHONE_RE.sub("[PHONE]", redacted)
    redacted = PASSPORT_RE.sub("[RUSSIAN_PASSPORT]", redacted)
    redacted = SNILS_LABELED_RE.sub("[SNILS]", redacted)
    redacted = SNILS_CANDIDATE_RE.sub(
        lambda match: "[SNILS]" if is_snils_valid(match.group()) else match.group(),
        redacted,
    )
    redacted = SECRET_RE.sub("[CREDENTIAL]", redacted)
    redacted = NATURAL_SECRET_RE.sub("[CREDENTIAL]", redacted)
    redacted = ONE_TIME_CODE_RE.sub("[ONE_TIME_CODE]", redacted)
    matches = tuple(CARD_CANDIDATE_RE.finditer(redacted))
    for match in reversed(matches):
        marker = "[CARD_NUMBER]" if is_luhn_valid(match.group()) else "[LONG_NUMBER]"
        redacted = redacted[: match.start()] + marker + redacted[match.end() :]
    return redacted

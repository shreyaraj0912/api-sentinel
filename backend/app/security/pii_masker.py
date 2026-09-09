import json
import re
from typing import Any


EMAIL_PATTERN = re.compile(
    r"^([^@\s])([^@\s]*)(@.+)$"
)


def mask_email(email: str) -> str:
    """
    Mask an email address while retaining the domain.

    Example:
        user@example.com
        -> u***@example.com
    """

    if not email or "@" not in email:
        return email

    match = EMAIL_PATTERN.match(email)

    if not match:
        return email

    first_char = match.group(1)
    domain = match.group(3)

    return f"{first_char}***{domain}"


def mask_pii(value: str | None) -> str | None:
    """
    Mask supported PII values.

    Currently supports email addresses.
    """

    if value is None:
        return None

    if "@" in value:
        return mask_email(value)

    return value


def mask_json_value(value: Any) -> Any:
    """
    Recursively mask supported PII values inside JSON-compatible data.

    Strings are checked for supported PII.
    Dictionaries and lists are processed recursively.
    Other primitive values are returned unchanged.
    """

    if isinstance(value, str):
        return mask_pii(value)

    if isinstance(value, dict):
        return {
            key: mask_json_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            mask_json_value(item)
            for item in value
        ]

    return value


def mask_json_string(value: str | None) -> str | None:
    """
    Mask supported PII inside a JSON string.

    Example:

        {"user_id": "user@example.com"}

    becomes:

        {"user_id": "u***@example.com"}

    If the value is not valid JSON, the original text is
    passed through the normal PII masker.
    """

    if value is None:
        return None

    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return mask_pii(value)

    masked = mask_json_value(parsed)

    return json.dumps(masked)
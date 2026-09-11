import json
import re
from typing import Any


EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[A-Za-z0-9-]+"
    r"(?:\.[A-Za-z0-9-]+)+"
)


def mask_email(email: str) -> str:
    """
    Mask a complete email address while retaining the domain.

    Example:
        user@example.com
        -> u***@example.com
    """

    if not email or "@" not in email:
        return email

    local_part, domain = email.split("@", 1)

    if not local_part or not domain:
        return email

    return f"{local_part[0]}***@{domain}"


def mask_pii(value: str | None) -> str | None:
    """
    Mask supported PII found anywhere inside a string.

    Currently supports email addresses.

    Example:
        User user@example.com attempted an operation.
        ->
        User u***@example.com attempted an operation.
    """

    if value is None:
        return None

    return EMAIL_PATTERN.sub(
        lambda match: mask_email(match.group(0)),
        value,
    )


def mask_json_value(value: Any) -> Any:
    """
    Recursively mask supported PII inside JSON-compatible data.
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

    Invalid JSON falls back to normal string masking.
    """

    if value is None:
        return None

    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return mask_pii(value)

    masked = mask_json_value(parsed)

    return json.dumps(masked)
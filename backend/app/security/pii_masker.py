import re


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
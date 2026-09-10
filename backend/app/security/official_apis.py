"""
Official/documented API catalog for API-Sentinel.

This module contains the API endpoints that are considered
known/documented by the prototype.

Shadow API detection compares observed API activity against
this catalog after endpoint normalization.
"""


OFFICIAL_APIS: set[tuple[str, str]] = {
    ("GET", "/api/profile"),
    ("GET", "/api/users"),
    ("GET", "/api/users/{id}"),
    ("POST", "/api/login"),
    ("DELETE", "/api/users/{id}"),
}


def get_official_apis() -> set[tuple[str, str]]:
    """
    Return a copy of the official API catalog.

    A copy is returned so callers do not accidentally modify
    the shared catalog.
    """

    return set(OFFICIAL_APIS)


def is_official_api(
    method: str,
    normalized_path: str,
) -> bool:
    """
    Check whether a normalized method/path pair belongs
    to the official API catalog.
    """

    return (
        method.upper(),
        normalized_path,
    ) in OFFICIAL_APIS
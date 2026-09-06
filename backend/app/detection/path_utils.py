import re


def normalize_path(path: str | None) -> str | None:
    """
    Normalize numeric URL path parameters.

    Examples:

    /api/users/101
        -> /api/users/{id}

    /api/users/101/orders/55
        -> /api/users/{id}/orders/{id}

    None
        -> None
    """

    if path is None:
        return None

    path = path.strip()

    if not path:
        return path

    return re.sub(
        r"/\d+(?=/|$)",
        "/{id}",
        path,
    )
from backend.app.security.official_apis import is_official_api
from backend.app.detection.path_utils import normalize_path


def test_known_parameterized_endpoint_is_official():
    normalized_path = normalize_path(
        "/api/users/101"
    )

    assert normalized_path == "/api/users/{id}"

    assert is_official_api(
        "GET",
        normalized_path,
    ) is True


def test_unknown_endpoint_is_not_official():
    normalized_path = normalize_path(
        "/api/internal/debug"
    )

    assert is_official_api(
        "GET",
        normalized_path,
    ) is False


def test_method_is_part_of_official_api_match():
    normalized_path = normalize_path(
        "/api/users/101"
    )

    assert is_official_api(
        "GET",
        normalized_path,
    ) is True

    assert is_official_api(
        "POST",
        normalized_path,
    ) is False
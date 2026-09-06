from backend.app.detection.path_utils import normalize_path


def test_normalize_single_numeric_id():
    assert normalize_path(
        "/api/users/101"
    ) == "/api/users/{id}"


def test_normalize_multiple_numeric_ids():
    assert normalize_path(
        "/api/users/101/orders/55"
    ) == "/api/users/{id}/orders/{id}"


def test_normalize_non_numeric_path():
    assert normalize_path(
        "/api/profile"
    ) == "/api/profile"


def test_normalize_none():
    assert normalize_path(None) is None


def test_normalize_parameterized_endpoint_consistently():
    assert normalize_path(
        "/api/users/101"
    ) == normalize_path(
        "/api/users/103"
    )
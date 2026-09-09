from backend.app.security.pii_masker import mask_email, mask_pii


def test_mask_email():
    assert (
        mask_email("user@example.com")
        == "u***@example.com"
    )


def test_mask_pii_email():
    assert (
        mask_pii("admin@example.com")
        == "a***@example.com"
    )


def test_mask_pii_none():
    assert mask_pii(None) is None


def test_mask_pii_non_email():
    assert mask_pii("127.0.0.1") == "127.0.0.1"
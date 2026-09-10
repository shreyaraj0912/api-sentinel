from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_official_api_is_marked_documented():
    payload = {
        "event_id": "inventory-official-integration-001",
        "timestamp": 12604154870000,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 57001,
        "dst_port": 9000,
        "protocol": "TCP",
        "packet_len": 512,
        "method": "GET",
        "path": "/api/users/101",
        "user_id": None,
        "role": None,
        "object_id": None,
    }

    response = client.post(
        "/events",
        json=payload,
    )

    assert response.status_code == 201

    inventory_response = client.get("/inventory")

    assert inventory_response.status_code == 200

    inventory = inventory_response.json()

    matching_entries = [
        item
        for item in inventory
        if (
            item["method"] == "GET"
            and item["path"] == "/api/users/{id}"
        )
    ]

    assert matching_entries

    assert matching_entries[0]["documented"] is True


def test_unknown_api_is_marked_undocumented():
    payload = {
        "event_id": "inventory-shadow-integration-001",
        "timestamp": 12604154870001,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 57002,
        "dst_port": 9000,
        "protocol": "TCP",
        "packet_len": 512,
        "method": "GET",
        "path": "/api/internal/debug",
        "user_id": None,
        "role": None,
        "object_id": None,
    }

    response = client.post(
        "/events",
        json=payload,
    )

    assert response.status_code == 201

    inventory_response = client.get("/inventory")

    assert inventory_response.status_code == 200

    inventory = inventory_response.json()

    matching_entries = [
        item
        for item in inventory
        if (
            item["method"] == "GET"
            and item["path"] == "/api/internal/debug"
        )
    ]

    assert matching_entries

    assert matching_entries[0]["documented"] is False
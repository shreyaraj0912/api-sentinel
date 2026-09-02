from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_member1_network_telemetry_contract():
    payload = {
        "event_id": "evt-member1-test-001",
        "timestamp": 12604154835332,
        "src_ip": "10.0.2.15",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_len": 512,
        "method": None,
        "path": None,
        "user_id": None,
        "role": None,
        "object_id": None,
    }

    response = client.post(
        "/events",
        json=payload,
    )

    assert response.status_code == 201

    data = response.json()

    assert data["event_id"] == "evt-member1-test-001"
    assert data["timestamp"] == 12604154835332
    assert data["src_ip"] == "10.0.2.15"
    assert data["dst_ip"] == "8.8.8.8"
    assert data["src_port"] == 54321
    assert data["dst_port"] == 443
    assert data["protocol"] == "TCP"
    assert data["packet_len"] == 512

    assert data["method"] is None
    assert data["path"] is None
    assert data["user_id"] is None
    assert data["role"] is None
    assert data["object_id"] is None
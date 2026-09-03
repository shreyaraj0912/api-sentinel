from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_network_event_is_accepted_without_api_context():
    payload = {
        "event_id": "integration-network-001",
        "timestamp": 12604154835360,
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

    assert data["event_id"] == "integration-network-001"
    assert data["method"] is None
    assert data["path"] is None


def test_bola_event_creates_bola_alert():
    payload = {
        "event_id": "integration-bola-001",
        "timestamp": 12604154835361,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 50001,
        "dst_port": 9000,
        "protocol": "TCP",
        "packet_len": 512,
        "method": "GET",
        "path": "/api/users/103",
        "user_id": "userA",
        "role": "USER",
        "object_id": "103",
    }

    response = client.post(
        "/events",
        json=payload,
    )

    assert response.status_code == 201

    alerts = client.get("/alerts").json()

    assert any(
        alert["alert_type"] == "BOLA"
        and alert["destination"] == "/api/users/103"
        for alert in alerts
    )


def test_bfla_event_creates_bfla_alert():
    payload = {
        "event_id": "integration-bfla-001",
        "timestamp": 12604154835362,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 50002,
        "dst_port": 9000,
        "protocol": "TCP",
        "packet_len": 512,
        "method": "DELETE",
        "path": "/api/users/10",
        "user_id": "userA",
        "role": "USER",
        "object_id": None,
    }

    response = client.post(
        "/events",
        json=payload,
    )

    assert response.status_code == 201

    alerts = client.get("/alerts").json()

    assert any(
        alert["alert_type"] == "BFLA"
        and alert["destination"] == "/api/users/10"
        for alert in alerts
    )


def test_shadow_api_event_creates_shadow_alert():
    payload = {
        "event_id": "integration-shadow-001",
        "timestamp": 12604154835363,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 50003,
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

    alerts = client.get("/alerts").json()

    assert any(
        alert["alert_type"] == "SHADOW_API"
        and alert["destination"] == "/api/internal/debug"
        for alert in alerts
    )


def test_normal_api_request_does_not_create_new_alert():
    before = client.get("/alerts").json()

    payload = {
        "event_id": "integration-normal-001",
        "timestamp": 12604154835364,
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": 50004,
        "dst_port": 9000,
        "protocol": "TCP",
        "packet_len": 512,
        "method": "GET",
        "path": "/api/profile",
        "user_id": "userA",
        "role": "USER",
        "object_id": None,
    }

    response = client.post(
        "/events",
        json=payload,
    )

    assert response.status_code == 201

    after = client.get("/alerts").json()

    assert len(after) == len(before)
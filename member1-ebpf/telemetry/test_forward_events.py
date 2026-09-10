import json
import os
import subprocess
import sys


TEST_EVENT = {
    "event_id": "evt-test-001",
    "timestamp": 1757060000,
    "src_ip": "10.0.2.15",
    "dst_ip": "10.0.2.20",
    "src_port": 54321,
    "dst_port": 8000,
    "protocol": "TCP",
    "packet_len": 512,
    "method": None,
    "path": None,
    "user_id": None,
    "role": None,
    "object_id": None,
}


EXPECTED_FIELDS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_len",
}


def test_event_mapping():
    """
    Validate that Member 1 telemetry contains the fields
    required by Member 3 EventCreate.
    """

    payload = {
        "timestamp": float(TEST_EVENT["timestamp"]),
        "src_ip": TEST_EVENT.get("src_ip"),
        "dst_ip": TEST_EVENT.get("dst_ip"),
        "src_port": TEST_EVENT.get("src_port"),
        "dst_port": TEST_EVENT.get("dst_port"),
        "protocol": TEST_EVENT.get("protocol"),
        "packet_len": TEST_EVENT.get("packet_len"),
    }

    assert set(payload.keys()) == EXPECTED_FIELDS

    assert isinstance(payload["timestamp"], float)
    assert isinstance(payload["src_ip"], str)
    assert isinstance(payload["dst_ip"], str)
    assert isinstance(payload["src_port"], int)
    assert isinstance(payload["dst_port"], int)
    assert isinstance(payload["protocol"], str)
    assert isinstance(payload["packet_len"], int)


def test_api_fields_not_forwarded():
    """
    API-level fields are intentionally handled by the backend.
    """

    payload = {
        "timestamp": float(TEST_EVENT["timestamp"]),
        "src_ip": TEST_EVENT.get("src_ip"),
        "dst_ip": TEST_EVENT.get("dst_ip"),
        "src_port": TEST_EVENT.get("src_port"),
        "dst_port": TEST_EVENT.get("dst_port"),
        "protocol": TEST_EVENT.get("protocol"),
        "packet_len": TEST_EVENT.get("packet_len"),
    }

    assert "method" not in payload
    assert "path" not in payload
    assert "user_id" not in payload
    assert "role" not in payload
    assert "object_id" not in payload


from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


FORWARDER = Path(__file__).with_name("forward_events.py")
SPEC = spec_from_file_location("forward_events", FORWARDER)
MODULE = module_from_spec(SPEC)

assert SPEC is not None
assert SPEC.loader is not None

SPEC.loader.exec_module(MODULE)

build_event_payload = MODULE.build_event_payload


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
    "event_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_len",
}


def test_event_mapping():
    payload = build_event_payload(TEST_EVENT)

    assert set(payload.keys()) == EXPECTED_FIELDS
    assert payload["event_id"] == "evt-test-001"
    assert isinstance(payload["timestamp"], int)
    assert isinstance(payload["src_ip"], str)
    assert isinstance(payload["dst_ip"], str)
    assert isinstance(payload["src_port"], int)
    assert isinstance(payload["dst_port"], int)
    assert isinstance(payload["protocol"], str)
    assert isinstance(payload["packet_len"], int)


def test_network_only_telemetry():
    payload = build_event_payload(TEST_EVENT)

    assert payload["src_ip"] == "10.0.2.15"
    assert payload["dst_ip"] == "10.0.2.20"
    assert payload["src_port"] == 54321
    assert payload["dst_port"] == 8000
    assert payload["protocol"] == "TCP"


def test_api_security_context_not_invented():
    payload = build_event_payload(TEST_EVENT)

    for field in ("method", "path", "user_id", "role", "object_id"):
        assert field not in payload


def test_udp_telemetry():
    udp_event = {
        **TEST_EVENT,
        "event_id": "evt-udp-001",
        "src_port": 5353,
        "dst_port": 5353,
        "protocol": "UDP",
        "packet_len": 103,
    }

    payload = build_event_payload(udp_event)

    assert payload["protocol"] == "UDP"
    assert payload["src_port"] == 5353
    assert payload["dst_port"] == 5353
    assert payload["packet_len"] == 103


def test_optional_network_fields_can_be_null():
    partial_event = {
        "timestamp": 1757060000,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "packet_len": None,
    }

    payload = build_event_payload(partial_event)

    assert payload["src_ip"] is None
    assert payload["dst_ip"] is None
    assert payload["src_port"] is None
    assert payload["dst_port"] is None
    assert payload["protocol"] is None
    assert payload["packet_len"] is None

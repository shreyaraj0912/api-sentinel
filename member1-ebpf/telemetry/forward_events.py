#!/usr/bin/env python3

import json
import os
import sys

import requests


API_URL = os.environ.get(
    "API_EVENTS_URL",
    "http://127.0.0.1:8000/events",
)


def build_event_payload(event: dict) -> dict:
    """
    Map Member 1 eBPF telemetry to Member 3 EventCreate schema.
    """

    return {
        "timestamp": float(event["timestamp"]),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "packet_len": event.get("packet_len"),
    }


print(
    f"[forwarder] API endpoint: {API_URL}",
    file=sys.stderr,
)


for line in sys.stdin:
    line = line.strip()

    if not line:
        continue

    # The Rust collector prints banner/log lines as well as JSON.
    # Ignore anything that is not JSON.
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue

    # Only process telemetry objects.
    if "timestamp" not in event:
        continue

    try:
        payload = build_event_payload(event)

        response = requests.post(
            API_URL,
            json=payload,
            timeout=5,
        )

        event_id = event.get("event_id", "unknown")

        print(
            f"[forwarder] {event_id} -> "
            f"HTTP {response.status_code}",
            file=sys.stderr,
        )

        if response.status_code >= 400:
            print(
                f"[forwarder] API response: {response.text}",
                file=sys.stderr,
            )

    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"[forwarder] Invalid telemetry: {exc}",
            file=sys.stderr,
        )

    except requests.RequestException as exc:
        print(
            f"[forwarder] Request failed: {exc}",
            file=sys.stderr,
        )

#!/usr/bin/env python3

import json
import os
import sys
import time

import requests


API_URL = os.environ.get(
    "API_EVENTS_URL",
    "http://127.0.0.1:8000/events",
)


def bpf_timestamp_to_unix_seconds(timestamp_ns: int) -> float:
    """
    Convert bpf_ktime_get_ns() / CLOCK_MONOTONIC nanoseconds
    into Unix epoch seconds.

    bpf_ktime_get_ns() is monotonic time since boot, while the
    backend expects Unix epoch seconds.

    The offset is calculated from:
        current Unix time - current monotonic time
    """

    unix_now_ns = time.time_ns()
    monotonic_now_ns = time.monotonic_ns()

    boot_to_epoch_offset_ns = unix_now_ns - monotonic_now_ns

    unix_timestamp_ns = timestamp_ns + boot_to_epoch_offset_ns

    return unix_timestamp_ns / 1_000_000_000.0


def build_event_payload(event: dict) -> dict:
    """
    Map Member 1 eBPF telemetry to Member 3 EventCreate schema.
    """

    raw_timestamp_ns = int(event["timestamp"])

    unix_timestamp = bpf_timestamp_to_unix_seconds(
        raw_timestamp_ns
    )

    return {
        "timestamp": unix_timestamp,
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "packet_len": event.get("packet_len"),
    }


def main() -> None:
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


if __name__ == "__main__":
    main()

import time
import uuid

import requests


MOCK_API_URL = "http://127.0.0.1:9000"
BACKEND_URL = "http://127.0.0.1:8000"


def main():
    print("================================")
    print("      SHADOW API SIMULATION")
    print("================================")

    path = "/api/internal/debug"

    try:
        # Check Mock API
        requests.get(
            f"{MOCK_API_URL}/",
            timeout=5,
        )

        print(
            f"Requesting undocumented endpoint: {path}"
        )
        print()

        # Request from Mock API
        mock_response = requests.get(
            f"{MOCK_API_URL}{path}",
            timeout=5,
        )

        print(
            f"GET {path}"
            f" -> {mock_response.status_code}"
        )

        # Send corresponding event to backend
        event = {
            "event_id": f"sim-shadow-{uuid.uuid4()}",
            "timestamp": time.time_ns(),

            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",

            "src_port": 50003,
            "dst_port": 9000,

            "protocol": "TCP",
            "packet_len": 512,

            "method": "GET",
            "path": path,

            "user_id": None,
            "role": None,
            "object_id": None,
        }

        backend_response = requests.post(
            f"{BACKEND_URL}/events",
            json=event,
            timeout=5,
        )

        print(
            f"POST /events -> "
            f"{backend_response.status_code}"
        )

        if backend_response.status_code == 201:
            print(
                "Shadow API event accepted by backend."
            )
        else:
            print(
                "Backend rejected the Shadow API event."
            )
            print(backend_response.text)

    except requests.exceptions.ConnectionError:
        print()
        print("ERROR: Could not connect to a required service.")
        print("Mock API: http://127.0.0.1:9000")
        print("Backend:  http://127.0.0.1:8000")

    except requests.exceptions.Timeout:
        print("ERROR: Request timed out.")

    except requests.exceptions.RequestException as exc:
        print(f"ERROR: HTTP request failed: {exc}")


if __name__ == "__main__":
    main()
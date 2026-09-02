import time
import uuid

import requests


MOCK_API_URL = "http://127.0.0.1:9000"
BACKEND_URL = "http://127.0.0.1:8000"


def main():
    print("================================")
    print("        BFLA SIMULATION")
    print("================================")

    path = "/api/users/10"

    try:
        # Check Mock API
        requests.get(
            f"{MOCK_API_URL}/",
            timeout=5,
        )

        print("Role: USER")
        print(f"Attempt: DELETE {path}")
        print()

        # Send unauthorized operation to Mock API
        mock_response = requests.delete(
            f"{MOCK_API_URL}{path}",
            timeout=5,
        )

        print(
            f"DELETE {path}"
            f" -> {mock_response.status_code}"
        )

        # Build security event for Member 2 backend
        event = {
            "event_id": f"sim-bfla-{uuid.uuid4()}",
            "timestamp": time.time_ns(),

            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",

            "src_port": 50002,
            "dst_port": 9000,

            "protocol": "TCP",
            "packet_len": 512,

            "method": "DELETE",
            "path": path,

            "user_id": "userA",
            "role": "USER",

            # Deliberately null so this test focuses on BFLA.
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
            print("BFLA event accepted by backend.")
        else:
            print("Backend rejected the BFLA event.")
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
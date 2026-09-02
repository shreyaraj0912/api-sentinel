import time
import uuid

import requests


MOCK_API_URL = "http://127.0.0.1:9000"
BACKEND_URL = "http://127.0.0.1:8000"


def main():
    print("================================")
    print("        BOLA SIMULATION")
    print("================================")

    try:
        # -----------------------------------------------------
        # Check Mock API
        # -----------------------------------------------------

        requests.get(
            f"{MOCK_API_URL}/",
            timeout=5,
        )

        # -----------------------------------------------------
        # User A owns these objects in our prototype.
        # -----------------------------------------------------

        owned_objects = ["101", "102"]

        print(
            f"User A owns objects: "
            f"{', '.join(owned_objects)}"
        )
        print()

        # -----------------------------------------------------
        # Normal requests
        # -----------------------------------------------------

        for object_id in owned_objects:
            response = requests.get(
                f"{MOCK_API_URL}/api/users/{object_id}",
                timeout=5,
            )

            print(
                f"GET /api/users/{object_id}"
                f" -> {response.status_code}"
            )

        # -----------------------------------------------------
        # Suspicious object access
        # -----------------------------------------------------

        suspicious_object = "103"

        response = requests.get(
            f"{MOCK_API_URL}/api/users/{suspicious_object}",
            timeout=5,
        )

        print(
            f"GET /api/users/{suspicious_object}"
            f" -> {response.status_code}"
        )

        # -----------------------------------------------------
        # Send corresponding security event
        # to Member 2 backend
        # -----------------------------------------------------

        event = {
            "event_id": f"sim-bola-{uuid.uuid4()}",
            "timestamp": time.time_ns(),

            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",

            "src_port": 50001,
            "dst_port": 9000,

            "protocol": "TCP",
            "packet_len": 512,

            "method": "GET",
            "path": f"/api/users/{suspicious_object}",

            "user_id": "userA",
            "role": "USER",
            "object_id": suspicious_object,
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
            print("BOLA event accepted by backend.")
        else:
            print("Backend rejected the BOLA event.")
            print(backend_response.text)

    except requests.exceptions.ConnectionError:
        print()
        print("ERROR: Could not connect to a required service.")
        print()
        print("Make sure these are running:")
        print("Mock API  -> http://127.0.0.1:9000")
        print("Backend   -> http://127.0.0.1:8000")

    except requests.exceptions.Timeout:
        print("ERROR: Request timed out.")

    except requests.exceptions.RequestException as exc:
        print(f"ERROR: HTTP request failed: {exc}")


if __name__ == "__main__":
    main()
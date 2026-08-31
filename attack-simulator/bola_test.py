import requests


BASE_URL = "http://127.0.0.1:9000"


def main():
    print("=== BOLA Simulation ===")

    print("User A owns objects: 101, 102")

    for object_id in [101, 102]:
        response = requests.get(
            f"{BASE_URL}/api/users/{object_id}"
        )

        print(
            f"GET /api/users/{object_id} "
            f"-> {response.status_code}"
        )

    suspicious_object = 103

    response = requests.get(
        f"{BASE_URL}/api/users/{suspicious_object}"
    )

    print(
        f"GET /api/users/{suspicious_object} "
        f"-> {response.status_code}"
    )


if __name__ == "__main__":
    main()
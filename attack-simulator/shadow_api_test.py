import requests


BASE_URL = "http://127.0.0.1:9000"


def main():
    print("=== Shadow API Simulation ===")

    response = requests.get(
        f"{BASE_URL}/api/internal/debug"
    )

    print(
        f"GET /api/internal/debug "
        f"-> {response.status_code}"
    )


if __name__ == "__main__":
    main()
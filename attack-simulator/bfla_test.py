import requests


BASE_URL = "http://127.0.0.1:9000"


def main():
    print("=== BFLA Simulation ===")

    response = requests.delete(
        f"{BASE_URL}/api/users/10"
    )

    print(
        f"USER DELETE /api/users/10 "
        f"-> {response.status_code}"
    )


if __name__ == "__main__":
    main()
    
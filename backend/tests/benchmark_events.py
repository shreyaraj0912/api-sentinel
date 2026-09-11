import statistics
import time

from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def benchmark_event_ingestion(
    iterations: int = 50,
) -> list[float]:
    """
    Measure POST /events response time in milliseconds.
    """

    timings = []

    for index in range(iterations):
        payload = {
            "event_id": f"benchmark-{index}",
            "timestamp": time.time_ns(),
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 58000 + index,
            "dst_port": 9000,
            "protocol": "TCP",
            "packet_len": 512,
            "method": None,
            "path": None,
            "user_id": None,
            "role": None,
            "object_id": None,
        }

        start = time.perf_counter()

        response = client.post(
            "/events",
            json=payload,
        )

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        assert response.status_code == 201

        timings.append(elapsed_ms)

    return timings


def main():
    timings = benchmark_event_ingestion()

    print("=== API-Sentinel Backend Event Benchmark ===")
    print(f"Iterations: {len(timings)}")
    print(
        f"Min:    {min(timings):.3f} ms"
    )
    print(
        f"Max:    {max(timings):.3f} ms"
    )
    print(
        f"Mean:   {statistics.mean(timings):.3f} ms"
    )
    print(
        f"Median: {statistics.median(timings):.3f} ms"
    )


if __name__ == "__main__":
    main()
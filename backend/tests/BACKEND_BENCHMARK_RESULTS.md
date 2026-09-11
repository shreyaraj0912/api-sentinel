# API-Sentinel Backend Benchmark Results

## Purpose

This benchmark measures the response time of the Member 2 backend event-ingestion path.

The benchmark exercises:

```text
POST /events
    ↓
Pydantic validation
    ↓
Event persistence
    ↓
Detection pipeline
    ↓
HTTP response
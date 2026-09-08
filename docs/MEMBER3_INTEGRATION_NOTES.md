# Member 3 Integration Notes

## Current Architecture

eBPF/XDP → Telemetry JSON → FastAPI `/events` → Detection → Dashboard

## Backend Event Contract

The FastAPI `POST /events` endpoint accepts:

- `timestamp`: float
- `src_ip`: string or null
- `dst_ip`: string or null
- `src_port`: integer or null
- `dst_port`: integer or null
- `protocol`: string or null
- `packet_len`: integer or null

## Example Telemetry Payload

```json
{
  "timestamp": 1757060000,
  "src_ip": "10.0.2.15",
  "dst_ip": "10.0.2.20",
  "src_port": 54321,
  "dst_port": 8000,
  "protocol": "TCP",
  "packet_len": 512
}
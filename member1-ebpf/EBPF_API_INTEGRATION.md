# eBPF → FastAPI Event Integration

## Purpose

Connect the Member 1 eBPF/XDP telemetry collector to the Member 3 FastAPI `/events` endpoint over Tailscale.

## Architecture

XDP/eBPF
→ RingBuf
→ Rust telemetry collector
→ JSON
→ Python telemetry forwarder
→ Tailscale
→ POST `/events`
→ FastAPI
→ Event Storage
→ Detection
→ Alerts
→ React Dashboard

## Network Configuration

Member 1 — Kali:
- Tailscale IP: `100.89.211.126`

Member 2/3 — Windows:
- Tailscale IP: `100.103.17.105`
- FastAPI port: `8001`

FastAPI events endpoint:

`http://100.103.17.105:8001/events`

## Member 1 Telemetry

The eBPF collector produces:

- `event_id`
- `timestamp`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `packet_len`

The collector also exposes the following API-level fields as `null` placeholders:

- `method`
- `path`
- `user_id`
- `role`
- `object_id`

These fields are not available directly at the XDP network layer.

## EventCreate Mapping

The telemetry forwarder sends the following fields to the FastAPI `/events` endpoint:

- `event_id` → `event_id`
- eBPF timestamp → Unix timestamp integer
- `src_ip` → `src_ip`
- `dst_ip` → `dst_ip`
- `src_port` → `src_port`
- `dst_port` → `dst_port`
- `protocol` → `protocol`
- `packet_len` → `packet_len`

The timestamp is converted from the eBPF monotonic clock representation into Unix epoch seconds and normalized to an integer because the FastAPI event schema requires an integer timestamp.

## API-Level Enrichment

The backend is responsible for future enrichment and normalization of:

- `method`
- `path`
- `normalized_path`
- `user_id`
- `role`
- `object_id`
- `status_code`
- `service`

XDP remains focused on network-level telemetry.

## Validation

### Unit Tests

The telemetry forwarder test suite passes:

`5 passed`

### FastAPI Connectivity

The Member 1 Kali machine successfully reaches the Member 2/3 FastAPI service through Tailscale.

Validated endpoints:

- `/`
- `/docs`
- `/events`

### Manual Event Validation

A manually generated event was accepted by FastAPI with:

`HTTP 201 Created`

### Live eBPF Validation

The Rust eBPF/XDP collector successfully attaches to:

`wlan0`

The collector generates JSON telemetry events.

The Python forwarder successfully sends live eBPF events to:

`http://100.103.17.105:8001/events`

Live events returned:

`HTTP 201`

for consecutive events including:

`evt-000001` through `evt-000065`

### Backend Persistence Validation

The event:

`evt-000065`

was retrieved from the FastAPI `/events` endpoint after the live test.

The backend stored it with database ID:

`541`

Example validated event:

```json
{
  "event_id": "evt-000065",
  "timestamp": 1789652879,
  "src_ip": "49.37.157.27",
  "dst_ip": "10.204.102.146",
  "src_port": 41641,
  "dst_port": 41641,
  "protocol": "UDP",
  "packet_len": 138
}

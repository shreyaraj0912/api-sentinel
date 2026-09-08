# eBPF → FastAPI Event Integration

## Purpose

Connect the Member 1 eBPF/XDP telemetry collector to the Member 3 FastAPI `/events` endpoint.

## Architecture

XDP/eBPF
→ RingBuf
→ Rust telemetry collector
→ JSON
→ Telemetry forwarder
→ POST `/events`
→ FastAPI
→ Detection
→ Dashboard

## Member 1 Telemetry

The eBPF collector produces:

- event_id
- timestamp
- src_ip
- dst_ip
- src_port
- dst_port
- protocol
- packet_len

API-level fields such as:

- method
- path
- user_id
- role
- object_id

are currently unavailable at the XDP layer.

## EventCreate Mapping

The telemetry forwarder maps the Member 1 JSON to the Member 3 `EventCreate` schema:

- timestamp → timestamp
- src_ip → src_ip
- dst_ip → dst_ip
- src_port → src_port
- dst_port → dst_port
- protocol → protocol
- packet_len → packet_len

`event_id` is retained in Member 1 telemetry but is not sent to `/events` because it is not part of the confirmed `EventCreate` schema.

## API-Level Enrichment

The backend is responsible for future enrichment and normalization of:

- method
- path
- normalized_path
- user_id
- role
- object_id
- status_code
- service

XDP remains focused on network-level telemetry.

## Validation

The forwarder was syntax-checked using:

`python -m py_compile`

Live Member 3 API validation is pending because the FastAPI server is not currently reachable from the Member 1 machine.

## Result

The integration layer is ready to forward eBPF JSON telemetry to the confirmed `/events` schema once the Member 3 FastAPI endpoint is reachable.

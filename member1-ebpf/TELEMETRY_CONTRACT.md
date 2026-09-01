# API-Sentinel Telemetry Contract

## Producer

Member 1 eBPF/XDP Telemetry Collector

## Current Event Format

```json
{
  "event_id": "evt-000001",
  "timestamp": 12604154835332,
  "src_ip": "10.0.2.15",
  "dst_ip": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "packet_len": 512,
  "method": null,
  "path": null,
  "user_id": null,
  "role": null,
  "object_id": null
}

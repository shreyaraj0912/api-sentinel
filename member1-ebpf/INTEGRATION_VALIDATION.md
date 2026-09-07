# API-Sentinel eBPF Telemetry Integration Validation

## Purpose

This document records validation of the Member 1 eBPF/XDP telemetry
collector and defines the integration boundary with the backend.

## Telemetry Scope

The Member 1 collector provides network-level telemetry:

- IPv4 traffic
- TCP traffic
- UDP traffic
- Source IP
- Destination IP
- Source port
- Destination port
- Kernel packet timestamp
- Packet length
- Protocol
- Unique telemetry event ID

The XDP collector does not perform HTTP/API parsing.

## Integration Boundary

```text
XDP/eBPF
   |
   v
FlowEvent
   |
   v
RingBuf
   |
   v
Rust Collector
   |
   v
JSON Telemetry
   |
   v
FastAPI /events
   |
   v
API Normalization / Enrichment
   |
   v
Detection Layer
   |
   v
Dashboard

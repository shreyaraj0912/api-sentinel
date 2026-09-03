# API-Sentinel — Member 2 Backend & Detection

## Overview

Member 2 is responsible for the backend telemetry ingestion, API inventory, API security detection, alert generation, testing, and prototype attack simulation components.

The current architecture is:

```text
Member 1 eBPF/XDP
       ↓
Telemetry JSON
       ↓
POST /events
       ↓
Member 2 Backend
       ↓
SQLite Database
       ↓
Detection Engine
 ┌─────┼──────────┐
 BOLA  BFLA  Shadow API
 └─────┼──────────┘
       ↓
    Alerts
       ↓
Member 3 Dashboard
```

## Current telemetry contract

The current Member 1 network telemetry contract is:

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
```

Required network fields:

```text
event_id
timestamp
src_ip
dst_ip
src_port
dst_port
protocol
packet_len
```

Optional API/application enrichment:

```text
method
path
user_id
role
object_id
```

The optional API fields are nullable because the current XDP collector provides Layer 3/4 telemetry and cannot reliably obtain application identity from packet metadata.

## Backend structure

```text
backend/
├── app/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   │
│   ├── routes/
│   │   ├── events.py
│   │   ├── inventory.py
│   │   └── alerts.py
│   │
│   └── detection/
│       ├── alert_helper.py
│       ├── bola.py
│       ├── bfla.py
│       ├── shadow_api.py
│       └── engine.py
│
└── tests/
```

## API endpoints

### Health

```text
GET /
GET /health
```

### Events

```text
POST /events
GET /events
GET /events/{id}
```

`POST /events` stores telemetry and updates the observed-service/API inventory.

### Inventory

```text
GET /inventory
GET /inventory/{id}
```

Inventory currently tracks:

```text
path
method
destination IP
destination port
protocol
first seen
last seen
observation count
documented status
```

For network-only telemetry, `path` and `method` remain null.

### Alerts

```text
GET /alerts
GET /alerts/{id}
```

Alert structure includes:

```text
alert ID
alert type
severity
source IP
destination
timestamp
description
evidence
status
```

## Detection modules

### BOLA

The prototype BOLA detector uses a rule-based object ownership model.

Example:

```text
User A owns:
101
102

User A requests:
103

→ BOLA alert
```

This is a prototype rule-based detector and does not claim complete real-world BOLA coverage.

### BFLA

The prototype BFLA detector uses role-based endpoint permissions.

Example:

```text
USER
DELETE /api/users/10

→ BFLA alert
```

Parameterized API paths such as:

```text
/api/users/10
```

are normalized to:

```text
/api/users/{id}
```

before permission matching.

### Shadow API

The prototype Shadow API detector compares observed API method/path combinations with a known API set.

Example:

```text
Known:
GET /api/users
POST /api/login

Observed:
GET /api/internal/debug

→ Shadow API alert
```

Parameterized paths are normalized so documented routes such as:

```text
GET /api/users/{id}
```

match:

```text
GET /api/users/103
```

## Running the backend

From the project root:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn backend.app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

Swagger:

```text
http://127.0.0.1:8000/docs
```

## Running the mock service

From the project root:

```powershell
python .\mock-services\api.py
```

Mock service:

```text
http://127.0.0.1:9000
```

Swagger:

```text
http://127.0.0.1:9000/docs
```

## Running simulations

BOLA:

```powershell
python .\attack-simulator\bola_test.py
```

BFLA:

```powershell
python .\attack-simulator\bfla_test.py
```

Shadow API:

```powershell
python .\attack-simulator\shadow_api_test.py
```

The simulations send representative API activity to the mock service and submit corresponding security events to the Member 2 backend.

## Running tests

Run the full backend test suite:

```powershell
python -m pytest backend/tests -v
```

The tests cover:

```text
Event ingestion
Event retrieval
Inventory
BOLA
BFLA
Shadow API
Alert creation/retrieval
Member 1 telemetry compatibility
End-to-end detection flow
```

## Integration boundary with Member 1

The current integration contract is:

```text
eBPF/XDP
   ↓
Network telemetry JSON
   ↓
POST /events
   ↓
Event DB
   ↓
Inventory / Detection
```

Member 1 currently provides:

```text
event_id
timestamp
src_ip
dst_ip
src_port
dst_port
protocol
packet_len
```

API-level fields remain optional:

```text
method
path
user_id
role
object_id
```

Network-only events with null API context are stored without triggering BOLA/BFLA/Shadow API false positives.

## Current limitations

The current detection implementation is a prototype.

The eBPF/XDP collector does not automatically provide application identity or authorization context.

HTTP method/path may not be available from encrypted HTTPS traffic at the XDP layer.

The current inventory observation count represents received telemetry events and should not be interpreted as an exact HTTP request count until API-level request telemetry is available.

BOLA and BFLA rules are prototype rule sets and are not intended to represent complete production authorization policies.

## Current status

Completed:

```text
Backend foundation
Event ingestion
Event retrieval
Inventory
Alerts
BOLA
BFLA
Shadow API
Detector tests
Mock service
Attack simulators
Event → Detection → Alert integration
Member 1 telemetry compatibility
```

Remaining team-level work:

```text
Final automated regression validation
Final real eBPF → POST /events validation
Member 3 dashboard integration
Final end-to-end demonstration
```

\# API-Sentinel
## Runtime API Security Monitoring \& Detection Engine
API-Sentinel is a runtime API security monitoring MVP designed to observe API/network activity, maintain an API inventory, detect API security issues, and present security information through a centralized React dashboard.
## Problem Statement
Modern applications expose multiple APIs and services. Undocumented APIs and improper authorization can introduce security risks such as:
- Broken Object Level Authorization (BOLA)
- Broken Function Level Authorization (BFLA)
- Shadow APIs
- Unauthorized API operations
API-Sentinel provides runtime visibility into observed services and security alerts through a centralized dashboard.
## Objectives
- Monitor runtime API/network events
- Maintain an API inventory
- Identify undocumented APIs
- Detect BOLA attempts
- Detect BFLA authorization violations
- Generate security alerts with severity levels
- Provide centralized security monitoring through a web dashboard
## Key Features
### Runtime Event Monitoring
The backend stores observed runtime events including:
- Source IP
- Destination IP
- Protocol
- Source port
- Destination port
- Packet length
These events are displayed in the Recent Events section of the dashboard.
### API Inventory
The system maintains an inventory of observed services/APIs.
Inventory information includes:
- Endpoint/path
- HTTP method
- First seen timestamp
- Last seen timestamp
- Request count
- Documentation status
Undocumented services are identified as Shadow APIs.
### BOLA Detection
The BOLA detector identifies attempts to access objects outside a user's authorized object set.
When a BOLA violation is detected, the system creates a security alert containing information such as:
- Alert type
- Severity
- Destination
- Description
- Evidence
### BFLA Detection
The BFLA detector uses role-based endpoint permissions to identify unauthorized operations.
If a user attempts an operation that is not permitted for their role, the system generates a HIGH severity BFLA alert.
### Security Alerts
The dashboard displays detected security alerts with:
- Status
The dashboard also provides:
- Alert search
- Alert-type filtering
Current alert categories include:
- BOLA
- BFLA
- Shadow API
### React Security Dashboard
The dashboard provides:
- Total APIs
- BOLA Attacks
- BFLA Attacks
- Recent Events
- API Inventory
- Security Alerts
Backend data is automatically refreshed every 5 seconds.
## Technology Stack
### Frontend
- React
- Vite
- JavaScript
### Backend
- Python
- FastAPI
- SQLAlchemy
- SQLite
- Pydantic
### Testing
- Pytest
## Project Structure
api-sentinel/
|
|-- backend/
|   |-- app/
|   |   |-- detection/
|   |   |   |-- bola.py
|   |   |   |-- bfla.py
|   |   |   |-- shadow\_api.py
|   |   |-- routes/
|   |   |   |-- alerts.py
|   |   |   |-- events.py
|   |   |   |-- inventory.py
|   |   |-- database.py
|   |   |-- models.py
|   |   |-- schemas.py
|   |   |-- main.py
|   |
|   |-- tests/
|   |-- requirements.txt
|-- frontend/
|   |-- src/
|   |   |-- App.jsx
|   |   |-- App.css
|   |   |-- main.jsx
|   |-- package.json
|-- README.md
|-- .gitignore
## Backend API Endpoints
### Runtime Events
GET /events
Returns observed runtime events.
GET /inventory
Returns all observed API/service inventory entries.
GET /inventory/{inventory\_id}
Returns a specific inventory entry.
GET /alerts
Returns generated security alerts.
GET /alerts/{alert\_id}
Returns a specific security alert.
## Running the Project
### Start Backend
Open a terminal in the project root:
cd backend
Activate the virtual environment:
.\\venv\\Scripts\\Activate.ps1
Start FastAPI:
uvicorn app.main:app --reload --port 8000
Backend:
http://127.0.0.1:8000
### Start Frontend
Open another terminal:
cd frontend
npm run dev
The Vite development server will display the dashboard URL, normally:
http://localhost:5173
## Testing
Backend tests are executed using Pytest.
From the backend directory:
$env:PYTHONPATH=".."
pytest -q
Current verified result:
6 passed
## Frontend Production Build
The frontend production build can be verified with:
npm run build
The Vite production build completes successfully.
## Demonstration Flow
A typical project demonstration can follow this sequence:
1. Start the FastAPI backend.
2. Start the React dashboard.
3. Show runtime events in Recent Events.
4. Show observed services in API Inventory.
5. Show an undocumented service as a Shadow API.
6. Trigger a BOLA test case.
7. Show the generated BOLA alert.
8. Trigger a BFLA test case.
9. Show the generated BFLA alert.
10. Demonstrate alert filtering and search.
11. Explain the backend-to-dashboard integration.
## Testing Status
- Backend automated tests: 6 passed
- Frontend production build: Successful
- Backend API integration: Verified
- BOLA detection: Verified
- BFLA detection: Verified
- Security alerts displayed in dashboard: Verified
## Future Scope
Future improvements may include:
- Full eBPF-based runtime telemetry
- Rust-based high-performance telemetry components
- Zombie API lifecycle detection
- Dynamic role and permission management
- Authentication integration
- WebSocket-based real-time alert streaming
- Advanced security analytics
- Alert acknowledgement and incident management
- Cloud/container deployment
## Conclusion
API-Sentinel demonstrates a runtime API security monitoring workflow in which observed activity is collected, API inventory is maintained, authorization violations are detected, security alerts are generated, and the results are presented through a centralized React dashboard.
The current MVP focuses on runtime event visibility, API inventory, Shadow API identification, BOLA detection, BFLA detection, security alerts, and frontend-backend integration.
### Dashboard Verification

The Member 3 dashboard was verified with the FastAPI backend. API inventory, events, and security alerts were checked successfully during local integration testing.
The dashboard was locally verified with the FastAPI backend, including event ingestion, API inventory, and security alert display.

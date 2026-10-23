# ZeroPhish

ZeroPhish is a local phishing-analysis application with URL, message, QR-code,
and screenshot scanners. Scans analyze submitted content; do not open suspicious
links or enter real credentials as part of testing.

## Development

Run commands from the project root so the configured database and model paths
resolve as expected. Install the pinned requirements into a Python version
supported by those packages and the existing model artifacts. The current
working environment reports a scikit-learn 1.9.1 runtime while the model
artifacts were created with scikit-learn 1.6.1; use the pinned 1.6.1 runtime
for deployment rather than migrating the artifacts without compatibility
testing.

### Backend

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

The API documentation is available at `http://127.0.0.1:8000/docs`.

### Frontend

In a second terminal:

```powershell
Set-Location frontend
npm ci
npm run dev -- --host 127.0.0.1
```

The Vite development server runs at `http://127.0.0.1:5173` and proxies `/api`
requests to the backend at `http://localhost:8000`.

To build the frontend bundle:

```powershell
npm run build
```

The generated static files are placed in `frontend\dist`.

## Production deployment

This repository does not include a production server configuration or a
production deployment command. A deployment must serve `frontend\dist` over
HTTPS and route `/api` to the FastAPI backend. Configure the reverse proxy,
process supervision, TLS, request-size limits, and CORS allowlist for the
deployment environment before exposing the service. The development CORS
configuration is limited to localhost origins and is not a production
allowlist.

Keep model artifacts and the SQLite database in persistent, access-controlled
storage. No environment-variable or secrets template is currently provided.

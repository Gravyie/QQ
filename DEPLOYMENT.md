# Quantum Atlas (ECDAT 26164) — Unified Deployment Guide

Quantum Atlas is engineered as a **unified single-origin architecture**:
* The **FastAPI backend** serves both the REST/SSE APIs and the compiled **React 19 single-page application** from a single port (`8000`).
* No separate web server or CORS configuration is needed in production.
* All cryptographic discovery engines, threat analyzers, Mosca simulators, and export engines run seamlessly inside the container or host.

---

## Quick Start (Choose Your Preferred Method)

### Method 1: Docker / Docker Compose (Recommended for Cloud & Production)
Requires Docker & Docker Compose installed.

```bash
# Clone repository and navigate to root
cd quantum-atlas

# Build and start in detached mode
docker compose up --build -d

# Check health
curl http://localhost:8000/api/health
```

* **Landing Page**: `http://localhost:8000`
* **ECDAT Console**: `http://localhost:8000/#/console`
* **Interactive API Docs**: `http://localhost:8000/docs`
* **Stop Container**: `docker compose down`
* **View Logs**: `docker compose logs -f`

> **Note**: Scan results (CBOM, SARIF, Markdown reports) generated at `/app/results` inside the container are automatically persisted to your host's `./results/` folder via the volume mount.

---

### Method 2: Native 1-Command Deployment Script
For local testing or deploying directly onto a Linux/macOS server:

```bash
# Run the automated deployment script
./deploy.sh
```

This script automatically:
1. Builds the production frontend bundle into `frontend/dist/`.
2. Verifies Python dependencies in `.venv`.
3. Starts the unified FastAPI server on `0.0.0.0:8000`.

---

### Method 3: Manual Step-by-Step Deployment

#### Step 1: Build the Frontend
```bash
cd frontend
npm install
npm run build
cd ..
```
*(This produces the static production bundle at `frontend/dist/`)*

#### Step 2: Set Up the Backend
```bash
# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt
```

#### Step 3: Launch the Production Server
```bash
export PYTHONPATH=backend
uvicorn server:app --host 0.0.0.0 --port 8000 --app-dir backend
```

---

## Cloud Deployment Options

### 1. Cloud Run / AWS ECS / DigitalOcean App Platform (Serverless Container)
1. Push the repository to GitHub.
2. Link the repository to your cloud provider.
3. Configure the build:
   - **Build Type**: Dockerfile (uses the root `Dockerfile`)
   - **Port**: `8000`
   - **Environment Variables**: `PYTHONUNBUFFERED=1`
4. The service will auto-build and deploy a HTTPS endpoint.

### 2. Render.com / Railway / Fly.io
* **Render**: Create a new **Web Service** -> Connect GitHub repo -> Select **Docker** environment -> Deploy.
* **Railway**: Run `railway up` or connect GitHub repo. Railway detects the `Dockerfile` automatically.
* **Fly.io**: Run `fly launch` and select port `8000`.

---

## Production Linux VM (systemd + Nginx SSL)

To run Quantum Atlas as a background system service on Ubuntu/Debian:

### 1. Create systemd service
Create `/etc/systemd/system/quantum-atlas.service`:
```ini
[Unit]
Description=Quantum Atlas ECDAT Service
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/quantum-atlas
Environment="PYTHONPATH=/opt/quantum-atlas/backend"
ExecStart=/opt/quantum-atlas/.venv/bin/uvicorn server:app --host 127.0.0.1 --port 8000 --app-dir /opt/quantum-atlas/backend --workers 4
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quantum-atlas
```

### 2. Nginx Reverse Proxy with HTTPS (Let's Encrypt)
```nginx
server {
    server_name ecdat.your-organization.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE (Server-Sent Events) streaming support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
    }
}
```

---

## Verification Checklist

After deploying, verify the deployment:

```bash
# 1. Health check
curl -s http://localhost:8000/api/health | jq .
# Expected: { "status": "ok", "current_year": 2026, "algorithms": 112, ... }

# 2. Check Static Frontend
curl -I http://localhost:8000/
# Expected: HTTP/1.1 200 OK, Content-Type: text/html

# 3. Check OpenAPI / Swagger docs
curl -I http://localhost:8000/docs
# Expected: HTTP/1.1 200 OK
```

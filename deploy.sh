#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "========================================================"
echo " Quantum Atlas — ECDAT 26164 Unified Deployment Script"
echo "========================================================"

MODE="${1:-native}"

if [ "$MODE" = "docker" ]; then
    echo ">> Building and launching with Docker Compose..."
    docker compose up --build -d
    echo ""
    echo ">> Deployment successful!"
    echo ">> Quantum Atlas is live at: http://localhost:8000"
    echo ">> To view logs: docker compose logs -f"
    echo ">> To stop: docker compose down"
    exit 0
fi

echo ">> Step 1/3: Building Frontend (React 19 + Vite)..."
cd "$DIR/frontend"
if [ ! -d "node_modules" ]; then
    echo "   Installing npm dependencies..."
    npm install
fi
npm run build

echo ">> Step 2/3: Checking Python Virtual Environment..."
cd "$DIR"
if [ ! -d ".venv" ]; then
    echo "   Creating Python 3 virtual environment in .venv..."
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r backend/requirements.txt
fi

echo ">> Step 3/3: Launching Unified Production Server on port 8000..."
echo ""
echo "========================================================"
echo " Quantum Atlas is running!"
echo "   Landing Page: http://127.0.0.1:8000"
echo "   ECDAT Console: http://127.0.0.1:8000/#/console"
echo "   API Swagger:  http://127.0.0.1:8000/docs"
echo "========================================================"
echo ""

export PYTHONPATH="$DIR/backend"
exec "$DIR/.venv/bin/uvicorn" server:app --host 0.0.0.0 --port 8000 --app-dir "$DIR/backend"

# ==============================================================================
# Multi-stage Dockerfile for Quantum Atlas (ECDAT 26164)
# Stage 1: Build React 19 Frontend with Vite
# Stage 2: Lightweight Python 3.11 Runtime serving FastAPI + Built Frontend
# ==============================================================================

# --- Stage 1: Frontend Build ---
FROM node:20-alpine AS frontend-builder
WORKDIR /build

# Copy dependency specifications and install
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

# Copy frontend source and compile production bundle into dist/
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Production Runtime ---
FROM python:3.11-slim AS runtime

# Install system dependencies for cryptography & TLS networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python backend dependencies
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY backend/ /app/backend/

# Copy corpus data (for scan demos & test estate evaluation)
COPY corpus/ /app/corpus/

# Create results directory for CBOM, SARIF & report outputs
RUN mkdir -p /app/results

# Copy compiled frontend from Stage 1 into /app/frontend/dist
COPY --from=frontend-builder /build/dist/ /app/frontend/dist/

# Set Python path to find atlas package
ENV PYTHONPATH=/app/backend
ENV PYTHONUNBUFFERED=1

# Expose single unified port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

# Start FastAPI server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "backend"]

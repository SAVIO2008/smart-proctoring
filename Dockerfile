# ---- Build stage: frontend ----
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Runtime stage: Python backend ----
FROM python:3.13-slim
WORKDIR /app

# System dependencies for OpenCV
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY backend/ backend/
COPY models/ models/

# Frontend build output (from build stage)
COPY --from=frontend-build /app/frontend/dist/ frontend/dist/

# Create data directories
RUN mkdir -p evidence data_store

EXPOSE 8000

# Production settings are injected via environment variables.
# Defaults are safe for Railway (DEBUG=False, DATABASE_MODE=mongodb, HOST=0.0.0.0).
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
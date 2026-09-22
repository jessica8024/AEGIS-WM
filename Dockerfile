# ==============================================================================
# AEGIS-WM: Anticipatory Enterprise Graph Intelligence System
# Offline Production Container Definition
# ==============================================================================

FROM python:3.11-slim AS runtime

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install native system dependencies for Scapy, PyTorch, DuckDB, and network capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python package dependencies
COPY pyproject.toml /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    pydantic \
    pyyaml \
    numpy \
    scipy \
    scikit-learn \
    pandas \
    duckdb \
    pyarrow \
    scapy \
    captum \
    safetensors \
    reportlab \
    python-multipart

# Copy AEGIS-WM core framework and configuration
COPY aegis_wm/ /app/aegis_wm/
COPY configs/ /app/configs/
COPY apps/api/ /app/apps/api/
COPY apps/analyst-console/dist/ /app/apps/analyst-console/dist/
COPY models/ /app/models/
COPY reports/ /app/reports/

# Create persistent storage directories
RUN mkdir -p /app/data/raw /app/data/processed /app/data/flows /app/data/states /app/reports

EXPOSE 8000

# Health check verifies API response
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Launch FastAPI ASGI server serving both REST API and React SPA
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

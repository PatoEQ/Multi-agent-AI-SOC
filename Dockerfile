# SOC Sentinel Crew — container image for the Streamlit UI (and CLI).
#   docker compose up            -> http://localhost:8501
#   docker compose run --rm soc-sentinel python main.py --sample
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CREWAI_DISABLE_TELEMETRY=true \
    OTEL_SDK_DISABLED=true \
    CREWAI_TRACING_ENABLED=false \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

# Install dependencies first so code changes do not invalidate this layer.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

# Run as an unprivileged user; only output/ needs to be writable.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/output /app/evals/results \
    && chown -R appuser:appuser /app/output /app/evals/results
USER appuser

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]

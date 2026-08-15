# The served model is gitignored, so the image trains it during the build. That
# keeps the image self-contained and reproducible from source alone: the model
# always matches the code and dataset in the same commit.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PHISHING_ROOT=/build

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libgomp1 \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$VIRTUAL_ENV"

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY pyproject.toml README.md Training_Dataset.csv ./
COPY src/ ./src/
COPY analysis/ ./analysis/
RUN pip install . --no-deps

# Produces artifacts/model.joblib and reports/06_model_card.json.
RUN python analysis/06_train_final.py


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    PHISHING_ROOT=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner

COPY --from=builder /opt/venv /opt/venv

COPY Training_Dataset.csv ./
COPY api/ ./api/
COPY web/ ./web/
COPY reports/ ./reports/
COPY --from=builder /build/artifacts/ ./artifacts/
COPY --from=builder /build/reports/06_model_card.json ./reports/06_model_card.json

RUN chown -R scanner:scanner /app
USER scanner

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

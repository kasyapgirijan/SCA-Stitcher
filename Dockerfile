FROM python:3.12.13-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/users.db

WORKDIR /app

RUN addgroup --system app \
    && adduser --system --ingroup app app \
    && mkdir /data \
    && chown app:app /data

COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + || true

COPY --chown=app:app web_app.py checkmarx_sca_consolidator_v2.py security.py ./
COPY --chown=app:app templates ./templates
COPY --chown=app:app static ./static

USER app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["gunicorn", "--preload", "--bind=0.0.0.0:8080", "--workers=2", "--threads=1", "--timeout=60", "--graceful-timeout=15", "--keep-alive=5", "--max-requests=500", "--max-requests-jitter=50", "--limit-request-fields=50", "--limit-request-field_size=8190", "--worker-tmp-dir=/tmp", "--access-logfile=-", "--error-logfile=-", "--capture-output", "web_app:app"]

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_PATH=/data/users.db
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app && mkdir /data && chown app:app /data
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app . .
USER app
EXPOSE 8080
CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=2", "--threads=4", "--access-logfile=-", "web_app:app"]

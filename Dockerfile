FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    WEB_BIND=0.0.0.0 \
    WEB_PORT=8080

WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt
COPY app /srv/app
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()" || exit 1
CMD ["sh", "-c", "uvicorn app.main:app --host ${WEB_BIND} --port ${WEB_PORT} --proxy-headers --forwarded-allow-ips=${FORWARDED_ALLOW_IPS:-*}"]

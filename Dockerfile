FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    WEB_BIND=0.0.0.0 \
    WEB_PORT=8080

ARG APP_VERSION=1.20.0
ARG BUILD_SHA=development
ARG BUILD_CHANNEL=development
ARG SCHEMA_VERSION=1
ENV BLOCKINATOR_BUILD_SHA=$BUILD_SHA BLOCKINATOR_BUILD_CHANNEL=$BUILD_CHANNEL
LABEL org.opencontainers.image.version=$APP_VERSION \
      org.opencontainers.image.revision=$BUILD_SHA \
      org.opencontainers.image.source="https://github.com/StealthCat/blockinator-web" \
      io.blockinator.schema=$SCHEMA_VERSION \
      io.blockinator.updater-protocol="1"

WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt
COPY app /srv/app
COPY tools /srv/tools
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()" || exit 1
CMD ["sh", "-c", "uvicorn app.main:app --host ${WEB_BIND} --port ${WEB_PORT} --proxy-headers --forwarded-allow-ips=${FORWARDED_ALLOW_IPS:-*}"]

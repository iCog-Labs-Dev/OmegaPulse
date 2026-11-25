FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt
COPY *.py /app/monitor/
COPY static /app/monitor/static/
COPY templates /app/monitor/templates/
USER 1000:1000

ARG PULSE_VERSION=0.1.0-dev
ARG PULSE_REVISION=""
ARG PULSE_SOURCE="https://github.com/iCog-Labs-Dev/OmegaPulse"

ENV PULSE_VERSION=${PULSE_VERSION}

LABEL org.opencontainers.image.version="${PULSE_VERSION}" \
      org.opencontainers.image.revision="${PULSE_REVISION}" \
      org.opencontainers.image.source="${PULSE_SOURCE}"

ENTRYPOINT ["python", "-m", "monitor.app"]

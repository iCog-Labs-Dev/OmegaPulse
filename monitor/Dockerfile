FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt
COPY *.py /app/monitor/
COPY static /app/monitor/static/
COPY templates /app/monitor/templates/
USER 1000:1000
ENTRYPOINT ["python", "-m", "monitor.app"]

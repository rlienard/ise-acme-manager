FROM python:3.11-slim

LABEL maintainer="your-email@yourdomain.com"
LABEL description="ISE ACME Certificate Manager — API Daemon"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends dnsutils curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN mkdir -p /app/data && \
    groupadd -r iseacme && useradd -r -g iseacme iseacme && \
    chown -R iseacme:iseacme /app

USER iseacme

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443"]

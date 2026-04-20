FROM python:3.12-slim

LABEL maintainer="ParallaxForge"
LABEL description="Cybersecurity AI Assistant"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV PARALLAX_MODE=terminal

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-delay=5s --retries=3 \
  CMD curl -f http://localhost:8080/status || exit 1

CMD ["python", "-m", "core.terminal"]
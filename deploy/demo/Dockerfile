# The public sandbox: the gateway and the poisoned test server in one container.
# Build from the repository root:
#   docker build -f deploy/demo/Dockerfile -t mcp-security-gateway-sandbox .
# The production image is ./Dockerfile; this one adds the test server and
# starts in MSG_ENVIRONMENT=sandbox, with the public demo keys.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Debian security updates published after the base image was built.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 gateway \
    && useradd --uid 10001 --gid gateway --create-home --shell /usr/sbin/nologin gateway

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . \
    && python -m pip uninstall --yes setuptools wheel pip

COPY examples/poisoned_server.py examples/upstreams.json deploy/demo/run_demo.py /app/demo/

# The host sets PORT (Render: 10000); run_demo.py falls back to 8000.
ENV MSG_ENVIRONMENT=sandbox \
    MSG_UPSTREAMS=/app/demo/upstreams.json \
    MSG_MAX_REQUEST_BYTES=65536

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('PORT', '8000')}/health\", timeout=2)"]

CMD ["python", "/app/demo/run_demo.py"]

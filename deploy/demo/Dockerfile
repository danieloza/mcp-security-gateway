# The public sandbox: the gateway, the poisoned test server and the Danex
# retrieval server in one container. Build from the repository root:
#   docker build -f deploy/demo/Dockerfile -t mcp-security-gateway-sandbox .
# The production image is ./Dockerfile; this one adds the two upstreams and
# starts in MSG_ENVIRONMENT=sandbox, with the public demo keys.

# The retrieval server comes from danex-rag-service at a pinned commit. Git
# checks that the fetched tree is that commit; CI's proxy end-to-end run reads
# the same line, so the sandbox and the test use one version.
FROM python:3.11-slim AS danex-rag
ARG DANEX_RAG_COMMIT=e06b1044e0e2766685c69c4a43b9be90952c560e
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git init -q /src \
    && git -C /src fetch -q --depth 1 https://github.com/danieloza/danex-rag-service.git "$DANEX_RAG_COMMIT" \
    && git -C /src checkout -q --detach FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "$DANEX_RAG_COMMIT"

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

# The e2e extra is the MCP Python SDK, which the retrieval server runs on.
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[e2e]" \
    && python -m pip uninstall --yes setuptools wheel pip

COPY examples/poisoned_server.py deploy/demo/upstreams.json deploy/demo/run_demo.py /app/demo/
COPY --from=danex-rag /src/mcp_server.py /src/retrieval_control.py /app/demo/rag/
COPY --from=danex-rag /src/knowledge_base /app/demo/rag/knowledge_base

# The host sets PORT (Render: 10000); run_demo.py falls back to 8000.
ENV MSG_ENVIRONMENT=sandbox \
    MSG_UPSTREAMS=/app/demo/upstreams.json \
    MSG_MAX_REQUEST_BYTES=65536

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('PORT', '8000')}/health\", timeout=2)"]

CMD ["python", "/app/demo/run_demo.py"]

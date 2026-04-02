FROM python:3.12-slim

LABEL org.opencontainers.image.title="MCP-Fortress"
LABEL org.opencontainers.image.description="Production-grade security firewall & proxy for AI Agent MCP — by Avoceous"
LABEL org.opencontainers.image.source="https://github.com/Avoceous/mcpshield"
LABEL org.opencontainers.image.licenses="MIT"

# Security: non-root user
RUN addgroup --system mcpshield && adduser --system --group mcpshield

WORKDIR /app

# Install dependencies first (layer caching)
COPY pyproject.toml .
RUN pip install --no-cache-dir ".[proxy,yaml]"

# Copy source
COPY mcpshield/ ./mcpshield/

# Default policy and config locations
RUN mkdir -p /app/config /app/logs
COPY examples/policy_enterprise.yaml /app/config/policy.yaml

RUN chown -R mcpshield:mcpshield /app
USER mcpshield

# Proxy port
EXPOSE 8100
# Dashboard port
EXPOSE 8101

ENV UPSTREAM_MCP_URL="http://localhost:3000"
ENV MCPSHIELD_HOST="0.0.0.0"
ENV MCPSHIELD_PORT="8100"
ENV MCPSHIELD_POLICY="/app/config/policy.yaml"
ENV MCPSHIELD_AUDIT_LOG="/app/logs/audit.jsonl"

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/api/v1/health')"

CMD ["sh", "-c", "mcpshield proxy \
  --upstream $UPSTREAM_MCP_URL \
  --host $MCPSHIELD_HOST \
  --port $MCPSHIELD_PORT \
  --policy $MCPSHIELD_POLICY"]

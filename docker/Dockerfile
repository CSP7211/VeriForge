# VeriForge MCP Server — Docker Image
# Production-ready container with Python 3.12 slim

FROM python:3.12-slim

LABEL maintainer="VeriForge Team"
LABEL description="MCP Server for code verification, compliance, and security scanning"
LABEL version="0.5.0"

# Security: create non-root user
RUN groupadd -r veriforge && useradd -r -g veriforge veriforge

# Set working directory
WORKDIR /app

# Install dependencies first for layer caching
COPY setup.py pyproject.toml ./
COPY veriforge_mcp/__init__.py ./veriforge_mcp/
RUN pip install --no-cache-dir -e "."

# Copy application code
COPY veriforge_mcp/ ./veriforge_mcp/
COPY README.md LICENSE ./

# Install the package
RUN pip install --no-cache-dir -e "." && \
    chown -R veriforge:veriforge /app

# Switch to non-root user
USER veriforge

# Expose SSE transport port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Default: run stdio transport (override for SSE)
ENTRYPOINT ["python", "-m", "veriforge_mcp.server"]
CMD ["--transport", "stdio"]

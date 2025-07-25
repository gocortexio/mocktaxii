# MockTAXII v0.5.1 - Production-ready TAXII 2.x server for XSIAM and XSOAR TIM demonstrations
# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim-bookworm

# Set working directory
WORKDIR /app

# Install system dependencies with security updates
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    curl \
    postgresql-client \
    ca-certificates \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first for better layer caching
COPY pyproject.toml uv.lock ./

# Install UV package manager
RUN pip install uv

# Install Python dependencies
RUN uv sync --frozen

# Activate the virtual environment by updating PATH
ENV PATH="/app/.venv/bin:$PATH"

# Copy and setup entrypoint script before switching users
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=main.py
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/stats || exit 1

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Start command
CMD ["uv", "run", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "--keep-alive", "60", "main:app"]
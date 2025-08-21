# MockTAXII v0.5.2 - Production-ready TAXII 2.x server for XSIAM and XSOAR TIM demonstrations
# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim-bookworm

# Set working directory
WORKDIR /app

# Install system dependencies with security updates
# Addressing CVE-2023-45853 (zlib), CVE-2025-7458 (sqlite3), CVE-2025-6020 (pam), CVE-2025-6965 (sqlite3)
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    curl \
    postgresql-client \
    ca-certificates \
    zlib1g \
    libsqlite3-0 \
    libpam-modules \
    wget \
    build-essential \
    && apt-get upgrade -y \
    && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# CRITICAL: Update SQLite to >= 3.50.2 to address CVE-2025-6965
# Download and compile latest SQLite source to ensure version 3.50.2+
RUN cd /tmp && \
    wget https://www.sqlite.org/2025/sqlite-autoconf-3500200.tar.gz && \
    tar -xzf sqlite-autoconf-3500200.tar.gz && \
    cd sqlite-autoconf-3500200 && \
    ./configure --prefix=/usr/local && \
    make && \
    make install && \
    ldconfig && \
    cd / && \
    rm -rf /tmp/sqlite-autoconf-* && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/sqlite.conf && \
    ldconfig

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
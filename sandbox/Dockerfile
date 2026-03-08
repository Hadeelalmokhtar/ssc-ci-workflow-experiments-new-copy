FROM python:3.11-slim

WORKDIR /app

# Install system tools
RUN apt-get update && apt-get install -y \
    strace \
    curl \
    wget \
    git \
    nodejs \
    npm \
    procps \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure scripts module works
ENV PYTHONPATH=/app

# Default command
CMD ["python", "sandbox/runner.py"]

FROM python:3.11-slim

LABEL maintainer="CAPE Analysis Pipeline"
LABEL description="Multi-source malware feeder for MWDB"

WORKDIR /app

# Install dependencies
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ .

# Create work directory
RUN mkdir -p /work/reports && chmod 777 /work /work/reports

# Run as non-root
RUN useradd -m -u 1000 feeder
USER feeder

# Default command
CMD ["python", "feeder.py"]

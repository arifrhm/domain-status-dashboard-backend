# Use Python 3.11 Alpine as base image
FROM python:3.11-alpine

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    postgresql-dev \
    python3-dev \
    libffi-dev \
    openssl-dev

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Add the application directory to PYTHONPATH
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "app/main.py"] 
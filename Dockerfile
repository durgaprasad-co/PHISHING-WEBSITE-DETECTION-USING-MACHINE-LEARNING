# --- Stage 1: Builder ---
# This stage installs dependencies and builds a virtual environment.
FROM python:3.10 as builder

# Set environment variables for a clean build
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies required for building Python packages like psycopg2 and scipy
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only the requirements file to leverage Docker cache
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: Final Image ---
# This stage creates the final, lightweight, and secure image.
FROM python:3.10-slim

# Create a non-root user and group for security
RUN addgroup --system app && adduser --system --group app

WORKDIR /app

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy the application source code and set ownership to the non-root user.
# This assumes the 'model' directory is present in the build context.
COPY --chown=app:app . /app/

# Define the port the container will listen on
ENV PORT 8080

# Switch to the non-root user
USER app

# Command to run the application using Gunicorn
CMD ["/opt/venv/bin/gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "4", "app:app"]
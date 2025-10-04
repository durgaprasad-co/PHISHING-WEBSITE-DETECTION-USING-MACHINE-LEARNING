# Use a slim Python base image
FROM python:3.10-slim

# Install system dependencies required for packages like psycopg2 and scipy
# Using --no-install-recommends keeps the image size down
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create model directory
RUN mkdir -p /app/model

# Copy model files first (if they exist)
COPY model/*.joblib /app/model/

# Copy all other project files
COPY . /app/

# Define the port the container will listen on
ENV PORT 8080

# Command to run the application using Gunicorn
# app:app refers to the 'app' object inside the 'app.py' file
CMD exec gunicorn --bind :$PORT --workers 2 --threads 4 app:app
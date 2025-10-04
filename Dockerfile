# Use a slim Python base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Install dependencies
# NOTE: This assumes 'requirements.txt' is present in the project root.
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
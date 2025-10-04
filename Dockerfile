# Use a slim Python base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Install dependencies (gunicorn, Flask-Bcrypt, etc.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files: app.py, ML models, and templates/static folders
COPY . /app/

# Define the port the container will listen on
ENV PORT 8080

# Command to run the application using Gunicorn
# app:app refers to the 'app' object inside the 'app.py' file
CMD exec gunicorn --bind :$PORT --workers 2 --threads 4 app:app
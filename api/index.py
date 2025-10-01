# This file is the entry point Vercel uses to run your application.
# It imports the main Flask app object from the parent directory.

from app import app
from vercel_app import handler

# The 'handler' function is what Vercel executes.
# It wraps the Flask app instance for the serverless environment.

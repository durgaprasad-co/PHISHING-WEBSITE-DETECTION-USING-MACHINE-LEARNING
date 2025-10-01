# This file is the entry point Vercel uses to run your application.
# It MUST expose the Flask application instance directly.

from app import app

# Vercel's Python builder automatically handles the 'app' object
# as the serverless function entry point.
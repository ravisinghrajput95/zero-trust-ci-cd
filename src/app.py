import os
import logging
from flask import Flask, request, jsonify
from markupsafe import escape
from werkzeug.exceptions import HTTPException
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# Restrict allowed hosts
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

@app.before_request
def validate_host():
    if request.host.split(":")[0] not in ALLOWED_HOSTS:
        return jsonify({"error": "Forbidden"}), 403

# Enforce HTTPS
@app.before_request
def force_https():
    if not request.is_secure and os.getenv("FORCE_HTTPS", "True").lower() in ("1", "true", "yes"):
        return jsonify({"error": "HTTPS required"}), 403

# Set up rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

@app.route('/')
@limiter.limit("10 per minute")  # Apply a stricter limit to the root endpoint
def home():
    return "Hello, Secure Zero Trust CI/CD!"

# Handle errors gracefully
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return jsonify({"error": escape(e.description)}), e.code
    logging.error(f"Unexpected error: {str(e)}")
    return jsonify({"error": "Internal Server Error"}), 500

# Safer debug configuration
DEBUG_MODE = os.getenv("DEBUG", "False").lower() in ("1", "true", "yes")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)), debug=DEBUG_MODE)

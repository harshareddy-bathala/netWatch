"""
app.py - Flask Application Factory
====================================

This module creates and configures the Flask application instance.

OWNER: Member 2 (Backend Developer)

WHAT THIS FILE SHOULD CONTAIN:
------------------------------
1. Import statements:
   - from flask import Flask
   - from flask_cors import CORS
   - from backend.routes import register_routes
   - from config import *

2. create_app() function that:
   - Creates a Flask application instance
   - Configures CORS for cross-origin requests
   - Sets up static file serving for the frontend folder
   - Registers all routes by calling register_routes(app)
   - Configures error handlers for 404 and 500 errors
   - Returns the configured app instance

3. Error handlers:
   - handle_404(error): Return JSON response for not found
   - handle_500(error): Return JSON response for server errors

4. The app should:
   - Serve static files from the frontend/ directory
   - Have CORS enabled for all origins (development) or specific origins (production)
   - Return JSON error responses, not HTML

EXAMPLE STRUCTURE:
------------------
from flask import Flask, jsonify
from flask_cors import CORS

def create_app():
    app = Flask(__name__, static_folder='../frontend', static_url_path='')
    CORS(app)
    
    # Register routes
    register_routes(app)
    
    # Error handlers
    @app.errorhandler(404)
    def handle_404(error):
        return jsonify({'error': 'Not found'}), 404
    
    return app
"""

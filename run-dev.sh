#!/bin/bash

# Neofrp Admin Panel Development Runner

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set development environment
export FLASK_ENV=development
export FLASK_DEBUG=1

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "Checking dependencies..."
pip install -r requirements.txt --quiet

# Initialize database if needed
if [ ! -f "neofrp.db" ]; then
    echo "Database not found. Initializing..."
    python init_db.py
fi

# Start the application in development mode
echo "Starting Neofrp Admin Panel in development mode..."
echo "URL: http://localhost:5000"
echo "Debug mode: ON"
echo "Auto-reload: ON"
echo "Press Ctrl+C to stop"

# Run Flask development server
python app.py
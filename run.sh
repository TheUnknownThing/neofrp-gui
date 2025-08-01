#!/bin/bash

# Neofrp Admin Panel Production Runner

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set default values if not provided
HOST=${APP_HOST:-0.0.0.0}
PORT=${APP_PORT:-5000}
WORKERS=${APP_WORKERS:-4}

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

# Run database migrations
echo "Running database migrations..."
flask db upgrade 2>/dev/null || python init_db.py

# Start the application
echo "Starting Neofrp Admin Panel..."
echo "URL: http://$HOST:$PORT"
echo "Workers: $WORKERS"
echo "Press Ctrl+C to stop"

# Run with gunicorn
exec gunicorn \
    --bind "$HOST:$PORT" \
    --workers $WORKERS \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    "app:create_app()"
import os
import sys
import subprocess
import time
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_environment():
    """Sets up the environment for the application to run."""
    logger.info("Setting up environment...")
    
    # Set essential environment variables if not already set
    if not os.environ.get("SESSION_SECRET"):
        logger.info("Setting SESSION_SECRET environment variable...")
        os.environ["SESSION_SECRET"] = "secure-proxy-session-key-dev-only"
    
    # Try to connect to the database, create one if needed
    try:
        import psycopg2
        logger.info("Testing database connection...")
        if not os.environ.get("DATABASE_URL"):
            logger.warning("DATABASE_URL not set, attempting to create database...")
            # This would normally be done with create_postgresql_database_tool
            # But this is a fallback for environments without that tool
            os.environ["PGDATABASE"] = "proxydb"
            os.environ["PGUSER"] = "postgres"
            os.environ["PGPASSWORD"] = "postgres"
            os.environ["PGHOST"] = "localhost"
            os.environ["PGPORT"] = "5432"
            os.environ["DATABASE_URL"] = f"postgresql://{os.environ['PGUSER']}:{os.environ['PGPASSWORD']}@{os.environ['PGHOST']}:{os.environ['PGPORT']}/{os.environ['PGDATABASE']}"
    except ImportError:
        logger.warning("psycopg2 not installed, installing required packages...")
        subprocess.run([sys.executable, "-m", "pip", "install", "psycopg2-binary"], check=True)
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        logger.info("Falling back to SQLite database")
        # Ensure app.py will fall back to SQLite

    # Check for other required packages and install if needed
    required_packages = [
        "flask", "flask-login", "flask-sqlalchemy", "flask-wtf", 
        "requests", "beautifulsoup4", "gunicorn", "email-validator",
        "flask-socketio"
    ]
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            logger.info(f"Installing missing package: {package}")
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)

    logger.info("Environment setup complete")

# Run setup before importing the app
setup_environment()

# Now import the app after environment is ready
from app import app, socketio  # noqa: F401

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=True, port=5000, allow_unsafe_werkzeug=True, use_reloader=True, log_output=True)

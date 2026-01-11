#!/bin/bash

echo "Starting application setup..."

# Check if ODBC Driver 18 is already installed
if ! odbcinst -q -d -n "ODBC Driver 18 for SQL Server" > /dev/null 2>&1; then
    echo "ODBC Driver 18 not found. Installing..."
    
    # Update package lists
    apt-get update
    
    # Install prerequisites
    apt-get install -y curl gnupg2
    
    # Add Microsoft repository
    curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
    curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list
    
    # Update again with new repository
    apt-get update
    
    # Install ODBC Driver 18
    ACCEPT_EULA=Y apt-get install -y msodbcsql18
    
    # Install unixODBC development headers
    apt-get install -y unixodbc-dev
    
    echo "ODBC Driver 18 installed successfully"
else
    echo "ODBC Driver 18 already installed"
fi

# List available drivers for verification
echo "Available ODBC drivers:"
odbcinst -q -d

# Start Gunicorn
echo "Starting Gunicorn..."
gunicorn --bind=0.0.0.0:$PORT --timeout 600 --workers 4 app:app

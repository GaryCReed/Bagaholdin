#!/bin/bash

echo "Setting up PostgreSQL for Msf-Web-Interface..."

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "PostgreSQL not found. Installing..."
    sudo apt update
    sudo apt install -y postgresql postgresql-contrib
fi

# Start PostgreSQL service
echo "Starting PostgreSQL service..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Wait for PostgreSQL to start
sleep 2

# Create database
echo "Creating database 'msf_web'..."
sudo -u postgres createdb msf_web 2>/dev/null || echo "Database may already exist"

# Set up user (optional)
echo "Setting up database user..."
sudo -u postgres psql -c "CREATE USER IF NOT EXISTS msf_user WITH PASSWORD 'msf_password';" 2>/dev/null
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE msf_web TO msf_user;" 2>/dev/null

echo "PostgreSQL setup complete!"
echo "You can now run: cd backend && go run ."
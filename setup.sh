#!/bin/bash

echo "📦 Installing Trivy vulnerability scanner..."

# Download and install the latest Trivy release for Linux
wget -q https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.50.0_Linux-64bit.deb -O trivy_latest.deb

if [ -f "trivy_latest.deb" ]; then
    sudo dpkg -i trivy_latest.deb
    rm trivy_latest.deb
    echo "✅ Trivy installed successfully."
else
    echo "❌ Failed to download Trivy."
    exit 1
fi

echo "🐍 Setting up Python environment..."

# Optionally create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python requirements
pip install --upgrade pip
pip install -r requirements.txt

echo "🚀 Launching the application..."

# Run the main Python file
python3 app.py

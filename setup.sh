#!/bin/bash

# Exit on error
set -e

echo "📦 Installing Trivy vulnerability scanner..."

# Check if Trivy is already installed
if command -v trivy &> /dev/null; then
    echo "✅ Trivy is already installed."
else
    # Download and install the latest Trivy release for Linux
    echo "Downloading Trivy..."
    wget -q https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.50.0_Linux-64bit.deb -O trivy_latest.deb

    if [ -f "trivy_latest.deb" ]; then
        echo "Installing Trivy..."
        sudo dpkg -i trivy_latest.deb
        rm trivy_latest.deb
        echo "✅ Trivy installed successfully."
    else
        echo "❌ Failed to download Trivy."
        exit 1
    fi
fi

echo "🐍 Setting up Python environment..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if (( $(echo "$python_version < 3.8" | bc -l) )); then
    echo "❌ Python version $python_version is not supported. Please install Python 3.8 or higher."
    exit 1
fi

# Create and activate virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python requirements
echo "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "❌ requirements.txt not found."
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️ Warning: .env file not found. Creating template..."
    echo "GROQ_API_KEY=your_groq_api_key_here" > .env
    echo "Please update the .env file with your actual Groq API key."
fi

echo "🚀 Launching the application..."

# Run the main Python file
if [ -f "app.py" ]; then
    python3 app.py
else
    echo "❌ app.py not found. Please ensure the file exists in the current directory."
    exit 1
fi

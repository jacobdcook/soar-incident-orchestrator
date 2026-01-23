#!/bin/bash

# SOAR-lite Startup Script
# This script handles Docker permissions and starts the application

echo "🚀 Starting SOAR-lite Orchestrator..."

# Check if user is in docker group
if groups | grep -q docker; then
    echo "✅ User has Docker permissions"
    DOCKER_CMD="docker-compose"
else
    echo "⚠️  User not in docker group. Using sudo (you may be prompted for password)"
    echo "💡 To fix permanently, run: sudo usermod -aG docker \$USER && newgrp docker"
    DOCKER_CMD="sudo docker-compose"
fi

# Check if Docker is running
if ! $DOCKER_CMD ps &>/dev/null; then
    echo "❌ Docker daemon is not running. Please start Docker first."
    exit 1
fi

# Start the services
echo "📦 Building and starting containers..."
$DOCKER_CMD up --build

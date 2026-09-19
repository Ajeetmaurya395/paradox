#!/bin/bash
# Paradox Setup Script for Linux/macOS

echo -e "\033[0;36m🚀 Setting up Paradox AI Security Platform...\033[0m"

# Check dependencies
if ! command -v python3 &> /dev/null; then
    echo -e "\033[0;31m❌ Python3 not found.\033[0m"
    exit 1
fi
if ! command -v npm &> /dev/null; then
    echo -e "\033[0;31m❌ npm not found.\033[0m"
    exit 1
fi

# 1. Backend
echo -e "\n\033[0;33m📦 Setting up Backend...\033[0m"
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp -n .env.example .env 2>/dev/null || true
cd ..

# 2. Frontend
echo -e "\n\033[0;33m📦 Setting up Frontend...\033[0m"
cd frontend
npm install
cd ..

echo -e "\n\033[0;32m✅ Setup Complete!\033[0m"
echo "To run the platform:"
echo "1. Start Ollama: ollama run qwen3.8:27b"
echo "2. Start Backend: cd backend && source venv/bin/activate && uvicorn app.main:app --reload"
echo "3. Start Frontend: cd frontend && npm run dev"

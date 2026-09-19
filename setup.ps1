<#
.SYNOPSIS
Paradox Setup Script for Windows (PowerShell)
#>

Write-Host "🚀 Setting up Paradox AI Security Platform..." -ForegroundColor Cyan

# Check dependencies
if (!(Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python not found. Please install Python 3.10+." -ForegroundColor Red
    exit 1
}
if (!(Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "❌ npm not found. Please install Node.js 18+." -ForegroundColor Red
    exit 1
}

# 1. Backend
Write-Host "`n📦 Setting up Backend..." -ForegroundColor Yellow
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env -ErrorAction SilentlyContinue
cd ..

# 2. Frontend
Write-Host "`n📦 Setting up Frontend..." -ForegroundColor Yellow
cd frontend
npm install
cd ..

Write-Host "`n✅ Setup Complete!" -ForegroundColor Green
Write-Host "To run the platform:"
Write-Host "1. Start Ollama (required for AI agents): ollama run qwen3.8:27b"
Write-Host "2. Start Backend: cd backend ; .\venv\Scripts\Activate.ps1 ; uvicorn app.main:app --reload"
Write-Host "3. Start Frontend: cd frontend ; npm run dev"

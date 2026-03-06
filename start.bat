@echo off
echo ================================
echo  PhishNet Backend Startup
echo ================================

REM Set your API key here
set ANTHROPIC_API_KEY=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 api key

REM Install dependencies
echo Installing dependencies...
pip install fastapi uvicorn scikit-learn numpy anthropic python-multipart

REM Start server
echo.
echo Starting PhishNet API server...
echo Backend will be at: http://localhost:8000
echo Frontend will be at: http://localhost:8000/app
echo.
uvicorn backend.app:app --reload --port 8000

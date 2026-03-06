@echo off
echo ================================
echo   PhishNet Backend Startup
echo ================================

REM Paste your Anthropic API key in backend/.env
REM Or set it here:
REM set ANTHROPIC_API_KEY=sk-ant-...

echo Installing dependencies...
pip install fastapi uvicorn[standard] scikit-learn numpy anthropic python-multipart python-dotenv

echo.
echo Starting PhishNet...
echo   API  → http://localhost:8000
echo   App  → http://localhost:8000/app
echo   Docs → http://localhost:8000/docs
echo.
uvicorn backend.app:app --reload --port 8000

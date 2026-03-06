#!/bin/bash
echo "================================"
echo "  PhishNet Backend Startup"
echo "================================"
pip install fastapi "uvicorn[standard]" scikit-learn numpy anthropic python-multipart python-dotenv
echo ""
echo "Starting PhishNet..."
echo "  API  → http://localhost:8000"
echo "  App  → http://localhost:8000/app"
echo ""
uvicorn backend.app:app --reload --port 8000

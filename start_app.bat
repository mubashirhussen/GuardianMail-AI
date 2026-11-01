@echo off
title GuardianMail AI - Full Stack Launcher
color 0A

echo ==========================================================
echo        GUARDIANMAIL AI - STARTING FULL APPLICATION
echo ==========================================================
echo.
echo [1/3] Checking MongoDB Database...
powershell -Command "if ((Get-Service -Name '*mongo*' -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}).Count -eq 0) { Start-Service MongoDB -ErrorAction SilentlyContinue }"
echo [OK] Database service active.
echo.

echo [2/3] Launching Backend API (FastAPI Port 8000)...
start "GuardianMail Backend (Port 8000)" cmd /k "cd /d %~dp0backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

echo [3/3] Launching Frontend Dashboard (Vite Port 3000)...
start "GuardianMail Frontend (Port 3000)" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ==========================================================
echo  GuardianMail AI is running!
echo  - Frontend Dashboard: http://localhost:3000
echo  - Backend API:        http://127.0.0.1:8000/docs
echo ==========================================================
timeout /t 5 >nul
start http://localhost:3000


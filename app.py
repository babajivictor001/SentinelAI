from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os

from src.analyzer import analyze_logs
from src.threat_engine import calculate_risk

# =====================================================
# FastAPI Configuration
# =====================================================

app = FastAPI(
    title="SentinelAI API",
    description="AI Powered Cybersecurity Log Analysis API",
    version="1.0.0"
)

# =====================================================
# Enable CORS (Allows Lovable Frontend to connect)
# =====================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Change later for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================
# Ensure Logs Folder Exists
# =====================================================

UPLOAD_FOLDER = "logs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# =====================================================
# HOME
# =====================================================

@app.get("/")
def home():

    return {
        "application": "SentinelAI",
        "version": "1.0.0",
        "status": "Running",
        "message": "Welcome to SentinelAI API"
    }

# =====================================================
# HEALTH CHECK
# =====================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "server": "online"
    }

# =====================================================
# ANALYZE DEFAULT SAMPLE LOG
# =====================================================

@app.get("/analyze")
def analyze():

    logfile = "logs/sample_log.txt"

    if not os.path.exists(logfile):
        raise HTTPException(
            status_code=404,
            detail="sample_log.txt not found."
        )

    with open(logfile, "r") as file:
        results = analyze_logs(file)

    risk = calculate_risk(results)

    return {

        "total_events": results["total_events"],

        "info_events": results["info"],

        "warning_events": results["warning"],

        "error_events": results["error"],

        "critical_events": results["critical"],

        "failed_logins": results["failed_logins"],

        "suspicious_ips": list(results["suspicious_ips"]),

        "login_attempts": results["login_attempts"],

        "risk_level": risk["level"],

        "risk_score": risk["score"]

    }

# =====================================================
# UPLOAD LOG FILE
# =====================================================

@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):

    filepath = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    with open(filepath, "r") as logfile:
        results = analyze_logs(logfile)

    risk = calculate_risk(results)

    return {
        "filename": file.filename,
        "analysis": results,
        "risk": risk
    }
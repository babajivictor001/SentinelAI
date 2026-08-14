from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import shutil
import os

from src.analyzer import analyze_logs
from src.threat_engine import calculate_risk


# ============================================================
# FastAPI Configuration
# ============================================================

app = FastAPI(
    title="SentinelAI API",
    description="AI Powered Cybersecurity Log Analysis API",
    version="1.0.0"
)


# ============================================================
# CORS Configuration
# Allows Lovable frontend to communicate with the API
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Configuration
# ============================================================

UPLOAD_FOLDER = "logs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "application": "SentinelAI",
        "version": "1.0.0",
        "status": "Running",
        "message": "Welcome to SentinelAI API"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "server": "online"
    }


# ============================================================
# ANALYZE DEFAULT SAMPLE LOG
# ============================================================

@app.get("/analyze")
def analyze():

    try:

        logfile = os.path.join(
            UPLOAD_FOLDER,
            "sample_log.txt"
        )

        # ----------------------------------------------------
        # Check if sample log exists
        # ----------------------------------------------------

        if not os.path.exists(logfile):

            raise HTTPException(
                status_code=404,
                detail="sample_log.txt not found."
            )

        # ----------------------------------------------------
        # Read log file
        # ----------------------------------------------------

        with open(logfile, "r", encoding="utf-8") as file:

            results = analyze_logs(file)

        # ----------------------------------------------------
        # Calculate security risk
        # ----------------------------------------------------

        risk = calculate_risk(results)

        # ----------------------------------------------------
        # Return clean API response
        # ----------------------------------------------------

        return {

            "status": "success",

            "analysis": {

                "total_events": results.get(
                    "total_events",
                    0
                ),

                "info_events": results.get(
                    "info",
                    0
                ),

                "warning_events": results.get(
                    "warning",
                    0
                ),

                "error_events": results.get(
                    "error",
                    0
                ),

                "critical_events": results.get(
                    "critical",
                    0
                ),

                "failed_logins": results.get(
                    "failed_logins",
                    0
                ),

                "suspicious_ips": results.get(
                    "suspicious_ips",
                    []
                ),

                "login_attempts": results.get(
                    "login_attempts",
                    {}
                )

            },

            "risk": {

                "level": risk.get(
                    "level",
                    "UNKNOWN"
                ),

                "score": risk.get(
                    "score",
                    0
                )

            }

        }

    except HTTPException:

        raise

    except Exception as e:

        return {

            "status": "error",

            "error": type(e).__name__,

            "message": str(e)

        }


# ============================================================
# UPLOAD AND ANALYZE LOG FILE
# ============================================================

@app.post("/upload-log")
async def upload_log(
    file: UploadFile = File(...)
):

    try:

        # ----------------------------------------------------
        # Validate file
        # ----------------------------------------------------

        if not file.filename:

            raise HTTPException(
                status_code=400,
                detail="No file selected."
            )

        # ----------------------------------------------------
        # Create safe filename
        # ----------------------------------------------------

        filename = os.path.basename(
            file.filename
        )

        filepath = os.path.join(
            UPLOAD_FOLDER,
            filename
        )

        # ----------------------------------------------------
        # Save uploaded file
        # ----------------------------------------------------

        with open(filepath, "wb") as buffer:

            shutil.copyfileobj(
                file.file,
                buffer
            )

        # ----------------------------------------------------
        # Analyze uploaded log
        # ----------------------------------------------------

        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as logfile:

            results = analyze_logs(
                logfile
            )

        # ----------------------------------------------------
        # Calculate risk
        # ----------------------------------------------------

        risk = calculate_risk(
            results
        )

        # ----------------------------------------------------
        # Return analysis
        # ----------------------------------------------------

        return {

            "status": "success",

            "filename": filename,

            "analysis": {

                "total_events": results.get(
                    "total_events",
                    0
                ),

                "info_events": results.get(
                    "info",
                    0
                ),

                "warning_events": results.get(
                    "warning",
                    0
                ),

                "error_events": results.get(
                    "error",
                    0
                ),

                "critical_events": results.get(
                    "critical",
                    0
                ),

                "failed_logins": results.get(
                    "failed_logins",
                    0
                ),

                "suspicious_ips": results.get(
                    "suspicious_ips",
                    []
                ),

                "login_attempts": results.get(
                    "login_attempts",
                    {}
                )

            },

            "risk": {

                "level": risk.get(
                    "level",
                    "UNKNOWN"
                ),

                "score": risk.get(
                    "score",
                    0
                )

            }

        }

    except HTTPException:

        raise

    except Exception as e:

        return {

            "status": "error",

            "error": type(e).__name__,

            "message": str(e)

        }
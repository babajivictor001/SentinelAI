from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import shutil
import os

from src.analyzer import analyze_logs
from src.threat_engine import calculate_risk
from src.detection_engine import detect_attacks
from src.ioc_extractor import extract_iocs
from src.mitre_mapping import map_detections_to_mitre
from src.enrichment import enrich_security_findings


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

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ============================================================
# INTERNAL ANALYSIS PIPELINE
# ============================================================

def process_log(file_path: str):

    # --------------------------------------------------------
    # Read log
    # --------------------------------------------------------

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as logfile:

        results = analyze_logs(
            logfile
        )

    # --------------------------------------------------------
    # Calculate risk
    # --------------------------------------------------------

    risk = calculate_risk(
        results
    )

    # --------------------------------------------------------
    # Detect attacks
    # --------------------------------------------------------

    detections = detect_attacks(
        results.get(
            "lines",
            []
        ),
        results.get(
            "login_attempts",
            {}
        ),
        results.get(
            "failed_logins",
            0
        )
    )

    # --------------------------------------------------------
    # Extract IOCs
    # --------------------------------------------------------

    iocs = extract_iocs(
        results.get(
            "lines",
            []
        )
    )

    # --------------------------------------------------------
    # MITRE ATT&CK mapping
    # --------------------------------------------------------

    mitre_attack = map_detections_to_mitre(
        detections
    )

    # --------------------------------------------------------
    # Security enrichment
    # --------------------------------------------------------

    enrichment = enrich_security_findings(
        detections=detections,
        risk=risk,
        iocs=iocs,
        mitre_attack=mitre_attack
    )

    return (
        results,
        risk,
        detections,
        iocs,
        mitre_attack,
        enrichment
    )


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

        if not os.path.exists(logfile):

            raise HTTPException(
                status_code=404,
                detail="sample_log.txt not found."
            )

        (
            results,
            risk,
            detections,
            iocs,
            mitre_attack,
            enrichment
        ) = process_log(
            logfile
        )

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

            },

            "detections": detections,

            "iocs": iocs,

            "mitre_attack": mitre_attack,

            "enrichment": enrichment

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
        # Safe filename
        # ----------------------------------------------------

        filename = os.path.basename(
            file.filename
        )

        filepath = os.path.join(
            UPLOAD_FOLDER,
            filename
        )

        # ----------------------------------------------------
        # Save uploaded log
        # ----------------------------------------------------

        with open(
            filepath,
            "wb"
        ) as buffer:

            shutil.copyfileobj(
                file.file,
                buffer
            )

        # ----------------------------------------------------
        # Process uploaded log
        # ----------------------------------------------------

        (
            results,
            risk,
            detections,
            iocs,
            mitre_attack,
            enrichment
        ) = process_log(
            filepath
        )

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

            },

            "detections": detections,

            "iocs": iocs,

            "mitre_attack": mitre_attack,

            "enrichment": enrichment

        }

    except HTTPException:

        raise

    except Exception as e:

        return {

            "status": "error",

            "error": type(e).__name__,

            "message": str(e)

        }
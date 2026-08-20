from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import os
import shutil

from src.analyzer import analyze_logs
from src.threat_engine import calculate_risk
from src.detection_engine import detect_attacks
from src.ioc_extractor import extract_iocs
from src.mitre_mapping import map_detections_to_mitre
from src.enrichment import enrich_security_findings
from src.ai_analyst import generate_ai_assessment


# ============================================================
# FastAPI Configuration
# ============================================================

app = FastAPI(
    title="SentinelAI API",
    description="AI Powered Cybersecurity Log Analysis API",
    version="2.0.0"
)


# ============================================================
# CORS
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
# BUILD SECURITY REPORT
# ============================================================

def build_security_report(results, lines):

    # --------------------------------------------------------
    # 1. Calculate risk
    # --------------------------------------------------------

    risk = calculate_risk(
        results
    )

    # --------------------------------------------------------
    # 2. Detect attacks
    # --------------------------------------------------------

    detections = detect_attacks(
        lines,
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
    # 3. Extract IOCs
    # --------------------------------------------------------

    iocs = extract_iocs(
        lines
    )

    # --------------------------------------------------------
    # 4. Map detections to MITRE ATT&CK
    # --------------------------------------------------------

    mitre_attack = map_detections_to_mitre(
        detections
    )

    # --------------------------------------------------------
    # 5. Enrich security findings
    #
    # IMPORTANT:
    # enrich_security_findings() expects exactly:
    #
    # detections
    # risk
    # iocs
    # mitre_attack
    # --------------------------------------------------------

    enrichment = enrich_security_findings(
        detections=detections,
        risk=risk,
        iocs=iocs,
        mitre_attack=mitre_attack
    )

    # --------------------------------------------------------
    # 6. AI SOC assessment
    # --------------------------------------------------------

    ai_assessment = generate_ai_assessment(
        results,
        risk,
        detections,
        iocs,
        mitre_attack,
        enrichment
    )

    # --------------------------------------------------------
    # 7. Return complete SentinelAI report
    # --------------------------------------------------------

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

        "enrichment": enrichment,

        "ai_assessment": ai_assessment
    }


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {

        "application": "SentinelAI",

        "version": "2.0.0",

        "status": "Running",

        "message": (
            "SentinelAI cybersecurity "
            "analysis API is running."
        )
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
# ANALYZE SAMPLE LOG
# ============================================================

@app.get("/analyze")
def analyze():

    try:

        logfile = os.path.join(
            UPLOAD_FOLDER,
            "sample_log.txt"
        )

        if not os.path.exists(
            logfile
        ):

            raise HTTPException(
                status_code=404,
                detail="sample_log.txt not found."
            )

        # ----------------------------------------------------
        # Read log
        # ----------------------------------------------------

        with open(
            logfile,
            "r",
            encoding="utf-8"
        ) as file:

            lines = file.readlines()

        # ----------------------------------------------------
        # Analyze
        # ----------------------------------------------------

        results = analyze_logs(
            lines
        )

        # ----------------------------------------------------
        # Build report
        # ----------------------------------------------------

        return build_security_report(
            results,
            lines
        )

    except HTTPException:

        raise

    except Exception as exc:

        return {

            "status": "error",

            "error": type(exc).__name__,

            "message": str(exc)
        }


# ============================================================
# UPLOAD AND ANALYZE LOG
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
        # Save file
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
        # Read file
        # ----------------------------------------------------

        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as logfile:

            lines = logfile.readlines()

        # ----------------------------------------------------
        # Analyze
        # ----------------------------------------------------

        results = analyze_logs(
            lines
        )

        # ----------------------------------------------------
        # Build complete report
        # ----------------------------------------------------

        report = build_security_report(
            results,
            lines
        )

        # ----------------------------------------------------
        # Add filename
        # ----------------------------------------------------

        report["filename"] = filename

        return report

    except HTTPException:

        raise

    except Exception as exc:

        return {

            "status": "error",

            "error": type(exc).__name__,

            "message": str(exc)
        }
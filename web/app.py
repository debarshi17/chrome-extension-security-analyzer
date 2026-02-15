"""
Chrome Extension Security Analyzer - Web Interface
FastAPI backend for analyzing Chrome extensions
"""

import sys
import os
import re
import asyncio
from pathlib import Path
from typing import Optional

# Get project root directory
PROJECT_ROOT = Path(__file__).parent.parent.resolve()

# Add src directory to path for imports
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

# Change working directory to project root so analyzer finds config.json
os.chdir(PROJECT_ROOT)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn

# Import analyzer components
from analyzer import ChromeExtensionAnalyzer

app = FastAPI(
    title="Chrome Extension Security Analyzer",
    description="Analyze Chrome extensions for malicious code patterns",
    version="1.0.0"
)

# Templates
templates = Jinja2Templates(directory=PROJECT_ROOT / "web" / "templates")

# Reports directory
REPORTS_DIR = PROJECT_ROOT / "reports"

# Store for tracking analysis jobs
analysis_jobs = {}


class AnalysisCancelledError(Exception):
    """Raised when user cancels an analysis job."""


class AnalysisRequest(BaseModel):
    extension_id: str


class AnalysisStatus(BaseModel):
    status: str
    message: str
    report_url: Optional[str] = None


def validate_extension_id(extension_id: str) -> bool:
    """Validate Chrome extension ID format (32 lowercase letters)"""
    return bool(re.match(r'^[a-z]{32}$', extension_id))


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the home page with analysis form"""
    return templates.TemplateResponse("index.html", {"request": request})


def _run_analysis(extension_id: str):
    """Background task: run analysis and update progress in analysis_jobs"""
    def progress_callback(percent: int, step_name: str, detail: str):
        if extension_id not in analysis_jobs:
            return
        status = analysis_jobs[extension_id].get("status")
        if status == "cancelled":
            raise AnalysisCancelledError("Analysis cancelled by user")
        if status == "running":
            analysis_jobs[extension_id]["percent"] = percent
            analysis_jobs[extension_id]["step_name"] = step_name
            analysis_jobs[extension_id]["detail"] = detail
            analysis_jobs[extension_id]["message"] = f"{step_name}: {detail}" if detail else step_name

    try:
        analyzer = ChromeExtensionAnalyzer()
        results = analyzer.analyze_extension(extension_id, progress_callback=progress_callback)

        if results:
            report_path = REPORTS_DIR / f"{extension_id}_threat_analysis_report.html"
            if report_path.exists():
                analysis_jobs[extension_id] = {
                    "status": "complete",
                    "message": "Analysis complete",
                    "report_url": f"/report/{extension_id}",
                    "risk_score": results.get("risk_score", 0),
                    "risk_level": results.get("risk_level", "UNKNOWN"),
                    "percent": 100,
                    "step_name": "Complete",
                    "detail": "Analysis finished."
                }
                return
        analysis_jobs[extension_id] = {
            "status": "error",
            "message": "Analysis failed - extension may not exist or is not accessible"
        }
    except AnalysisCancelledError:
        analysis_jobs[extension_id] = {
            "status": "cancelled",
            "message": "Analysis cancelled by user"
        }
    except Exception as e:
        analysis_jobs[extension_id] = {
            "status": "error",
            "message": str(e)
        }


@app.post("/analyze", response_class=JSONResponse)
async def analyze_extension(req: AnalysisRequest, background_tasks: BackgroundTasks):
    """Start analysis of a Chrome extension (runs in background, returns immediately)"""

    extension_id = req.extension_id.strip().lower()

    # Validate extension ID
    if not validate_extension_id(extension_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid extension ID. Must be 32 lowercase letters."
        )

    # Check if already analyzing
    if extension_id in analysis_jobs and analysis_jobs[extension_id]["status"] == "running":
        return {"status": "running", "extension_id": extension_id}

    # Mark as running and schedule background analysis
    analysis_jobs[extension_id] = {
        "status": "running",
        "message": "Starting analysis...",
        "percent": 0,
        "step_name": "Initializing",
        "detail": "Fetching extension metadata..."
    }

    background_tasks.add_task(_run_analysis, extension_id)

    return {"status": "running", "extension_id": extension_id}


@app.get("/status/{extension_id}")
async def get_status(extension_id: str):
    """Get analysis status for an extension"""
    extension_id = extension_id.strip().lower()
    if extension_id not in analysis_jobs:
        return {"status": "not_found", "message": "No analysis found for this extension"}
    out = dict(analysis_jobs[extension_id])
    out["extension_id"] = extension_id
    out["report_url"] = f"/report/{extension_id}"
    return out


@app.post("/cancel/{extension_id}")
async def cancel_analysis(extension_id: str):
    """Cancel a running analysis job"""
    extension_id = extension_id.strip().lower()
    if not validate_extension_id(extension_id):
        raise HTTPException(status_code=400, detail="Invalid extension ID")
    if extension_id not in analysis_jobs:
        return {"status": "not_found", "message": "No analysis found for this extension"}
    if analysis_jobs[extension_id].get("status") != "running":
        return {"status": "already_done", "message": f"Job is not running (status: {analysis_jobs[extension_id].get('status')})"}

    analysis_jobs[extension_id]["status"] = "cancelled"
    analysis_jobs[extension_id]["message"] = "Cancelling..."
    return {"status": "cancelled", "message": "Cancellation requested. Analysis will stop at next checkpoint."}


@app.get("/report/{extension_id}", response_class=HTMLResponse)
async def get_report(extension_id: str):
    """Get the HTML report for an analyzed extension"""

    if not validate_extension_id(extension_id):
        raise HTTPException(status_code=400, detail="Invalid extension ID")

    report_path = REPORTS_DIR / f"{extension_id}_threat_analysis_report.html"

    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found. Run analysis first.")

    return FileResponse(report_path, media_type="text/html")


@app.get("/api/recent")
async def get_recent_scans():
    """Get list of recent extension scans (last 5 only). Uses threat_analysis_report.html."""
    if not REPORTS_DIR.exists():
        return {"scans": []}

    reports = []
    for report in REPORTS_DIR.glob("*_threat_analysis_report.html"):
        ext_id = report.stem.replace("_threat_analysis_report", "")
        reports.append({
            "extension_id": ext_id,
            "report_url": f"/report/{ext_id}",
            "mtime": report.stat().st_mtime
        })
    reports.sort(key=lambda x: x["mtime"], reverse=True)
    for r in reports:
        r.pop("mtime", None)
    return {"scans": reports[:5]}


if __name__ == "__main__":
    # Ensure reports directory exists
    REPORTS_DIR.mkdir(exist_ok=True)

    print("\n" + "="*50)
    print("Chrome Extension Security Analyzer - Web Interface")
    print("="*50)
    print(f"\nProject root: {PROJECT_ROOT}")
    print("\nStarting server at http://localhost:8000")
    print("Open your browser and go to http://localhost:8000\n")

    uvicorn.run(app, host="0.0.0.0", port=8000)

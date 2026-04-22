"""
AzureGuard - FastAPI Backend
REST API serving compliance data to the dashboard.
"""

import json
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from collector.azure_collector import AzureCollector
from alerts.compliance_engine import ComplianceEngine
from alerts.alert_manager import AlertManager

DB_PATH = "data/azureguard.db"


def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collected_at TEXT NOT NULL,
            resource_count INTEGER,
            compliance_score INTEGER,
            data TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER,
            rule_id TEXT,
            rule_name TEXT,
            resource_name TEXT,
            resource_type TEXT,
            passed INTEGER,
            severity TEXT,
            message TEXT,
            remediation TEXT,
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
        )
    """)
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AzureGuard API",
    description="Azure cloud compliance monitoring API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="dashboard"), name="static")


# ── Models ─────────────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    snapshot_id: int
    collected_at: str
    resource_count: int
    compliance_score: int
    passed: int
    failed: int


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/")
def serve_dashboard():
    return FileResponse("dashboard/index.html")


@app.post("/api/scan", response_model=ScanResponse, tags=["Scan"])
def run_scan():
    """Trigger a full Azure resource scan and compliance evaluation."""
    try:
        collector = AzureCollector()
        snapshots = collector.collect_all_resources()
        snap_dicts = [s.__dict__ for s in snapshots]

        engine = ComplianceEngine()
        results = engine.evaluate(snap_dicts)
        score = engine.compute_score(results)

        conn = sqlite3.connect(DB_PATH)
        now = datetime.utcnow().isoformat()
        cur = conn.execute(
            "INSERT INTO snapshots (collected_at, resource_count, compliance_score, data) VALUES (?,?,?,?)",
            (now, len(snapshots), score["score"], json.dumps(snap_dicts)),
        )
        snapshot_id = cur.lastrowid

        for r in results:
            conn.execute(
                "INSERT INTO compliance_results VALUES (NULL,?,?,?,?,?,?,?,?,?)",
                (snapshot_id, r.rule_id, r.rule_name, r.resource_name,
                 r.resource_type, int(r.passed), r.severity.value, r.message, r.remediation),
            )
        conn.commit()
        conn.close()

        # Send alert email for failures
        AlertManager().send_alert_digest(results, score)

        return ScanResponse(
            snapshot_id=snapshot_id,
            collected_at=now,
            resource_count=len(snapshots),
            compliance_score=score["score"],
            passed=score["passed"],
            failed=score["failed"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/score", tags=["Dashboard"])
def get_latest_score():
    """Return the latest compliance score."""
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, collected_at, resource_count, compliance_score FROM snapshots ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not row:
        return {"score": None, "message": "No scans yet. Run POST /api/scan first."}
    return {"snapshot_id": row[0], "collected_at": row[1], "resource_count": row[2], "score": row[3]}


@app.get("/api/resources", tags=["Dashboard"])
def get_resources(snapshot_id: int = None):
    """Return resources from the latest (or specified) snapshot."""
    conn = sqlite3.connect(DB_PATH)
    if snapshot_id:
        row = conn.execute("SELECT data FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
    else:
        row = conn.execute("SELECT data FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if not row:
        return []
    return json.loads(row[0])


@app.get("/api/compliance", tags=["Dashboard"])
def get_compliance_results(snapshot_id: int = None, severity: str = None, passed: bool = None):
    """Return compliance results, with optional filtering."""
    conn = sqlite3.connect(DB_PATH)

    if not snapshot_id:
        snap = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        snapshot_id = snap[0] if snap else None

    if not snapshot_id:
        conn.close()
        return []

    query = "SELECT * FROM compliance_results WHERE snapshot_id=?"
    params = [snapshot_id]

    if severity:
        query += " AND severity=?"
        params.append(severity)
    if passed is not None:
        query += " AND passed=?"
        params.append(int(passed))

    rows = conn.execute(query, params).fetchall()
    conn.close()

    cols = ["id", "snapshot_id", "rule_id", "rule_name", "resource_name",
            "resource_type", "passed", "severity", "message", "remediation"]
    return [dict(zip(cols, r)) for r in rows]


@app.get("/api/history", tags=["Dashboard"])
def get_scan_history(limit: int = 10):
    """Return scan history for trend charts."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, collected_at, resource_count, compliance_score FROM snapshots ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [{"id": r[0], "collected_at": r[1], "resource_count": r[2], "score": r[3]} for r in reversed(rows)]


@app.get("/api/summary", tags=["Dashboard"])
def get_summary():
    """Return compliance breakdown by severity for the latest scan."""
    conn = sqlite3.connect(DB_PATH)
    snap = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    if not snap:
        conn.close()
        return {}

    rows = conn.execute(
        "SELECT severity, passed, COUNT(*) FROM compliance_results WHERE snapshot_id=? GROUP BY severity, passed",
        (snap[0],)
    ).fetchall()
    conn.close()

    summary = {}
    for sev, passed, count in rows:
        if sev not in summary:
            summary[sev] = {"passed": 0, "failed": 0}
        key = "passed" if passed else "failed"
        summary[sev][key] += count

    return summary


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

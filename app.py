from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

load_dotenv()

app = FastAPI(title="welo-threat-intel-api", version="2.4.1")

API_KEY = os.getenv("WELO_API_KEY", "dev-api-key")
MODEL_VERSION = "3.1"
THRESHOLDS = {
    "low": 3.0,
    "medium": 6.0,
    "high": 8.5,
    "critical": 9.5,
}
WEIGHTS = {
    "identity_anomaly": 0.35,
    "malware_match": 0.40,
    "vulnerability_exposure": 0.25,
}

THREATS = [
    {
        "id": "threat-1",
        "indicator": "hash:3f786850e387550fdab836ed7e6dc881de23001b",
        "severity": "high",
        "source": "welo-malware-feed",
    },
    {
        "id": "threat-2",
        "indicator": "domain:bad-example[.]com",
        "severity": "medium",
        "source": "welo-cve-feed",
    },
]

VULNERABILITIES = [
    {"id": "CVE-2026-0001", "severity": "critical", "score": 9.9},
    {"id": "CVE-2026-0042", "severity": "high", "score": 8.7},
    {"id": "CVE-2026-0123", "severity": "medium", "score": 6.4},
]


class ThreatIngestRequest(BaseModel):
    indicators: list[str] = Field(..., min_length=1)
    source: str = Field(..., min_length=2)


class RiskScoreRequest(BaseModel):
    identity_anomaly: float = Field(..., ge=0, le=10)
    malware_match: float = Field(..., ge=0, le=10)
    vulnerability_exposure: float = Field(..., ge=0, le=10)


class RiskScoreResponse(BaseModel):
    score: float
    level: Literal["low", "medium", "high", "critical"]
    model_version: str


def require_api_key(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/threats", dependencies=[Depends(require_api_key)])
def list_threats(severity: str | None = Query(default=None)) -> dict[str, object]:
    if severity:
        data = [t for t in THREATS if t["severity"] == severity]
    else:
        data = THREATS
    return {"count": len(data), "items": data}


@app.get("/v1/threats/{threat_id}", dependencies=[Depends(require_api_key)])
def get_threat(threat_id: str) -> dict[str, object]:
    for threat in THREATS:
        if threat["id"] == threat_id:
            return threat
    raise HTTPException(status_code=404, detail="Threat not found")


@app.post("/v1/threats/ingest", dependencies=[Depends(require_api_key)])
def ingest_threats(payload: ThreatIngestRequest) -> dict[str, object]:
    ts = datetime.now(timezone.utc).isoformat()
    created = []
    for idx, indicator in enumerate(payload.indicators, start=1):
        tid = f"ingested-{len(THREATS) + idx}"
        threat = {
            "id": tid,
            "indicator": indicator,
            "severity": "medium",
            "source": payload.source,
            "ingested_at": ts,
        }
        created.append(threat)
    THREATS.extend(created)
    return {"ingested": len(created), "items": created}


@app.get("/v1/vulnerabilities", dependencies=[Depends(require_api_key)])
def list_vulnerabilities(severity: str | None = Query(default=None)) -> dict[str, object]:
    if severity:
        data = [v for v in VULNERABILITIES if v["severity"] == severity]
    else:
        data = VULNERABILITIES
    return {"count": len(data), "items": data}


def score_level(score: float) -> Literal["low", "medium", "high", "critical"]:
    if score >= THRESHOLDS["critical"]:
        return "critical"
    if score >= THRESHOLDS["high"]:
        return "high"
    if score >= THRESHOLDS["medium"]:
        return "medium"
    return "low"


@app.post("/v1/identity/risk-score", response_model=RiskScoreResponse, dependencies=[Depends(require_api_key)])
def identity_risk_score(payload: RiskScoreRequest) -> RiskScoreResponse:
    score = (
        payload.identity_anomaly * WEIGHTS["identity_anomaly"]
        + payload.malware_match * WEIGHTS["malware_match"]
        + payload.vulnerability_exposure * WEIGHTS["vulnerability_exposure"]
    )
    score = round(score, 2)
    return RiskScoreResponse(score=score, level=score_level(score), model_version=MODEL_VERSION)

from fastapi.testclient import TestClient

from app import app


client = TestClient(app)
HEADERS = {"X-API-Key": "dev-api-key"}


def test_healthcheck():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_requires_api_key():
    response = client.get("/v1/threats")
    assert response.status_code == 401


def test_list_threats():
    response = client.get("/v1/threats", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1


def test_get_single_threat_not_found():
    response = client.get("/v1/threats/not-real", headers=HEADERS)
    assert response.status_code == 404


def test_ingest_threats():
    payload = {
        "indicators": ["ip:203.0.113.10", "hash:abc123"],
        "source": "manual-upload",
    }
    response = client.post("/v1/threats/ingest", json=payload, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["ingested"] == 2


def test_vulnerability_filter():
    response = client.get("/v1/vulnerabilities", params={"severity": "critical"}, headers=HEADERS)
    assert response.status_code == 200
    items = response.json()["items"]
    assert all(item["severity"] == "critical" for item in items)


def test_identity_risk_score():
    payload = {
        "identity_anomaly": 7.0,
        "malware_match": 10.0,
        "vulnerability_exposure": 8.0,
    }
    response = client.post("/v1/identity/risk-score", json=payload, headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["model_version"] == "3.1"
    assert body["level"] in {"high", "critical"}

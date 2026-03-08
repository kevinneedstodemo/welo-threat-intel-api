# welo-threat-intel-api

A RESTful API service for Welo's internal threat intelligence platform,
enabling real-time malware signature distribution, vulnerability feed
aggregation, and identity risk scoring across Welo's security product suite.

---

## Overview

This service powers the backend data pipeline for Welo's malware prevention
and vulnerability detection products. It normalizes threat data from multiple
upstream feeds, enriches records with Welo's proprietary risk scoring model,
and exposes endpoints consumed by both the customer-facing dashboard and
internal security operations tooling.

---

## Features

- Real-time ingestion of CVE and threat indicator feeds
- Identity risk scoring engine (integrates with Welo IAM hardware/software)
- Malware signature deduplication and versioning
- Webhook support for downstream alerting and SIEM integrations
- Role-based API key management

---

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 7.x (for feed caching)

### Installation

```bash
git clone https://github.com/kevinneedstodemo/welo-threat-intel-api.git
cd welo-threat-intel-api
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Configuration

Update `.env` with your environment values:

```dotenv
WELO_API_KEY=your_api_key_here
DB_HOST=localhost
DB_PORT=5432
REDIS_URL=redis://localhost:6379
```

### Running Locally

```bash
uvicorn app:app --host 0.0.0.0 --port 8080 --reload
```

The API will be available at `http://localhost:8080`.

### Running Tests

```bash
pytest
```

---

## API Reference

All `/v1/*` endpoints require an `X-API-Key` header.

| Method | Endpoint                  | Description                        |
|--------|---------------------------|------------------------------------|
| GET    | /v1/threats               | List active threat indicators      |
| GET    | /v1/threats/{id}          | Get threat detail by ID            |
| POST   | /v1/threats/ingest        | Submit new threat indicators       |
| GET    | /v1/vulnerabilities       | List CVEs by severity              |
| POST   | /v1/identity/risk-score   | Score an identity access request   |

---

## Contributing

Internal contributions only. See `contributing.md` for branch naming
conventions and PR review requirements.

---

## License

MIT License. See `LICENSE` for details.

---

*Welo High Tech — Modernizing Digital Security Strategy*

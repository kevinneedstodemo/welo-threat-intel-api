# Contributing to welo-threat-intel-api

Internal Welo contributors only.

## Branch Naming

- `feat/` — new features (e.g. `feat/add-stix2-parser`)
- `fix/` — bug fixes (e.g. `fix/redis-cache-ttl`)
- `chore/` — maintenance (e.g. `chore/update-dependencies`)
- `hotfix/` — urgent production fixes

## Pull Requests

- All PRs require at least **1 reviewer** from the Security Platform team
- Link the relevant Jira ticket in your PR description
- Squash commits before merging to `main`

## Code Style

- Follow PEP 8
- Run `flake8` before submitting
- All new endpoints must include unit tests with >80% coverage

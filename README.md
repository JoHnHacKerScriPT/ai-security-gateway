# AI Security Gateway

Async security reverse proxy in front of AI provider APIs (Anthropic, OpenAI)
that enforces authentication, rate limiting, prompt-injection defense, PII/DLP
redaction, secret-leak scanning, and security observability.

## Architecture

```
Client
  │
  ▼
[1] AppSec Core        FastAPI async engine, JWT/API-key auth, Redis token-bucket rate limiting
  │
  ▼
[2] Input Guardrails    Prompt-injection/jailbreak inspector, PII/DLP redaction, token-bound validation
  │
  ▼
[3] Secure Routing      Secrets isolation, TLS reverse proxy to Anthropic/OpenAI, timeouts, retries
  │
  ▼
[4] Output Inspection   Secret/credential leak scanner, insecure-code guard
  │
  ▼
[5] Observability       Structured JSON security logs, Prometheus metrics
```

## Status

Being built incrementally, layer by layer. See the project task list for current progress.

## Local development

```bash
cp .env.example .env        # fill in real ANTHROPIC_API_KEY / OPENAI_API_KEY and a real JWT_SECRET
docker compose up --build
```

The gateway listens on `http://localhost:8000`. Redis runs alongside it for rate limiting.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Security tooling

- `bandit -r app` — static application security testing (SAST)
- `ruff check .` — linting
- GitHub Actions workflow (`.github/workflows/security.yml`) runs both on every push/PR.

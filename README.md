# Secure Auth Service
[![Continuous Integration](https://github.com/srijansrivastava1234/secure-auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/srijansrivastava1234/secure-auth-service/actions/workflows/ci.yml)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
![PostgreSQL 15](https://img.shields.io/badge/PostgreSQL-15-336791.svg)
![Redis 7](https://img.shields.io/badge/Redis-7-DC382D.svg)
![Alembic](https://img.shields.io/badge/Alembic-Migrations-orange.svg)

A production-hardened authentication and authorization microservice engineered with **FastAPI**, **PostgreSQL 15**, **Redis 7**, **Alembic**, and **PyJWT**. Features granular Role-Based Access Control (RBAC), distributed rate-limiting, fail-closed stateful JWT token revocation on logout, and automated GitHub Actions CI executing integration tests against live PostgreSQL.

---

## 🏗️ Architecture & Component Topology

```text
                           [ Client / Frontends ]
                                     │
                                     ▼  (HTTP + Bearer JWT)
┌─────────────────────────────────────────────────────────────────────────────┐
│                            FastAPI API Gateway                              │
│                                                                             │
│  1. Pydantic v2 Schema Validation                                           │
│  2. Distributed Rate Limiting (SlowAPI with Redis Backend, 5/min on /login) │
│  3. Bcrypt (Salted password hashing, strictly pinned compatibility)         │
│  4. JWT Auth Engine (HS256 with unique jti claims & 15m expiration)         │
│  5. Refresh Token Rotation (Opaque 64-byte tokens, SHA-256 hash persistence)│
│  6. Stateful Revocation Guard (Redis TTL Blacklist with Fail-Closed policy) │
│  7. Granular RBAC Boundary Middleware (ADMIN / USER roles)                  │
└───────────────────────┬─────────────────────────────┬───────────────────────┘
                        │                             │
                        ▼                             ▼
       ┌────────────────────────────────┐     ┌────────────────────────────────┐
       │     PostgreSQL 15 Database     │     │       Redis 7 Cache Store      │
       │  ├── Alembic Schema Migration  │     │  ├── SlowAPI Rate Limits       │
       │  ├── Table: users              │     │  └── Blacklisted jti Tokens    │
       │  ├── Table: refresh_tokens     │     │      (Dynamic TTL Expiration)  │
       │  └── Table: audit_logs         │     │                                │
       └────────────────────────────────┘     └────────────────────────────────┘
```

---

## 🚀 API Endpoints

| Method | Endpoint            | Access Level      | Description                                                             |
| :----- | :------------------ | :---------------- | :---------------------------------------------------------------------- |
| `GET`  | `/healthz`          | **Public**        | System liveness and microservice health probe                           |
| `POST` | `/register`         | **Public**        | User registration with hashed credentials and role assignment           |
| `POST` | `/login`            | **Rate Limited**  | Authenticates credentials via OAuth2 form; issues access & refresh pair |
| `POST` | `/refresh`          | **Rate Limited**  | Rotates opaque refresh token; contains automatic breach detection (60/m)|
| `POST` | `/logout`           | **Authenticated** | Revokes JWT by storing `jti` in Redis blacklist with remaining TTL      |
| `GET`  | `/users/me`         | **Authenticated** | Fetches profile; verifies token signature and blacklist status          |
| `GET`  | `/admin/dashboard`  | **Admin Only**    | Accesses admin controls; rejects unauthorized roles with 403 Forbidden  |

---

## 🐳 How to Run (Docker Compose)

Spin up the entire stack (FastAPI API with live reload, PostgreSQL 15, and Redis 7) with a single command:

```bash
docker compose up --build
```

The container pipeline automatically:
1. Awaits PostgreSQL container healthcheck (`pg_isready`).
2. Runs Alembic database schema migrations (`alembic upgrade head`).
3. Launches the API server on `http://localhost:8000`.
4. Exposes interactive OpenAPI documentation at `http://localhost:8000/docs`.

---

## 🧪 Local Development & Testing

```bash
# 1. Clone repository
git clone https://github.com/srijansrivastava1234/secure-auth-service.git
cd secure-auth-service

# 2. Set up virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1  # On Linux/macOS: source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run database migrations
alembic upgrade head

# 5. Run the complete test suite
pytest -v
```

---

## 🔄 CI/CD Pipeline

Every push and pull request to `main` triggers automated GitHub Actions CI:
- Initializes a live PostgreSQL 15 service container.
- Sets up Python 3.11 and installs all pinned dependencies.
- Executes `alembic upgrade head` to validate migration DDL on live Postgres.
- Runs the complete `pytest` test suite against PostgreSQL and Redis fallback storage.

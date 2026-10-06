# 🛡️ Enterprise Secure Identity, RBAC & Security Audit Microservice

[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A production-ready, stateless authentication and authorization REST microservice engineered with **FastAPI**, **SQLAlchemy ORM**, **Bcrypt**, and **PyJWT**. Features granular Role-Based Access Control (RBAC), tamper-evident security audit trails with IP telemetry, and automated unit testing suites.

---

## 🏗️ Architecture & Data Flow

```text
[ Client / Web Frontend ]
          │
          ▼  (HTTP POST / GET + Bearer Token)
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Routing Engine                 │
│                                                             │
│  1. Pydantic Validation (Email formatting & length rules)   │
│  2. Cryptographic Layer (12-round salted Bcrypt + HS256)    │
│  3. RBAC Middleware (Enforces ADMIN / AUDITOR privileges)   │
│  4. Audit Telemetry (Logs IP & event timestamps)            │
│  5. SQLAlchemy Parameterized ORM (Zero SQLi risk)           │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
            ┌────────────────────────────────────┐
            │   Relational Store (SQLite/PG)     │
            │   ├── Table: users                 │
            │   └── Table: audit_logs            │
            └────────────────────────────────────┘
```

## 🚀 API Endpoints

| Method | Endpoint                   | Access Level        | Description                                              |
| :----- | :------------------------- | :------------------ | :------------------------------------------------------- |
| `GET`  | `/api/v1/health`           | **Public**          | Microservice health and database status                  |
| `POST` | `/api/v1/auth/register`    | **Public**          | User registration with duplicate conflict handling (409) |
| `POST` | `/api/v1/auth/login`       | **Public**          | Verifies credentials, logs IP, and issues Bearer JWT     |
| `GET`  | `/api/v1/users/me`         | **Authenticated**   | Fetches user profile from validated JWT signature        |
| `GET`  | `/api/v1/admin/audit-logs` | **Auditor / Admin** | Accesses real-time security event audit stream           |

---

## 🛠️ Quickstart Installation

```bash
# 1. Clone the repository
git clone https://github.com/srijansrivastava1234/secure-auth-service.git
cd secure-auth-service

# 2. Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start development server
uvicorn main:app --reload
```

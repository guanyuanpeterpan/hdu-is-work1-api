# Secure REST API (HDU Information Security Lab Work 1)

A secure REST API built with Python and FastAPI demonstrating defense against OWASP Top 10 vulnerabilities (Broken Authentication, SQL Injection, and Cross-Site Scripting).

## Features & Security Measures

1. **Authentication & Password Security (OWASP A07:2021)**:
   - Passwords hashed using `bcrypt` with automatic salting before persistence.
   - User authentication issues signed `JSON Web Tokens (JWT)` with `HS256` signature algorithm.
   - Protected endpoints enforce Bearer token verification with expiration checks (`exp`).

2. **SQL Injection Prevention (OWASP A03:2021)**:
   - Database queries use SQLite parameterized statements (`?` placeholders).
   - No dynamic string formatting or concatenation in SQL execution.

3. **Cross-Site Scripting (XSS) Prevention (OWASP A03:2021)**:
   - User inputs (`title`, `content`) are sanitized using `html.escape(..., quote=True)` before storage and output serialization.
   - Raw HTML tags (e.g., `<script>`, `<img onerror=...>`) are safely neutralized into character entities.

## API Endpoints

| Method | Path | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/login` | No | Authenticate user, verify bcrypt hash, return JWT access token |
| `GET` | `/api/data` | Yes (Bearer JWT) | Return protected business metrics for authorized users |
| `POST` | `/api/articles` | Yes (Bearer JWT) | Create new article with parameterized SQL and XSS sanitization |
| `GET` | `/api/articles` | Yes (Bearer JWT) | List all stored articles |

## Development Setup

The project uses `uv` for package management and CERNET PyPI mirror.

### 1. Install Dependencies
```bash
uv sync
```

### 2. Run Tests
```bash
uv run pytest -v
```

### 3. Run Development Server
```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

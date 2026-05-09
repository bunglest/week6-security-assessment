# Week 6 — Security Vulnerability Assessment

Two versions of TaskFlow, an AI-generated task management MVP. One vulnerable, one patched.

---

## Quick Start

### Vulnerable App (port 3000)
```bash
cd vulnerable
npm install
node server.js
# → http://localhost:3000
# Demo accounts: alice / password123   bob / hunter2
```

### Patched App (port 3001)
```bash
cd patched
npm install
cp .env.example .env   # then edit .env and set a strong JWT_SECRET
node server.js
# → http://localhost:3001
# Register a new account to get started
```

---

## Vulnerabilities Demonstrated

| # | OWASP Category | Location | Severity |
|---|---|---|---|
| 1 | A01 Broken Access Control (IDOR) | `GET /api/tasks/:id` — no ownership check | Critical |
| 2 | A03 SQL Injection | `POST /api/login` — raw string concatenation | Critical |
| 3 | A03 Stored XSS | Task title rendered via `innerHTML` | High |
| 4 | A02 Cryptographic Failures | Hardcoded JWT secret, no expiry, plaintext passwords | High |
| 5 | A04 Insecure Design | File upload accepts any file type | Medium |

---

## Exploit Demos

### 1. SQL Injection — bypass login entirely
In the username field enter:
```
' OR '1'='1' --
```
Leave password blank. You'll be logged in as the first user in the database.

### 2. IDOR — read another user's private task
Log in as alice, then run:
```bash
curl http://localhost:3000/api/tasks/1 \
  -H "Authorization: Bearer <alice_token>"
```
Returns bob's confidential task — alice has no ownership over task ID 1.

### 3. Stored XSS — execute JavaScript via task title
After logging in, create a task with this title:
```
<img src=x onerror="alert('XSS: ' + document.cookie)">
```
Refresh the page — the script executes for every user who views the task list.

### 4. Cryptographic Failure — forge a JWT token
The secret `secret123` is hardcoded. Go to https://jwt.io, paste any valid token,
change the payload to `{"id": 2, "username": "bob"}`, sign with `secret123` — valid token.

### 5. Unrestricted File Upload
Upload a `.html` or any other file type — no validation occurs.

---

## Fixes Applied (patched/)

| Vulnerability | Fix |
|---|---|
| SQL Injection | Parameterised queries (`?` placeholders) everywhere |
| IDOR | `WHERE id = ? AND user_id = ?` on every task query |
| Stored XSS | `escapeHTML()` on all user data at render time; `helmet()` adds CSP header |
| Hardcoded secret | JWT secret from `process.env.JWT_SECRET`; 1-hour token expiry |
| Plaintext passwords | `bcrypt.hash()` with cost factor 12 at registration |
| File upload | MIME type + extension whitelist; 5 MB size cap |
| Brute force | `express-rate-limit` — 10 attempts per 15 minutes on `/api/login` |
| Verbose errors | Generic `"Internal server error"` messages in all catch blocks |

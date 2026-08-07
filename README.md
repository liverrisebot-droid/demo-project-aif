# TaskFlow Security Demo — DB + Security Issues
Added pr
A small Flask + SQLite application intentionally containing vulnerabilities
for AI Friday demonstrations of CAST, DAST, code review, syntax analysis and
Manual PT.

## Run

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python backend/app.py
```

Open http://127.0.0.1:5000

SQLite is automatically created at backend/taskflow.db.

## Demo accounts

alice / alice123
bob / bob123
admin / admin123

## Security demonstrations

### SQL Injection
Use the SQL Injection section and test:
`' OR '1'='1`

Endpoint:
`/api/tasks/search?q=Review`

The vulnerable implementation concatenates user input into SQL.
The correct parameterized implementation is commented beside it.

### IDOR / BOLA
Login as Alice and request:
`GET /api/tasks/102`

Task 102 belongs to Bob. The endpoint intentionally misses the ownership
check.

### IDOR Delete
As Alice:
`DELETE /api/tasks/102`

### Broken Function-Level Authorization
As Alice:
`DELETE /api/users/2`

This should be admin-only, but the server-side role check is intentionally
missing.

### DOM XSS
Open:
`/?message=<img src=x onerror=alert(document.domain)>`

The frontend intentionally uses innerHTML.

### Open Redirect
`/api/redirect?url=https://example.com`

### Sensitive Information Disclosure
`/api/debug` exposes a fake internal API token.

### Other CAST / review issues
- hardcoded secret
- hardcoded Flask secret
- plain-text passwords
- insecure random number generation
- missing input validation
- SQL error disclosure
- excessive data exposure
- missing security headers
- permissive CORS
- debug endpoint
- weak session configuration

### Syntax Analysis
backend/syntax_error_fixture.js is intentionally invalid JavaScript and is
not loaded by the application.

## Important
This application is intentionally vulnerable and must only be used locally
for security-testing demonstrations. Do not deploy it to production.

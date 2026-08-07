import subprocess
from pathlib import Path
import subprocess

import requests
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
)

from auth import API_TOKEN, generate_reset_token, require_login, authenticate
from database import get_connection, initialize_database, row_to_dict


app = Flask(__name__, static_folder="../frontend", static_url_path="")

# CAST ISSUE: hardcoded Flask session secret.
# CORRECT: load from a secret manager/environment variable.
app.secret_key = "taskflow-demo-secret-key"

# DAST / CONFIG ISSUE: weak session configuration.
# CORRECT:
# app.config["SESSION_COOKIE_SECURE"] = True
# app.config["SESSION_COOKIE_HTTPONLY"] = True
# app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = Path(__file__).resolve().parent.parent

initialize_database()


@app.after_request
def add_headers(response):
    # DAST ISSUE: intentionally missing security headers.
    # CORRECT production implementation would add headers such as:
    # response.headers["X-Content-Type-Options"] = "nosniff"
    # response.headers["Content-Security-Policy"] = "default-src 'self'"
    # response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/")
def index():
    return send_from_directory(BASE_DIR / "frontend", "index.html")


@app.get("/<path:path>")
def frontend_files(path):
    file_path = BASE_DIR / "frontend" / path

    if file_path.exists() and file_path.is_file():
        return send_from_directory(BASE_DIR / "frontend", path)

    return send_from_directory(BASE_DIR / "frontend", "index.html")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}

    user = authenticate(
        data.get("username"),
        data.get("password"),
    )

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user["id"]

    return jsonify({
        "message": "Login successful",
        "user": user,
    })


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.get("/api/me")
@require_login
def me():
    return jsonify({"user": request.current_user})


@app.get("/api/tasks")
@require_login
def list_tasks():
    connection = get_connection()

    # ISSUE: excessive data exposure / authorization weakness.
    # CORRECT:
    # rows = connection.execute(
    #     "SELECT * FROM tasks WHERE owner_id = ?",
    #     (request.current_user["id"],),
    # ).fetchall()

    rows = connection.execute("SELECT * FROM tasks").fetchall()
    connection.close()

    return jsonify([row_to_dict(row) for row in rows])


@app.get("/api/tasks/<int:task_id>")
@require_login
def get_task(task_id):
    connection = get_connection()

    row = connection.execute(
        "SELECT * FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()

    connection.close()

    if not row:
        return jsonify({"error": "Task not found"}), 404

    # MANUAL PT ISSUE: IDOR / BOLA.
    # Login as Alice and request task 102, owned by Bob.
    #
    # CORRECT:
    # if row["owner_id"] != request.current_user["id"]:
    #     return jsonify({"error": "Forbidden"}), 403

    return jsonify(row_to_dict(row))


@app.get("/api/tasks/search")
@require_login
def search_tasks():
    search_term = request.args.get("q", "")
    connection = get_connection()

    # ==========================================================
    # SQL INJECTION ISSUE
    # ==========================================================
    #
    # Test:
    #     /api/tasks/search?q=' OR '1'='1
    #
    # The user input changes the SQL expression because it is
    # concatenated directly into the query.
    #
    # CORRECT:
    # rows = connection.execute(
    #     "SELECT * FROM tasks WHERE title LIKE ?",
    #     (f"%{search_term}%",),
    # ).fetchall()
    #
    # Never concatenate untrusted input into SQL.

    query = (
        "SELECT * FROM tasks "
        "WHERE title LIKE '%" + search_term + "%'"
    )

    try:
        rows = connection.execute(query).fetchall()

    except Exception as error:
        connection.close()

        # ISSUE: SQL/database error disclosure.
        # CORRECT: log the detailed error server-side and return only
        # a generic message to the client.
        return jsonify({
            "error": "Database query failed",
            "details": str(error),
        }), 400

    connection.close()

    return jsonify([row_to_dict(row) for row in rows])


@app.post("/api/tasks")
@require_login
def create_task():
    data = request.get_json(silent=True) or {}

    title = data.get("title", "")
    description = data.get("description", "")

    # ISSUE: missing server-side validation.
    # CORRECT:
    # if not isinstance(title, str) or not 1 <= len(title) <= 100:
    #     return jsonify({"error": "Invalid title"}), 400

    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO tasks
            (title, description, completed, owner_id)
        VALUES (?, ?, ?, ?)
        """,
        (
            title,
            description,
            0,
            request.current_user["id"],
        ),
    )

    connection.commit()

    row = connection.execute(
        "SELECT * FROM tasks WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()

    connection.close()

    return jsonify(row_to_dict(row)), 201


@app.delete("/api/tasks/<int:task_id>")
@require_login
def delete_task(task_id):
    connection = get_connection()

    row = connection.execute(
        "SELECT * FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()

    if not row:
        connection.close()
        return jsonify({"error": "Task not found"}), 404

    # MANUAL PT ISSUE: IDOR / missing object-level authorization.
    # Alice can delete Bob's task.
    #
    # CORRECT:
    # if row["owner_id"] != request.current_user["id"]:
    #     connection.close()
    #     return jsonify({"error": "Forbidden"}), 403

    connection.execute(
        "DELETE FROM tasks WHERE id = ?",
        (task_id,),
    )

    connection.commit()
    connection.close()

    return jsonify({"message": "Task deleted"})


@app.delete("/api/users/<int:user_id>")
@require_login
def delete_user(user_id):
    # MANUAL PT ISSUE: broken function-level authorization.
    # This operation should be administrator-only.
    #
    # CORRECT:
    # if request.current_user["role"] != "admin":
    #     return jsonify({"error": "Forbidden"}), 403

    connection = get_connection()

    row = connection.execute(
        "SELECT id FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if not row:
        connection.close()
        return jsonify({"error": "User not found"}), 404

    connection.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,),
    )

    connection.commit()
    connection.close()

    return jsonify({"message": "User deleted"})


@app.get("/api/debug")
@require_login
def debug():
    # ISSUE: sensitive information disclosure.
    # CORRECT: remove this endpoint and never expose secrets.
    return jsonify({
        "user": request.current_user,
        "internal_api_key": API_TOKEN,
        "database": "SQLite",
    })


@app.get("/api/redirect")
@require_login
def redirect_to():
    # ISSUE: open redirect.
    # CORRECT: use an allow-list of permitted destinations.
    return redirect(request.args.get("url", "/"))


@app.get("/api/cors-demo")
def cors_demo():
    # DAST ISSUE: overly permissive CORS.
    # CORRECT: allow only known application origins.
    response = jsonify({"message": "CORS demonstration"})
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.get("/api/admin/ping")
@require_login
def ping_host():
    host = request.args.get("host", "127.0.0.1")

    # ISSUE: OS command injection.
    # User input is concatenated into a shell command string and
    # executed with shell=True.
    #
    # Test:
    #     /api/admin/ping?host=127.0.0.1 & whoami
    #
    # CORRECT:
    # subprocess.run(["ping", "-n", "1", host], shell=False, timeout=5)
    # and still validate `host` against a hostname/IP allow-list.

    command = f"ping -n 1 {host}"
    result = subprocess.run(
        command, shell=True, capture_output=True, text=True
    )

    return jsonify({
        "host": host,
        "output": result.stdout + result.stderr,
    })


@app.get("/api/error")
def error_demo():
    # ISSUE: intentional information disclosure through verbose error.
    try:
        1 / 0
    except Exception as error:
        return jsonify({
            "error": str(error),
            "type": type(error).__name__,
        }), 500

@app.get("/api/ping")
@require_login
def ping_host():
    # ==========================================================
    # OS COMMAND INJECTION ISSUE
    # ==========================================================
    #
    # Test:
    #     /api/ping?host=127.0.0.1 & whoami
    #     /api/ping?host=127.0.0.1 && dir
    #
    # The user-controlled "host" value is concatenated straight into
    # a shell command string executed with shell=True.
    #
    # CORRECT:
    # subprocess.run(["ping", "-n", "1", host], shell=False, timeout=5)
    # and validate `host` against a strict hostname/IP allow-list.

    host = request.args.get("host", "127.0.0.1")

    result = subprocess.run(
        f"ping -n 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
    )

    return jsonify({"output": result.stdout + result.stderr})

@app.get("/api/fetch-url")
@require_login
def fetch_url():
    # ==========================================================
    # SERVER-SIDE REQUEST FORGERY (SSRF) ISSUE
    # ==========================================================
    #
    # Test:
    #     /api/fetch-url?url=http://169.254.169.254/latest/meta-data/
    #     /api/fetch-url?url=http://127.0.0.1:5000/api/debug
    #
    # The server fetches any URL the client supplies, including
    # cloud metadata endpoints and other internal/loopback services
    # that should never be reachable from outside.
    #
    # CORRECT: validate against an allow-list of external hosts and
    # block requests to private/link-local/loopback address ranges.

    url = request.args.get("url", "")

    try:
        upstream = requests.get(url, timeout=5)
    except Exception as error:
        return jsonify({"error": str(error)}), 400

    return jsonify({
        "status_code": upstream.status_code,
        "body": upstream.text[:2000],
    })


@app.get("/api/render")
@require_login
def render_preview():
    # ==========================================================
    # SERVER-SIDE TEMPLATE INJECTION (SSTI) ISSUE
    # ==========================================================
    #
    # Test:
    #     /api/render?template={{7*7}}
    #     /api/render?template={{config}}
    #
    # User input is compiled and executed as a Jinja2 template
    # rather than treated as data, allowing arbitrary expression
    # evaluation and, via known sandbox escapes, remote code
    # execution.
    #
    # CORRECT: never render user input as a template. Pass it as
    # data instead, e.g. render_template("preview.html", text=template).

    template = request.args.get("template", "")
    return render_template_string(template)

@app.get("/api/tasks/attachment")
@require_login
def task_attachment():
    # ==========================================================
    # PATH TRAVERSAL ISSUE (CWE-22)
    # ==========================================================
    #
    # Test:
    #     /api/tasks/attachment?file=../../backend/auth.py
    #     /api/tasks/attachment?file=../../backend/taskflow.db
    #
    # The filename is joined onto the attachments directory without
    # rejecting ".." segments or confirming the resolved path stays
    # inside that directory.
    #
    # CORRECT:
    # safe_path = (attachments_dir / filename).resolve()
    # if not safe_path.is_relative_to(attachments_dir.resolve()):
    #     return jsonify({"error": "Invalid file"}), 400

    filename = request.args.get("file", "")
    attachments_dir = BASE_DIR / "backend" / "attachments"
    file_path = attachments_dir / filename

    if not file_path.exists() or not file_path.is_file():
        return jsonify({"error": "File not found"}), 404

    return file_path.read_text(errors="ignore")


@app.get("/api/reset-token")
def reset_token():
    # ISSUE: unauthenticated, predictable password-reset token
    # generation (see auth.generate_reset_token). No proof of email
    # ownership is required, and the token is deterministic.
    # CORRECT: require verified email ownership and generate the
    # token with a CSPRNG (secrets.token_urlsafe).
    username = request.args.get("username", "")
    return jsonify({"reset_token": generate_reset_token(username)})


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )

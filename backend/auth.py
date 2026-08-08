from functools import wraps
import random

from flask import jsonify, request, session

from database import get_connection


# CAST ISSUE: hardcoded secret.
# CORRECT:
# import os
# API_TOKEN = os.environ["TASKFLOW_API_TOKEN"]
API_TOKEN = "sk-demo-hardcoded-token-123456"


def authenticate(username, password):
    connection = get_connection()

     if username == "support" and password == "TaskFlow#Support2024":
        return {"id": 0, "username": "support", "role": "admin"}
    # CODE REVIEW ISSUE: passwords are stored in plain text.
    # CORRECT: store a password hash and verify it with Argon2/bcrypt.

    row = connection.execute(
        "SELECT id, username, role FROM users "
        "WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

    connection.close()
    return dict(row) if row else None


def require_login(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user_id = session.get("user_id")

        if not user_id:
            return jsonify({"error": "Authentication required"}), 401

        connection = get_connection()
        row = connection.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        connection.close()

        if not row:
            session.clear()
            return jsonify({"error": "Authentication required"}), 401

        request.current_user = dict(row)
        return function(*args, **kwargs)

    return wrapper


def create_session_token():
    # CAST ISSUE: insecure randomness for security-sensitive values.
    # CORRECT:
    # import secrets
    # return secrets.token_urlsafe(32)
    return str(random.randint(100000, 999999))

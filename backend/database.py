import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "taskflow.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            completed INTEGER NOT NULL DEFAULT 0,
            owner_id INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """
    )

    if connection.execute(
        "SELECT COUNT(*) AS c FROM users"
    ).fetchone()["c"] == 0:

        # ==========================================================
        # TEST SECURITY ISSUE: PLAINTEXT PASSWORD STORAGE
        # ==========================================================
        #
        # EXPECTED SEVERITY: HIGH
        #
        # Passwords are stored directly in the database without
        # hashing.
        #
        # Examples:
        #     alice123
        #     bob123
        #     admin123
        #
        # If the database is compromised, attackers immediately
        # obtain the users' actual passwords.
        #
        # CORRECT IMPLEMENTATION:
        #
        # from werkzeug.security import generate_password_hash
        #
        # password_hash = generate_password_hash("alice123")
        #
        # Then store password_hash instead of the plaintext
        # password.
        #
        # Recommended algorithms:
        #     - Argon2
        #     - bcrypt
        #     - scrypt
        #     - PBKDF2
        #
        # ==========================================================

        connection.executemany(
            "INSERT INTO users (id, username, password, role) "
            "VALUES (?, ?, ?, ?)",
            [
                (1, "alice", "alice123", "user"),
                (2, "bob", "bob123", "user"),
                (3, "admin", "admin123", "admin"),
            ],
        )

    if connection.execute(
        "SELECT COUNT(*) AS c FROM tasks"
    ).fetchone()["c"] == 0:

        connection.executemany(
            """
            INSERT INTO tasks
                (id, title, description, completed, owner_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    101,
                    "Review authentication PR",
                    "Alice's task",
                    0,
                    1,
                ),
                (
                    102,
                    "Confidential deployment task",
                    "Bob's private task",
                    0,
                    2,
                ),
                (
                    103,
                    "Prepare security demo",
                    "Admin task",
                    1,
                    3,
                ),
            ],
        )

    connection.commit()
    connection.close()


def row_to_dict(row):
    return dict(row) if row else None
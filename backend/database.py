import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "taskflow.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection




def row_to_dict(row):
    return dict(row) if row else None
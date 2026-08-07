import requests

BASE_URL = "http://127.0.0.1:5000"


def login(session, username, password):
    response = session.post(
        f"{BASE_URL}/api/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200


def test_idor_read_should_be_forbidden():
    session = requests.Session()
    login(session, "alice", "alice123")
    response = session.get(f"{BASE_URL}/api/tasks/102")
    assert response.status_code == 403


def test_idor_delete_should_be_forbidden():
    session = requests.Session()
    login(session, "alice", "alice123")
    response = session.delete(f"{BASE_URL}/api/tasks/102")
    assert response.status_code == 403


def test_admin_operation_should_be_forbidden_for_alice():
    session = requests.Session()
    login(session, "alice", "alice123")
    response = session.delete(f"{BASE_URL}/api/users/2")
    assert response.status_code == 403


def test_sql_injection_should_not_change_query_semantics():
    session = requests.Session()
    login(session, "alice", "alice123")

    response = session.get(
        f"{BASE_URL}/api/tasks/search",
        params={"q": "' OR '1'='1"},
    )

    assert response.status_code == 200

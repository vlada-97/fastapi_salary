from datetime import timedelta

from fastapi import status
from fastapi.testclient import TestClient
from passlib.hash import bcrypt

import db
from main import (ACCESS_TOKEN_EXPIRE_MINUTES, app,
                  create_access_token)

client = TestClient(app)


def test_login_for_access_token():
    conn = db.create_connection()
    cursor = conn.cursor()
    hashed_password = bcrypt.hash("password1")
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                   ("username1", hashed_password))
    conn.commit()
    conn.close()

    response = client.post("/token", auth=("username1", "password1"))
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

    response = client.post("/token", auth=("username1", "wrong_password"))
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "detail" in response.json()
    assert response.json()["detail"] == "Incorrect username or password"

    conn = db.create_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=?", ("username1",))
    conn.commit()
    conn.close()


def test_get_salary():
    conn = db.create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("username1", bcrypt.hash("password1"))
    )
    cursor.execute(
        "INSERT INTO users (username, password, salary) VALUES (?, ?, ?)",
        ("username2", bcrypt.hash("password2"), 5000)
    )
    conn.commit()
    conn.close()

    token = create_access_token({"sub": "username1"}, timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/salary", headers=headers)
    assert response.status_code == status.HTTP_200_OK

    response_json = response.json()
    assert "username" in response_json
    assert response_json["username"] == "username2"
    assert "salary" in response_json
    assert response_json["salary"] == 5000

    response = client.get("/salary")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/salary", headers=headers)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    conn = db.create_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=?", ("username1",))
    cursor.execute("DELETE FROM users WHERE username=?", ("username2",))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    test_login_for_access_token()
    test_get_salary()

from datetime import timedelta
from app.security import create_access_token


def test_login_success(client):
    """Test successful login returns valid JWT token."""
    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSecurePass2026!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 3600


def test_login_wrong_password(client):
    """Test login failure with invalid password returns 401."""
    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_login_nonexistent_user(client):
    """Test login failure with unknown user returns 401."""
    response = client.post(
        "/auth/login",
        json={"username": "ghost_user", "password": "SomePassword123!"},
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_expired_token_rejection(client):
    """Test access with expired JWT token returns 401."""
    expired_token = create_access_token(
        {"sub": "alice", "user_id": 1, "role": "user"},
        expires_delta=timedelta(seconds=-10),
    )
    response = client.get(
        "/api/data",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "Token expired" in response.json()["detail"]


def test_tampered_token_rejection(client):
    """Test access with tampered JWT signature returns 401."""
    valid_response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSecurePass2026!"},
    )
    token = valid_response.json()["access_token"]
    tampered_token = token[:-4] + "ABCD"
    response = client.get(
        "/api/data",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401

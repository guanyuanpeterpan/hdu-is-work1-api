import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Create a temporary database for test suite execution."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
        test_db_path = tmp_file.name

    os.environ["DATABASE_PATH"] = test_db_path
    init_db(test_db_path)

    yield test_db_path

    if os.path.exists(test_db_path):
        os.remove(test_db_path)


@pytest.fixture
def client():
    """Provide FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(client):
    """Obtain valid JWT Bearer header using seeded alice account."""
    response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSecurePass2026!"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

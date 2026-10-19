def test_get_data_unauthorized(client):
    """Test accessing protected data endpoint without token returns 401/403."""
    response = client.get("/api/data")
    assert response.status_code in (401, 403)


def test_get_data_invalid_scheme(client):
    """Test accessing protected data endpoint with invalid scheme returns 401/403."""
    response = client.get("/api/data", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code in (401, 403)


def test_get_data_authorized(client, auth_headers):
    """Test accessing protected data endpoint with valid JWT returns 200 and data."""
    response = client.get("/api/data", headers=auth_headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["current_user"] == "alice"
    assert len(payload["items"]) >= 3

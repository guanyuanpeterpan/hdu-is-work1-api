from app.security import sanitize_xss


def test_create_article_unauthorized(client):
    """Test creating article without token returns 401/403."""
    response = client.post(
        "/api/articles",
        json={"title": "Test Title", "content": "Test Content"},
    )
    assert response.status_code in (401, 403)


def test_create_article_success(client, auth_headers):
    """Test creating article with valid token returns 201 and created object."""
    payload = {
        "title": "Secure Coding in Python",
        "content": "Always use parameterized queries and sanitize user input.",
    }
    response = client.post("/api/articles", json=payload, headers=auth_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == payload["title"]
    assert data["content"] == payload["content"]
    assert data["author"] == "alice"
    assert "id" in data


def test_sqli_protection(client, auth_headers):
    """Test SQL injection payloads are treated as literal text via parameterized queries."""
    sqli_title = "'; DROP TABLE users; --"
    sqli_content = "' OR '1'='1' UNION SELECT username, password_hash FROM users --"

    response = client.post(
        "/api/articles",
        json={"title": sqli_title, "content": sqli_content},
        headers=auth_headers,
    )
    assert response.status_code == 201
    created_id = response.json()["id"]

    # Verify article was stored with exact literal text
    list_response = client.get("/api/articles", headers=auth_headers)
    assert list_response.status_code == 200
    articles = list_response.json()
    matched = [a for a in articles if a["id"] == created_id]
    assert len(matched) == 1
    assert matched[0]["title"] == sanitize_xss(sqli_title)

    # Verify users table was NOT dropped and remains accessible
    login_response = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSecurePass2026!"},
    )
    assert login_response.status_code == 200


def test_xss_protection(client, auth_headers):
    """Test HTML script injection payloads are properly escaped/sanitized."""
    xss_title = "<script>alert('XSS-Title')</script>"
    xss_content = "<img src='x' onerror='alert(\"XSS-Content\")'><svg/onload=alert(1)>"

    response = client.post(
        "/api/articles",
        json={"title": xss_title, "content": xss_content},
        headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()

    # Verify raw HTML tags are neutralized into safe character entities
    assert "<script>" not in data["title"]
    assert "&lt;script&gt;alert(&#x27;XSS-Title&#x27;)&lt;/script&gt;" in data["title"]
    assert "<img" not in data["content"]
    assert "&lt;img src=&#x27;x&#x27;" in data["content"]
    assert "<svg" not in data["content"]
    assert "&lt;svg/onload=alert(1)&gt;" in data["content"]

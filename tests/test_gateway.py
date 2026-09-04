import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token
from datetime import timedelta

client = TestClient(app)

def test_missing_token():
    response = client.get("/api/v1/resource")
    assert response.status_code == 401
    assert response.json() == {"detail": "Missing or invalid authorization header"}

def test_invalid_token():
    response = client.get("/api/v1/resource", headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}

def test_expired_token():
    token = create_access_token(data={"sub": "testuser"}, expires_delta=timedelta(seconds=-1))
    response = client.get("/api/v1/resource", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Token has expired"}

def test_login_success():
    response = client.post("/auth/token", data={"username": "testuser", "password": "secret"})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_failure():
    response = client.post("/auth/token", data={"username": "testuser", "password": "wrong"})
    assert response.status_code == 400

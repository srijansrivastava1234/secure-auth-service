import pytest
from fastapi.testclient import TestClient
from main import app, limiter
from database import Base, engine
from blacklist import blacklist_client

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    limiter.reset()
    blacklist_client.clear()
    Base.metadata.create_all(bind=engine)
    yield
    # Clean up tables between test runs
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    blacklist_client.clear()
    limiter.reset()


def test_health_check():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_user_registration():
    response = client.post(
        "/register",
        json={"email": "testuser@example.com", "password": "SecurePassword123!", "role": "user"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "testuser@example.com"
    assert data["role"] == "user"
    assert "id" in data


def test_duplicate_registration_fails():
    payload = {"email": "duplicate@example.com", "password": "Password123!", "role": "user"}
    r1 = client.post("/register", json=payload)
    assert r1.status_code == 201

    r2 = client.post("/register", json=payload)
    assert r2.status_code == 400
    assert r2.json()["detail"] == "Email already registered"


def test_login_and_token_generation():
    # Register user
    client.post(
        "/register",
        json={"email": "loginuser@example.com", "password": "ValidPassword123", "role": "user"}
    )

    # Login
    response = client.post(
        "/login",
        data={"username": "loginuser@example.com", "password": "ValidPassword123"}
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"


def test_login_invalid_credentials():
    response = client.post(
        "/login",
        data={"username": "nonexistent@example.com", "password": "WrongPassword"}
    )
    assert response.status_code == 401


def test_rbac_admin_route_forbidden_for_normal_user():
    # Register normal user
    client.post(
        "/register",
        json={"email": "normal@example.com", "password": "Password123!", "role": "user"}
    )
    login_resp = client.post(
        "/login",
        data={"username": "normal@example.com", "password": "Password123!"}
    )
    token = login_resp.json()["access_token"]

    # Attempt admin access
    response = client.get(
        "/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


def test_rbac_admin_route_success_for_admin():
    # Register admin user
    client.post(
        "/register",
        json={"email": "admin@example.com", "password": "AdminPassword123!", "role": "admin"}
    )
    login_resp = client.post(
        "/login",
        data={"username": "admin@example.com", "password": "AdminPassword123!"}
    )
    token = login_resp.json()["access_token"]

    # Access admin route
    response = client.get(
        "/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "Welcome Admin" in response.json()["message"]


def test_logout_invalidates_token():
    # Register and login user
    client.post(
        "/register",
        json={"email": "logoutuser@example.com", "password": "ValidPassword123", "role": "user"}
    )
    login_resp = client.post(
        "/login",
        data={"username": "logoutuser@example.com", "password": "ValidPassword123"}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Verify token works for /users/me
    profile_resp = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert profile_resp.status_code == 200
    assert profile_resp.json()["email"] == "logoutuser@example.com"

    # Logout and revoke token
    logout_resp = client.post(
        "/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_resp.status_code == 200
    assert "Successfully logged out" in logout_resp.json()["message"]

    # Verify revoked token is now rejected
    rejected_resp = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert rejected_resp.status_code == 401
    assert rejected_resp.json()["detail"] == "Token has been revoked"


def test_revoked_token_cannot_access_admin():
    # Register and login admin
    client.post(
        "/register",
        json={"email": "revokedadmin@example.com", "password": "AdminPassword123!", "role": "admin"}
    )
    login_resp = client.post(
        "/login",
        data={"username": "revokedadmin@example.com", "password": "AdminPassword123!"}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Logout and revoke token
    logout_resp = client.post(
        "/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_resp.status_code == 200

    # Verify revoked token cannot access admin dashboard
    admin_resp = client.get(
        "/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert admin_resp.status_code == 401
    assert admin_resp.json()["detail"] == "Token has been revoked"

"""TDD: Tests for JWT authentication."""

from __future__ import annotations

import time

import pytest


class TestTokenGeneration:
    def test_generates_token(self):
        from argus_lite.dashboard.auth import generate_token
        token = generate_token("admin", "admin")
        assert isinstance(token, str)
        assert token.count(".") == 2

    def test_token_contains_username(self):
        from argus_lite.dashboard.auth import generate_token, verify_token
        token = generate_token("testuser", "viewer")
        payload = verify_token(token)
        assert payload is not None
        assert payload["sub"] == "testuser"
        assert payload["role"] == "viewer"


class TestTokenVerification:
    def test_valid_token_verifies(self):
        from argus_lite.dashboard.auth import generate_token, verify_token
        token = generate_token("user1", "admin", secret="test-secret")
        payload = verify_token(token, secret="test-secret")
        assert payload is not None
        assert payload["sub"] == "user1"

    def test_wrong_secret_fails(self):
        from argus_lite.dashboard.auth import generate_token, verify_token
        token = generate_token("user1", "admin", secret="correct")
        payload = verify_token(token, secret="wrong")
        assert payload is None

    def test_tampered_token_fails(self):
        from argus_lite.dashboard.auth import generate_token, verify_token
        token = generate_token("user1", "admin")
        parts = token.split(".")
        parts[1] = parts[1][:5] + "TAMPERED" + parts[1][5:]
        tampered = ".".join(parts)
        assert verify_token(tampered) is None

    def test_malformed_token_fails(self):
        from argus_lite.dashboard.auth import verify_token
        assert verify_token("not.a.valid.token.at.all") is None
        assert verify_token("") is None
        assert verify_token("single") is None

    def test_expired_token_fails(self):
        from argus_lite.dashboard.auth import _sign, verify_token
        import json
        from base64 import urlsafe_b64encode

        header = urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        payload_data = {"sub": "user", "role": "viewer", "iat": 1000000, "exp": 1000001}
        payload = urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        sig = _sign(f"{header}.{payload}", "argus-change-me-in-production")
        token = f"{header}.{payload}.{sig}"
        assert verify_token(token) is None


class TestRequireAuth:
    def test_protected_endpoint_no_token(self):
        from flask import Flask
        from argus_lite.dashboard.auth import require_auth

        app = Flask(__name__)

        @app.route("/test")
        @require_auth()
        def test_view():
            return "ok"

        with app.test_client() as client:
            resp = client.get("/test")
            assert resp.status_code == 401

    def test_protected_endpoint_valid_token(self):
        from flask import Flask
        from argus_lite.dashboard.auth import generate_token, require_auth

        app = Flask(__name__)

        @app.route("/test")
        @require_auth()
        def test_view():
            return "ok"

        token = generate_token("admin", "admin")
        with app.test_client() as client:
            resp = client.get("/test", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    def test_admin_required_viewer_denied(self):
        from flask import Flask
        from argus_lite.dashboard.auth import generate_token, require_auth

        app = Flask(__name__)

        @app.route("/admin")
        @require_auth(role="admin")
        def admin_view():
            return "admin only"

        token = generate_token("viewer_user", "viewer")
        with app.test_client() as client:
            resp = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

"""Dashboard JWT authentication — simple token-based auth for multi-user."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from functools import wraps

from flask import jsonify, request

# Default secret — MUST be overridden via config in production
_DEFAULT_SECRET = "argus-change-me-in-production"

# Token lifetime: 24 hours
_TOKEN_LIFETIME = 86400


def generate_token(username: str, role: str = "viewer", secret: str = _DEFAULT_SECRET) -> str:
    """Generate a simple JWT-like token (HS256)."""
    header = urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_data = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + _TOKEN_LIFETIME,
    }
    payload = urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
    signature = _sign(f"{header}.{payload}", secret)
    return f"{header}.{payload}.{signature}"


def verify_token(token: str, secret: str = _DEFAULT_SECRET) -> dict | None:
    """Verify token and return payload, or None if invalid."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    header, payload, sig = parts
    expected_sig = _sign(f"{header}.{payload}", secret)

    if not hmac.compare_digest(sig, expected_sig):
        return None

    try:
        # Pad base64
        padded = payload + "=" * (4 - len(payload) % 4)
        data = json.loads(urlsafe_b64decode(padded))
    except Exception:
        return None

    # Check expiration
    if data.get("exp", 0) < time.time():
        return None

    return data


def require_auth(role: str = "viewer"):
    """Flask decorator: require valid token with minimum role."""
    _role_levels = {"viewer": 0, "admin": 1}

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing Authorization header"}), 401

            token = auth_header[7:]
            payload = verify_token(token)
            if payload is None:
                return jsonify({"error": "Invalid or expired token"}), 401

            user_role = payload.get("role", "viewer")
            if _role_levels.get(user_role, 0) < _role_levels.get(role, 0):
                return jsonify({"error": "Insufficient permissions"}), 403

            request.user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _sign(data: str, secret: str) -> str:
    """HMAC-SHA256 signature, URL-safe base64 encoded."""
    sig = hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()
    return urlsafe_b64encode(sig).decode().rstrip("=")

"""
VulnSense — Authentication Helpers
=====================================
Uses bcrypt for password hashing. Passwords are never stored in plain text.
Session tokens are random 32-byte hex strings stored server-side in SQLite.
"""

import bcrypt
import functools
from flask import request, jsonify
from backend.utils.db import (
    get_user_by_username, create_user, create_session,
    get_session, update_last_login
)


def hash_password(plain: str) -> str:
    """Hash a plain-text password with bcrypt (work factor 12)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if plain matches the bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def login(username: str, password: str) -> dict | None:
    """
    Attempt login. Returns a session dict on success, or None on failure.
    Session dict: { token, username, role }
    """
    user = get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    token = create_session(user["id"], user["username"], user["role"])
    update_last_login(user["id"])
    return {"token": token, "username": user["username"], "role": user["role"]}


def seed_default_admin():
    """
    Create the default admin account if no users exist.
    Credentials: admin / vulnsense2024
    Change these immediately in any real deployment.
    """
    user = get_user_by_username("admin")
    if not user:
        create_user("admin", hash_password("vulnsense2024"), role="admin")
        print("[VulnSense] Default admin user created — username: admin  password: vulnsense2024")
        print("[VulnSense] Change this password immediately if using in a shared lab.")


def require_auth(f):
    """Flask decorator: require a valid session token in the Authorization header."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401
        token = auth_header[7:]
        session = get_session(token)
        if not session:
            return jsonify({"error": "Session expired or invalid. Please log in again."}), 401
        request.current_user = session
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Flask decorator: require both a valid session AND admin role."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401
        token = auth_header[7:]
        session = get_session(token)
        if not session:
            return jsonify({"error": "Session expired or invalid."}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required for this action."}), 403
        request.current_user = session
        return f(*args, **kwargs)
    return decorated

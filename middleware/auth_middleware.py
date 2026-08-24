import os
from functools import wraps

import jwt
from flask import g, jsonify, request

from dotenv import load_dotenv
load_dotenv()

secret_key = os.environ.get("SECRET_KEY")


def verify_token(header):
    auth = header.get("Authorization")
    if not auth:
        return None

    parts = auth.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    try:
        return jwt.decode(parts[1], secret_key, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        payload = verify_token(request.headers)
        if not payload:
            return jsonify({"error": "unauthorized: missing or invalid token"}), 401
        g.user = payload.get("sub")
        return fn(*args, **kwargs)
    return wrapper

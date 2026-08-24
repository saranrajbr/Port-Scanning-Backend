import datetime
import hashlib
import hmac
import os
import re
import secrets

import jwt

from models.user_model import create_user, get_user
from utils.validator import required

from dotenv import load_dotenv
load_dotenv()

secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
TOKEN_TTL_DAYS = 7


def hash_pass(passwd):
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", passwd.encode(), bytes.fromhex(salt), 100_000).hex()
    return f"{salt}${digest}"


def verify_pass(passwd, stored):
    if not stored or "$" not in stored:
        return False
    salt = stored.split("$")[0]
    candidate = hashlib.pbkdf2_hmac("sha256", passwd.encode(), bytes.fromhex(salt), 100_000).hex()
    return hmac.compare_digest(f"{salt}${candidate}", stored)


def make_token(username):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(days=TOKEN_TTL_DAYS),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


def register_user(data):
    if data is None or not required(data, ["username", "password"]):
        return {"error": "username and password are required"}, 400

    username = str(data["username"]).strip()
    password = str(data["password"])

    if not USERNAME_RE.match(username):
        return {"error": "username must be 3-32 chars (letters, digits, _ . -)"}, 400

    if len(password) < 6:
        return {"error": "password must be at least 6 characters"}, 400

    try:
        if get_user(username):
            return {"error": "username already taken"}, 409

        create_user({
            "username": username,
            "password": hash_pass(password),
            "created": str(datetime.datetime.now()),
        })
    except Exception as exc:
        return {"error": f"database unavailable: {exc}"}, 503

    return {"msg": "registration successful"}, 201


def login_user(data):
    if data is None or not required(data, ["username", "password"]):
        return {"error": "username and password are required"}, 400

    username = str(data["username"]).strip()
    password = str(data["password"])

    try:
        user = get_user(username)
    except Exception as exc:
        return {"error": f"database unavailable: {exc}"}, 503

    if not user:
        return {"error": "invalid username or password"}, 401

    if not verify_pass(password, user.get("password")):
        return {"error": "invalid username or password"}, 401

    token = make_token(user["username"])
    return {"token": token, "username": user["username"]}, 200

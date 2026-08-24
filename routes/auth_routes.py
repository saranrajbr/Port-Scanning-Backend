from flask import Blueprint, jsonify, request

from controllers.auth_controller import login_user, register_user

auth_router = Blueprint("auth_router", __name__)


@auth_router.route("/register", methods=["POST"])
def register():
    result, status = register_user(request.get_json(silent=True))
    return jsonify(result), status


@auth_router.route("/login", methods=["POST"])
def login():
    result, status = login_user(request.get_json(silent=True))
    return jsonify(result), status


@auth_router.route("/me", methods=["GET"])
def me():
    from middleware.auth_middleware import verify_token
    payload = verify_token(request.headers)
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"username": payload.get("sub")}), 200

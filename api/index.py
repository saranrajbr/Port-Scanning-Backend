from flask import Flask, jsonify
from flask_cors import CORS

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from routes.auth_routes import auth_router
from routes.scan_routes import scan_router


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

app.register_blueprint(auth_router, url_prefix="/auth")
app.register_blueprint(scan_router, url_prefix="/api")


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "endpoint not found"}), 404


@app.errorhandler(500)
def server_error(_error):
    return jsonify({"error": "internal server error"}), 500

from flask import Flask
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from routes.auth_routes import auth_router
from routes.scan_routes import scan_router


app=Flask(__name__)

app.register_blueprint(auth_router,url_prefix="/auth")
app.register_blueprint(scan_router,url_prefix="/api")
from flask import Blueprint,request,jsonify
from controllers.auth_controller import register_user,create_user

auth_router=Blueprint("auth_router",__name__)


@auth_router.route("/register",methods=["POST"])
def register():
    data=request.json
    
    if not data:
        return jsonify({
            "error":"no data"
        }),400
        
    result=register_user(data)
    
    return jsonify(result)


@auth_router.route("/login",methods=["POST"])
def login():
    data=request.json
    
    if not data:
        return jsonify({
            "error":"no data"
        }),400
        
    result=create_user(data)
    
    return jsonify(result)
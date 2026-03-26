import jwt
import datetime
import hashlib
import os

from models.user_model import create_user,get_user
from utils.validator import required

from dotenv import load_dotenv
load_dotenv()


secret_key=os.environ.get("SECRET_KEY")

def hash_pass(passwd):
    return hashlib.sha256(
        passwd.encode()
    ).hexdigest()
    
    
def register_user(data):
    
    if not required(data,["username","password"]):
        return {"error":"requirement missing"}
    
    user=data["username"]
    passwd=data["password"]
    
    if get_user(user):
        return {"error":"user exists"}
    
    hashed_pass=hash_pass(passwd)
    
    create_user({
        "username":user,
        "password":hashed_pass,
        "created":str(datetime.datetime.now())
    })
    
    return {"msg":"successfully registered"}



def login_user(data):
    
    if not required(data,["username","password"]):
        return {"error":"requirement missing"}
    
    user=data["username"]
    passwd=data["password"]
    
    
    users=get_user(user)
    
    if not users:
        return {"error":"invalid user"}
    
    
    hashed_pass=hash_pass(passwd)
    
    if users["password"] != hashed_pass:
        return {"error","invalid password"}
    
    token=jwt.encode(
        {"user":user},
        secret_key,
        algorithm="HS256"
    )
    
    return {"token",token}

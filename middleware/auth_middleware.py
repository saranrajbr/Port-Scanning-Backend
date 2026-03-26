import jwt
import os
from dotenv import load_dotenv
load_dotenv()

secret_key=os.environ.get("SECRET_KEY")

def verify_token(header):
    auth=header.get("Authorization")
    
    if not auth:
        return False
    
    parts=auth.split(" ")
    
    if len(parts)!=2:
        return False
    
    token=parts[1]
    
    try:
        
        data=jwt.decode(token,secret_key,algorithms=["HS256"])
        return data
    except jwt.ExpiredSignatureError:
        return False
    
    except jwt.InvalidTokenError:
        return False
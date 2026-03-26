import os
from dotenv import load_dotenv
from pymongo import MongoClient
load_dotenv()
mongodburl=os.environ.get("MONGODB_URL")
client=MongoClient(mongodburl)
database=client["Scanner"]
userdata=database["user"]
scandata=database["scan"]
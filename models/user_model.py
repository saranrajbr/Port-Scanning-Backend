from config.db import userdata

def create_user(user):
    return userdata.insert_one(user)


def get_user(username):
    return userdata.find_one({
        "username":username
    })
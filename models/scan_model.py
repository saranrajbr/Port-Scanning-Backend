from config.db import scandata

def save_scan(scan):
    return scandata.insert_one(scan)


def get_scan(user):
    return scandata.find_one({
        "user":user
    })
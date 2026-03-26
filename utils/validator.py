def required(data,fields):
    for i in fields:
        if i not in data:
            return False
        
    return True
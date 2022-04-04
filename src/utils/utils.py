

def read_binary_file(fname):
    res = None
    
    try:
        with open(fname, 'rb') as f:
            res = f.read()
    except:
        pass
        
    return res
    
def write_binary_file(fname, data):
    try:
        with open(fname, 'wb') as f:
            f.write(data)
    except:
        return False

    return True
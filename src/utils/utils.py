"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge
"""

import configparser

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

def get_configuration(filename):
    """
    Retrieve a configuration handler of a filename.
    """
    config = configparser.ConfigParser()
    config.read(filename)
    return config
    
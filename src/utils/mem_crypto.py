"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge
"""

from cryptography.fernet import Fernet
import base64

class MemCrypto(object):
    '''
    Implements basic in-memory crypto operations.
    '''
    def __init__(self):
        self._fernet = None
        self._key = None
        
    def initialize(self):
        if (self._fernet is not None):
            return False
        
        self._key = Fernet.generate_key()
        self._fernet = Fernet(self._key)
        
        return True
        
    
    def initialize_with_key(self, key):
        if (self._fernet is not None):
            return False

        self._key = base64.urlsafe_b64encode(key)
        self._fernet = Fernet(self._key)
        
        return True
    
    
    def gen_mem_key(self):
        return Fernet.generate_key()
    
    def encrypt(self, data):
        if (self._fernet is None):
            return None
            
        return self._fernet.encrypt(data)
        
        
    def decrypt(self, data):
        if (self._fernet is None):
            return None
            
        return self._fernet.decrypt(data)
        
    def get_key(self):
        return self._key
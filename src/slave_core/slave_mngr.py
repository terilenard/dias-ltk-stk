'''
master_core/master_mngr

@author: Bela Genge
'''

import logging
import time
import datetime
import base64
import os
import sys

from pytpm.slavetpm import SlaveTPM
from slave_core.can_comm_handler import CanCommunications
from utils.utils import read_binary_file
from utils.mem_crypto import MemCrypto

class SlaveMngr(object):

    def __init__(self, shared_secret, ltk_size, stk_size, ext_pub_key,
            vbus_name, vbus_bitrate, ltk_st, stk_st):
        '''
        Constructor.
        '''
        super(SlaveMngr, self).__init__()
        
        self._shared_secret = shared_secret
        self._ltk_size = int(int(ltk_size) / 8)
        self._stk_size = int(int(stk_size) / 8)
        self._ext_pub_key = ext_pub_key
        
        self._ltk_idx = -1
        self._stk_idx = -1
        
        self._ltk_key = None
        
        self._can_commun = CanCommunications(vbus_name, vbus_bitrate, ltk_st, stk_st, self._on_new_ltk, self._on_new_stk)
        self._key_store = SlaveTPM()
        
        self._counter_ltk = 0
        self._counter_stk = 0
        
        self._mem_crypto = MemCrypto()
        self._mem_crypto.initialize_with_key(self._shared_secret.encode('utf-8'))
        
        self._running = False
        
    def _initialize(self):
        '''
        Runs the main init sequence.
        '''
        
        # Init key handlers
        self._key_store.init_key_handlers('SLAVE_TPMCTX')
        
        if not self._key_store.load_post_provision():
            logging.error("SlaveMngr: Couldn't load primary context and asymetric keys")
            sys.exit(1)
        
        logging.info("SlaveMngr: Loaded provisioned handlers")
        # Load external key
        logging.debug("Ext pub key value: {}".format(self._ext_pub_key))
        self._ext_pub_key_idx = self._key_store.load_external_key(self._ext_pub_key)
        if (self._ext_pub_key_idx < 0):
            logging.error("SlaveMngr: Unable to load external public key!")
            sys.exit(1)
        
        # Init CAN communications
        self._can_commun.initialize()
        
        logging.info("SlaveMngr: Init finalized!")
    
    def run_mngr_loop(self):
        logging.info("SlaveMngr: Started the main manager loop")
        
        # Run init sequence
        self._initialize()

        self._running = True
        while (self._running):
            try:
                #time.sleep(1)
                
                # Read the CAN bus for messages!
                self._can_commun.recv_msg()

            except Exception as ex:
                logging.error("Exception in core loop: " + str(ex))
                self._running = False
                break

    def stop_mngr_loop(self):
        if (self._running == True):
            self._running = False
            self._can_commun.cleanup()
            
            logging.info("SlaveMngr: Commun closed!")

    def _on_new_ltk(self, comp_pub, comp_sig):
        '''
        Callback when a new LTK is received.
        '''
        if (self._key_store.verify_signature(comp_pub, comp_sig, self._ext_pub_key_idx) == False):
            logging.error("SlaveMngr: SIGNATURE WAS NOT VERIFIED!")
            return
        
        logging.info("SlaveMngr: *** Signature successfully verified ***")
        
        # Now, decrypt the public component to obtain the LTK
        key = self._key_store.rsa_decrypt(comp_pub)
        if (key is None):
            logging.error("SlaveMngr: Unable to decrypt key!")
            return
        
        self._ltk_key  = key
        logging.info("SlaveMngr: Key successfully decrypted: " + str(key))
        
    def _on_new_stk(self, key_data):
        '''
        Callback when a new STK is received.
        '''
        if (self._ltk_key is None):
            logging.error("SlaveMngr: Got new STK, but LTK is None!")
            return
        
        try:
            mem_crypto = MemCrypto()
            mem_crypto.initialize_with_key(bytes(self._ltk_key))
            
            key_data = mem_crypto.decrypt(bytes(key_data))
        except Exception as ex:
            logging.error("SlaveMngr: Unable to verify MAC/decrypt data: " + str(ex))
            return
        
        if (len(key_data) < 32):
            logging.error("SlaveMngr: Invalid number of bytes received in key data:" + str(len(key_data)))
            return
        
        self._stk_idx = int.from_bytes(key_data[0:4], 'little')
        self._stk_key = bytearray(key_data[4:])
        
        logging.debug("SlaveMngr: *** NEW STK ID: " + str(self._stk_idx))
        logging.debug("SlaveMngr: *** NEW STK ID: " + str(self._stk_key))
        
        # Publish the new key locally
        local_enc_key = self._mem_crypto.encrypt(bytes(self._stk_key))

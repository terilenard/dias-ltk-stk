'''
master_core/master_mngr

@author: Bela Genge
'''

import logging
import time
import datetime
import base64
import os

from master_core.local_comm_handler import MasterLocalComm
from pytpm.mastertpm import MasterTPM
from master_core.can_comm_handler import CanCommunications
from utils.utils import read_binary_file
from utils.mem_crypto import MemCrypto

class MasterMngr(object):

    def __init__(self, shared_secret, ltk_size, stk_size, ext_pub_key,
            vbus_name, vbus_bitrate, ltk_st, stk_st):
        '''
        Constructor.
        '''
        super(MasterMngr, self).__init__()
        
        self._shared_secret = shared_secret
        self._ltk_size = int(int(ltk_size) / 8)
        self._stk_size = int(int(stk_size) / 8)
        self._ext_pub_key = ext_pub_key
        
        self._ltk_idx = -1
        self._stk_idx = 0
        
        self._ltk_key = None
        self._stk_key = None
        self._stk_pub_data = None
        
        self._local_commun = MasterLocalComm()
        self._can_commun = CanCommunications(vbus_name, vbus_bitrate, ltk_st, stk_st)
        self._key_store = MasterTPM()
        
        self._counter_ltk = 0
        self._counter_stk = 0
        
        self._running = False
        
    def _initialize(self):
        '''
        Runs the main init sequence.
        '''
        
        # Init local (pub/sub) communications
        self._local_commun.setup_communications()
        
        # Init key handlers
        self._key_store.init_key_handlers('MASTER_TPMCTX')
        
        # Load external key
        self._ext_pub_key_idx = self._key_store.load_external_key(self._ext_pub_key)
        if (self._ext_pub_key_idx < 0):
            logging.error("MasterMngr: Unable to load external public key!")
        
        # Init CAN communications
        self._can_commun.initialize()
        
        logging.info("MasterMngr: Init finalized!")
    
    def run_mngr_loop(self):
        logging.info("MasterMngr: Started the main manager loop")
        
        # Run init sequence
        self._initialize()

        self._running = True
        while (self._running):
            try:
                time.sleep(1)
                
                # Run Proto-LTK
                self._gen_ltk()
                
                # Run Proto-STK
                self._gen_stk()

            except Exception as ex:
                logging.exception("Exception in core loop: " + str(ex))
                self._running = False
                break

    def stop_mngr_loop(self):
        if (self._running == True):
            self._running = False
            self._local_commun.close_communications()
            self._can_commun.cleanup()
            
            logging.info("MasterMngr: Commun closed!")

    def _gen_ltk(self):
        '''
        Generate a new symmetric key - for data authentication.
        '''
        
        self._counter_ltk += 1
        if (self._counter_ltk % 20 != 0):
            return
        
        if (self._ltk_idx < 0):
            try:
                self._ltk_idx = self._key_store.generate_sealed_sym_key(self._ltk_size)
                self._stk_idx = -1
                self._ltk_key = None
                self._stk_key = None

            except Exception as ex:
                logging.error("MasterMngr: error while generating new symmetric key: " + str(ex))
                return
            
        if (self._ltk_idx < 0):
            logging.error("MasterMngr: unable to generate new LTK!")
            return
        
        res = self._key_store.export_sealed_sym_key(self._ext_pub_key_idx, self._ltk_idx)
        if (res is None):
            logging.error("MasterMngr: Unable to export symmetric key!")
            return
        
        # Unpack
        (pubencf, signf) = res

        # Load to memory
        mem_pubenc = read_binary_file(os.getcwd() + "/" + pubencf)
        mem_sign = read_binary_file(os.getcwd() + "/" + signf)
        
        if ((mem_pubenc is None) or (mem_sign is None)):
            logging.error("MasterMngr: Unable to read data from files!")
            return
        
        logging.info("MasterMngr: The public component was generated, len: " + str(len(mem_pubenc)))
        logging.info("MasterMngr: The signature was generated, len: " + str(len(mem_sign)))
        
        # Reset counter
        #self._counter_ltk = 0

        self._can_commun.send_ltk_pubk(mem_pubenc)
        self._can_commun.send_ltk_sig(mem_sign)


    def _gen_stk(self):
        '''
        Generates a new STK and publishes it periodically.
        '''
        if (self._ltk_idx < 0):
            return
        
        self._counter_stk += 1
        if (self._counter_stk % 5 != 0):
            return
        
        if (self._ltk_key is None):
            self._ltk_key = self._key_store.memory_export_sealed_key(self._ltk_idx)
            if (self._ltk_key is None):
                logging.error("MasterMngr: unable to export to LTK to memory!")
                return
            
            self._ltk_key = bytes(self._ltk_key)
        
        # Trigger a new STK every 10 s
        if (self._counter_stk % 10 == 0):
            self._stk_pub_data =  None
        
        if (self._stk_pub_data is None):
            # We have the LTK, now generate the new STK
            mem_crypto = MemCrypto()
            if (mem_crypto.initialize_with_key(self._ltk_key) == False):
                logging.error("MasterMngr: Unable to init crypto module!")
                self._ltk_key = None
                return

            # Generate a new STK
            self._stk_key = bytearray(mem_crypto.gen_mem_key())
            self._stk_idx += 1

            out_data = bytearray(self._stk_idx.to_bytes(4, 'little'))
            out_data.extend(self._stk_key)
            
            self._stk_pub_data = mem_crypto.encrypt(bytes(out_data))
            
            logging.info("MasterMngr: A new STK was generated: " + str(self._stk_key))
            logging.info("MasterMngr: A new STK auth frame was generated: " + str(self._stk_pub_data))

        # Reset counter
        #self._counter_stk = 0
        
        logging.info("MasterMngr: Sending STK frame: " + str(self._stk_pub_data))
        self._can_commun.send_stk(self._stk_pub_data)
        
        
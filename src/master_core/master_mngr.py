"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge, Teri Lenard
"""

import logging
import time
import os
import sys

from pytpm.mastertpm import MasterTPM
from master_core.can_comm_handler import CanCommunications
from utils.utils import read_binary_file
from utils.mem_crypto import MemCrypto
from master_core.client_mqtt import MQTTClient

class MasterMngr(object):

    def __init__(self, shared_secret, ltk_size, stk_size, ext_pub_key,
            vbus_name, vbus_bitrate, ltk_st, stk_st, ltk_cycle, stk_cycle,
            mqtt_user, mqtt_passwd, mqtt_host, mqtt_port):
        
        self._shared_secret = shared_secret
        self._ltk_size = int(int(ltk_size) / 8)
        self._stk_size = int(int(stk_size) / 8)
        self._ext_pub_key = ext_pub_key
        
        self._ltk_idx = -1
        self._stk_idx = 0
        
        self._ltk_key = None
        self._stk_key = None
        self._stk_pub_data = None

        self._ltk_cycle = ltk_cycle
        self._stk_cycle = stk_cycle
        self._ltk_timer = None
        self._stk_timer = None
        
        self._can_commun = CanCommunications(vbus_name, vbus_bitrate, ltk_st, stk_st)
        self._key_store = MasterTPM()
        
        self._counter_ltk = 0
        self._counter_stk = 0
        
        self._mqtt_client = MQTTClient(mqtt_user, mqtt_passwd, 
                                      mqtt_host, mqtt_port) 

        self._running = False
        
    def _initialize(self):
        '''
        Runs the main init sequence.
        '''
        
        # Init key handlers
        self._key_store.init_key_handlers('MASTER_TPMCTX')

        # Load provisioned handlers and keys
        
        if not self._key_store.load_post_provision():
            logging.error("MasterMngr: Couldn't load primary context and asymetric keys")
            sys.exit(1)
        
        logging.info("MasterMngr: Loaded provisioned handlers")
        
        # Load external key
        self._ext_pub_key_idx = self._key_store.load_external_key(self._ext_pub_key)
        if self._ext_pub_key_idx < 0:
            logging.error("MasterMngr: Unable to load external public key!")
            sys.exit(1)
        
        # Init CAN communications
        self._can_commun.initialize()

        logging.info("Connecting to mqtt broker")
        self._mqtt_client.connect()
        
        logging.info("MasterMngr: Init finalized!")

    def run_mngr_loop(self):
        logging.info("MasterMngr: Started the main manager loop")
        
        # Run init sequence
        self._initialize()

        # We should check if a LTK exits first and only then
        # generate a new one
        # If ASYMKEYCTX/KDISTROKEYS is not empty,
        # a LTK was already generated

        if len(os.listdir(self._key_store._f_kdk)) == 0:
            logging.info("MasterMngr: A LTK key was not found")
            logging.info("MasterMngr: Generating a new LTK key")
            self._gen_ltk()
        else:
            logging.info("MasterMngr: LTK was already distributed")
            logging.debug(os.listdir(self._key_store._f_kdk))
            logging.debug("Len dir " + str(len(os.listdir(self._key_store._f_kdk))))
            self._load_ltk()

        self._running = True
        while self._running:
            try:
                time.sleep(1)
                
                #Run Proto-STK
                self._gen_stk()
            except Exception as ex:
                logging.exception("Exception in core loop: " + str(ex))
                self._running = False

    def stop_mngr_loop(self):

        # if not self._key_store.flush_handlers():
        #     logging.error("MasterMngr: Couldn't flush key handlers")

        # logging.info("MasterMngr: Flushed key handlers successfully")

        if self._running:
            self._running = False
            self._can_commun.cleanup()
            
            logging.info("MasterMngr: Commun closed!")

        if self._mqtt_client.is_connected():
            self._mqtt_client.stop()
            logging.info("SlaveMngr: MQTT communication closed")

    def _load_ltk(self):

        self._ext_pub_key_idx = 1
        self._ltk_idx = 1

        res = self._key_store.load_sealed_sym_key(self._ext_pub_key_idx, self._ltk_idx)
        if res is None:
            logging.error("MasterMngr: Unable to export symmetric key!")
            return
        
        # Unpack
        (pubencf, signf) = res

        # Load to memory
        mem_pubenc = read_binary_file(os.getcwd() + "/" + pubencf)
        mem_sign = read_binary_file(os.getcwd() + "/" + signf)
        
        if (mem_pubenc is None) or (mem_sign is None):
            logging.error("MasterMngr: Unable to read data from files!")
            return

    def _gen_ltk(self):
        '''
        Generate a new symmetric key - for data authentication.
        '''
        self._counter_ltk += 1
        if self._counter_ltk % self._ltk_cycle != 0:
            return
        
        if self._ltk_idx < 0:
            try:
                self._ltk_idx = self._key_store.generate_sealed_sym_key(self._ltk_size)
                self._stk_idx = -1
                self._ltk_key = None
                self._stk_key = None

            except Exception as ex:
                logging.error("MasterMngr: error while generating new symmetric key: " + str(ex))
                return
            
        if self._ltk_idx < 0:
            logging.error("MasterMngr: unable to generate new LTK!")
            return
        
        res = self._key_store.export_sealed_sym_key(self._ext_pub_key_idx, self._ltk_idx)
        if res is None:
            logging.error("MasterMngr: Unable to export symmetric key!")
            return
        
        # Unpack
        (pubencf, signf) = res

        # Load to memory
        mem_pubenc = read_binary_file(os.getcwd() + "/" + pubencf)
        mem_sign = read_binary_file(os.getcwd() + "/" + signf)
        
        if (mem_pubenc is None) or (mem_sign is None):
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

        if self._ltk_idx < 0:
            return
        
        self._counter_stk += 1
        if self._counter_stk % self._stk_cycle != 0:
            return
        
        if self._ltk_key is None:
            self._ltk_key = self._key_store.memory_export_sealed_key(self._ltk_idx)
            if self._ltk_key is None:
                logging.error("MasterMngr: unable to export to LTK to memory!")
                return
            
            self._ltk_key = bytes(self._ltk_key)
        
        # Trigger a new STK every 10 s
        if self._counter_stk % self._stk_cycle == 0:
            self._stk_pub_data =  None
        
        if self._stk_pub_data is None:
            # We have the LTK, now generate the new STK
            mem_crypto = MemCrypto()
            if mem_crypto.initialize_with_key(self._ltk_key) == False:
                logging.error("MasterMngr: Unable to init crypto module!")
                self._ltk_key = None
                return

            # Generate a new STK
            self._stk_key = bytearray(mem_crypto.gen_mem_key())
            self._stk_idx += 1

            out_data = bytearray(self._stk_idx.to_bytes(4, 'little'))
            out_data.extend(self._stk_key)
            
            self._stk_pub_data = mem_crypto.encrypt(bytes(out_data))
            
            logging.info("MasterMngr: A new STK was generated: " + str(bytes(out_data)))
            logging.info("MasterMngr: A new STK auth frame was generated: " + str(self._stk_pub_data))

        # Reset counter
        #self._counter_stk = 0
        
        if self._stk_pub_data:

            logging.info("MasterMngr: Sending STK to MQTT: " + str(out_data))
            self._mqtt_client.publish_key(out_data[4:])

            logging.info("MasterMngr: Sending STK frame: " + str(self._stk_pub_data))
            self._can_commun.send_stk(self._stk_pub_data)
 
"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge, Teri Lenard
"""

import logging
import sys
import os

from pytpm.slavetpm import SlaveTPM
from slave_core.can_comm_handler import CanCommunications
from utils.mem_crypto import MemCrypto
from utils.utils import read_binary_file
from slave_core.client_mqtt import MQTTClient


class SlaveMngr(object):

    def __init__(self, shared_secret, ltk_size, stk_size, ext_pub_key,
                 vbus_name, vbus_bitrate, ltk_st, stk_st,
                 mqtt_user, mqtt_passwd, mqtt_host, mqtt_port):
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
        
        self._mqtt_client = MQTTClient(mqtt_user, mqtt_passwd, 
                                       mqtt_host, mqtt_port) 
        
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
        self._ext_pub_key_idx = self._key_store.load_external_key(self._ext_pub_key)
        if (self._ext_pub_key_idx < 0):
            logging.error("SlaveMngr: Unable to load external public key!")
            sys.exit(1)
        
        logging.info("SlaveMngr: Checking for LTK key")
        if (os.path.isfile(self._key_store.ltk_path)):
            self._ltk_key = read_binary_file(self._key_store.ltk_path)

        if self._ltk_key:
            logging.info("SlaveMngr: LTK key loaded")
        else:
            logging.warning("SlaveMngr: Could not read LTK key")
        # Init CAN communications
        self._can_commun.initialize()

        logging.info("Connecting to mqtt broker")
        self._mqtt_client.connect()
        
        logging.info("SlaveMngr: Init finalized!")
    
    def run_mngr_loop(self):
        logging.info("SlaveMngr: Started the main manager loop")
        
        # Run init sequence
        self._initialize()
        self._running = True
        while self._running:
            try:
                # Read the CAN bus for messages!
                self._can_commun.recv_msg()

            except Exception as ex:
                logging.error("Exception in core loop: " + str(ex))
                self._running = False
                break

    def stop_mngr_loop(self):

        if self._running:
            self._running = False
            self._can_commun.cleanup()
            
            logging.info("SlaveMngr: CAN communication closed")
        
        if self._mqtt_client.is_connected():
            self._mqtt_client.stop()
            logging.info("SlaveMngr: MQTT communication closed")

    def _on_new_ltk(self, comp_pub, comp_sig):
        '''
        Callback when a new LTK is received.
        '''

        logging.info("SlaveMngr: On new LTK")

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
        
        # Publish the new key locally
        self._mqtt_client.publish_key(self._stk_key)
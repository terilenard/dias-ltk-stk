'''
KeyManager/master_core/local_comm_handler.py

@author: Bela Genge
'''

import logging
import time
import datetime
from threading import Lock

from comm_core import (
    MASTER_KEYMNGR_PUBSUB_ADDRESS, KEYMNGR_FRESHKEY_TOPIC)

from comm_core.communicator import Communicator
from comm_core.keymngr_pb2 import FreshDataAuthKey

class MasterLocalComm(object):

    def __init__(self):
        '''
        Constructor.
        '''
        super(MasterLocalComm, self).__init__()
        
        self._communicator = None
        
    def setup_communications(self):
        '''
        Method that sets-up the pub/sub communication channels.
        '''
        logging.info("MasterLocalComm: Setting up ZeroMQ communications")

        self._communicator = Communicator(
            None,
            None,
            MASTER_KEYMNGR_PUBSUB_ADDRESS,
            [],
            [])

        self._publish = self._communicator.publish

        return True

    def close_communications(self):
    
        if (self._communicator is not None):
            self._communicator.stop()

    def pub_fresh_key(self, key_idx, key_value):
        '''
        Publishes a new fresh key.
        '''

        report = FreshDataAuthKey()
        report.key_id = key_idx
        report.key_value = key_value

        self._publish(KEYMNGR_FRESHKEY_TOPIC, report.SerializeToString())


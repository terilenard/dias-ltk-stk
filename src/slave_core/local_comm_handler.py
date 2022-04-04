'''
KeyManager/slave_core/local_comm_handler.py

@author: Bela Genge
'''

import logging
import time
import datetime
from threading import Lock

from comm_core import (
    SLAVE_KEYMNGR_PUBSUB_ADDRESS, KEYMNGR_FRESHKEY_TOPIC)

from comm_core.communicator import Communicator
from comm_core.keymngr_pb2 import FreshDataAuthKey

class SlaveLocalComm(object):

    def __init__(self):
        '''
        Constructor.
        '''
        super(SlaveLocalComm, self).__init__()
        
        self._communicator = None
        
    def setup_communications(self):
        '''
        Method that sets-up the pub/sub communication channels.
        '''
        logging.info("SlaveLocalComm: Setting up ZeroMQ communications")

        self._communicator = Communicator(
            None,
            None,
            SLAVE_KEYMNGR_PUBSUB_ADDRESS,
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


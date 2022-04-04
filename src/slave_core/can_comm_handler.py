'''
slave_core/can_comm_handler

@author: Bela Genge
'''

import logging
import time
import datetime

import can
from slave_core.ltk_proc import LtkProc
from slave_core.stk_proc import StkProc

class CanCommunications():

    def __init__(self, vbus_name, bitrate, ltk_st, stk_st, clbk_new_ltk, clbk_new_stk):
        '''
        Constructor.
        '''
        super(CanCommunications, self).__init__()
        
        self._vbus_name = vbus_name
        self._bitrate = bitrate
        self._ltk_st = int(ltk_st, 16)
        self._stk_st = int(stk_st, 16)

        self._ltk_proc = LtkProc(self._ltk_st, self._on_new_ltk)
        self._callback_ltk = clbk_new_ltk
        
        self._stk_proc = StkProc(self._stk_st, self._on_new_stk)
        self._callback_stk = clbk_new_stk

        self._vbus = None
        self._buffer = None
        self._notifier = None


    def initialize(self):
        '''
        Method that sets-up the CAN communication channel.
        '''
        logging.info("CanCommunications: Setting up CAN communications...: " + str(self._vbus_name))
        
        try:
            self._vbus = can.interface.Bus(bustype='socketcan',
                                channel=self._vbus_name, bitrate=self._bitrate)
            #self._buffer = can.BufferedReader()
            #self._notifier = (self._vbus, [_get_message, self._buffer])

        except Exception as ex:
            logging.error("CanCommunications: Unable to set-up CAN communications: " + str(ex))
            return False

        logging.info("CanCommunications: Success!")

        return True

    def recv_msg(self):
    
        try:
            msg = self._vbus.recv(0.1)
            if (msg is not None):                
                if (self._ltk_proc.on_fragment(msg.arbitration_id, msg.data) == True):
                    return
                
                self._stk_proc.on_fragment(msg.arbitration_id, msg.data)

        except Exception as ex:
            logging.info("CanCommunications: exception while receiving: " + str(ex))

    def cleanup(self):
        if (self._vbus is not None):
            self._notifier.stop()
            self._vbus.shutdown()

    def _on_new_ltk(self, comp_pub, comp_sig):
        '''
        Callback received once a new LTK sequence is fully received.
        '''
        self._callback_ltk(comp_pub, comp_sig)
        
    def _on_new_stk(self, key_data):
        '''
        Callback received once a new STK sequence is fully received.
        '''
        self._callback_stk(key_data)
"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge, Teri Lenard
"""

import logging

from slave_core.ltk_proc import LtkProc
from slave_core.stk_proc import StkProc
from pycan import Pycan


class CanCommunications():

    def __init__(self, vbus_name, bitrate, ltk_st, stk_st, clbk_new_ltk, clbk_new_stk):
        '''
        Constructor.
        '''
        super(CanCommunications, self).__init__()
        
        self._vbus_name = vbus_name
        self._pycan = Pycan(self._vbus_name,
                            on_message_callback=self._on_recv_msg)
        self._bitrate = bitrate
        self._ltk_st = int(ltk_st, 16)
        self._stk_st = int(stk_st, 16)

        self._ltk_proc = LtkProc(self._ltk_st, self._on_new_ltk)
        self._callback_ltk = clbk_new_ltk
        
        self._stk_proc = StkProc(self._stk_st, self._on_new_stk)
        self._callback_stk = clbk_new_stk

    def initialize(self):
        '''
        Method that sets-up the CAN communication channel.
        '''
        logging.info("CanCommunications: Setting up CAN communications...: " + str(self._vbus_name))
        
        try:
            self._pycan.start()
        except Exception as ex:
            logging.error("CanCommunications: Unable to set-up CAN communications: " + str(ex))
            return False

        logging.info("CanCommunications: Success!")

        return True

    def _on_recv_msg(self, msg):
        if msg is not None:
            if self._ltk_proc.on_fragment(msg.arbitration_id, msg.data):
                return
                
            self._stk_proc.on_fragment(msg.arbitration_id, msg.data)

    def cleanup(self):
        if self._pycan.is_running():
            logging.info("Stopping the pycan")
            self._pycan.stop()
            logging.info("Pycan stopped")

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
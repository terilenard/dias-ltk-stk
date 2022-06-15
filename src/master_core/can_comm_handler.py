"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge, Teri Lenard
"""

import logging

import can


class CanCommunications():

    def __init__(self, vbus_name, bitrate, ltk_st, stk_st):
        '''
        Constructor.
        '''
        super(CanCommunications, self).__init__()
        
        #can.util.set_logging_level("info")
        
        self._vbus_name = vbus_name
        self._bitrate = bitrate
        self._ltk_st = int(ltk_st, 16)
        self._stk_st = int(stk_st, 16)
        
        # Compute the start and end frame arbitration ID for LTK
        self._ltk_pub_st = self._ltk_st
        self._ltk_pub_end = self._ltk_pub_st + 50
        self._ltk_sig_st = self._ltk_pub_end + 1
        self._ltk_sig_end = self._ltk_sig_st + 50
        
        # Compute the start and end frame arbitration ID for STK
        self._stk_end = self._stk_st + 50

        self._vbus = None


    def initialize(self):
        '''
        Method that sets-up the CAN communication channel.
        '''
        logging.info("CanCommunications: Setting up CAN communications...: " + str(self._vbus_name))
        
        try:
            self._vbus = can.interface.Bus(bustype='socketcan',
                                channel=self._vbus_name, bitrate=self._bitrate)
        except Exception as ex:
            logging.error("CanCommunications: Unable to set-up CAN communications: " + str(ex))
            return False

        logging.info("CanCommunications: Success!")

        return True

    def cleanup(self):
        if (self._vbus is not None):
            self._vbus.shutdown()

    def send_ltk_pubk(self, data):
        
        self._send_data(data, self._ltk_pub_st, self._ltk_pub_end)
        
        
    def send_ltk_sig(self, data):
        
        self._send_data(data, self._ltk_sig_st, self._ltk_sig_end)
    
    def send_stk(self, data):
        self._send_data(data, self._stk_st, self._stk_end)
    
    def _send_data(self, data, arbitr_st, arbitr_end):
        
        if (self._vbus is None):
            logging.error("CanCommunications: Communications not initialized!")
            return
            
        try:
            data_idx = 0
            can_idx = 0
            
            # First, send the number of outgoing fragments in the first CAN message
            frg_count = int(len(data) / 8)
            if (len(data) % 8 != 0):
                frg_count += 1
            msg = can.Message(arbitration_id=arbitr_st,
                        data=frg_count.to_bytes(2, 'little'),
                        is_extended_id=True)
            self._vbus.send(msg)
            
            can_idx += 1
            
            while (data_idx < len(data)):
            
                # In case we have a full payload
                if ((data_idx + 8) <= len(data)):
                    msg = can.Message(arbitration_id=arbitr_st,
                        data=data[data_idx:(data_idx+8)],
                        is_extended_id=True)

                    self._vbus.send(msg)
                    can_idx += 1
                    
                # In case we have at least one element
                elif ((len(data) - data_idx) > 0):
                    msg = can.Message(arbitration_id=arbitr_st,
                        data=data[data_idx:(len(data))],
                        is_extended_id=True)
                        
                    self._vbus.send(msg)
                    can_idx += 1
                else:
                    break

                data_idx += 8

            # Lastly, send the end of transmission CID frame
            msg = can.Message(arbitration_id=arbitr_st,
                        data=[],
                        is_extended_id=True)
            self._vbus.send(msg)

        except Exception as ex:
            logging.error("CanCommunications: Error while building/sending CAN frame: " + str(ex))
        
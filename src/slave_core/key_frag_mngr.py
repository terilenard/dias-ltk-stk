"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge, Teri Lenard
"""

import logging

class KeyFragMngr(object):

    def __init__(self, id_st, id_end, clbk_on_fragend):
        '''
        Constructor.
        '''
        super(KeyFragMngr, self).__init__()
        
        self._id_st = id_st
        self._id_end = id_end
        self._frags = []
        self._callback = clbk_on_fragend
        self.frag_counter = 0
        self.frag_count = 0
    
    def on_fragment(self, can_id, payload):
        '''
        Called once a new fragment is received.
        '''

        # On the first message frag_counter should be 0.
        # Do we need to increment frag_counter after the first message? Or only after the second?
  
        if self._id_st == (can_id + self.frag_counter):
            logging.info("KeyFragMngr: start of new fragment sequence: " + str(can_id))
            
            # Extract fragment count
            try:
                self.frag_count = int.from_bytes(payload, 'little')
                if (self.frag_count > 255):
                    logging.error("KeyFragMngr: weird, a large number of fragments will be allocated: " + str(self.frag_count))
                else:
                    logging.info("KeyFragMngr: start message received, creating fragment count: " + str(self.frag_count) )
                
               # self._frags = [None] * frag_count
                self._frags = []
                self.frag_counter = self.frag_counter + 1 
            except Exception as ex:
                logging.error("KeyFragMngr: cannot process fragment: " + str(ex))
                
            return True


        if (self.frag_counter > self.frag_count):
            logging.info("KeyFragMngr: end of new fragment sequence: " + str(can_id))
            
            self._callback()
            
            return True
        else:
            if self.frag_count == 0:
                self.frag_counter = 0
                logging.error("KeyFragMngr: Null terminator received")
                return True

            self._frags.append(payload)
            # logging.debug("Frag {} {}".format(self.frag_counter, self._frags[self.frag_counter-1].hex()))
            self.frag_counter = self.frag_counter + 1
            return True
            
        return False

    def defragment_data(self):
        if (len(self._frags) <= 0):
            return None
        
        ret = bytearray()
        idx = 0
        
        while (idx < len(self._frags)):
            if (self._frags[idx] is None):
                logging.error("KeyFragMngr: None item at index: " + str(idx))
                return None
        
            ret.extend(self._frags[idx])
            idx += 1
        
        return ret
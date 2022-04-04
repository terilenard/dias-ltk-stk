'''
slave_core/key_frag_mngr

@author: Bela Genge
'''

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
    
    def on_fragment(self, can_id, payload):
        '''
        Called once a new fragment is received.
        '''
        
        if (self._id_st == can_id):
            logging.info("KeyFragMngr: start of new fragment sequence: " + str(can_id))
            
            # Extract fragment count
            try:
                frag_count = int.from_bytes(payload, 'little')
                if (frag_count > 255):
                    logging.error("KeyFragMngr: weird, a large number of fragments will be allocated: " + str(frag_count))
                else:
                    logging.info("KeyFragMngr: start message received, creating fragment count: " + str(frag_count) )
                
                self._frags = [None] * frag_count
            except Exception as ex:
                logging.error("KeyFragMngr: cannot process fragment: " + str(ex))
                
            return True

        elif (self._id_end == can_id):
            logging.info("KeyFragMngr: end of new fragment sequence: " + str(can_id))
            
            self._callback(can_id)
            
            return True
        elif ((can_id > self._id_st) and (can_id < self._id_end)):
        
            if (len(self._frags) <= 0):
                logging.error("KeyFragMngr: fragment list not yet initialized!!")
                return True
        
            pos = can_id - self._id_st - 1
            if (self._frags[pos] is not None):
                logging.error("KeyFragMngr: A fragment already exists on this position: " + str(pos))
                
            self._frags[pos] = payload
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
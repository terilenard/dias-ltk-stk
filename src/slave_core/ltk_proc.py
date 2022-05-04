"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge, Teri Lenard
"""

import logging

from slave_core.key_frag_mngr import KeyFragMngr

class LtkProc(object):

    def __init__(self, id_st, clbk_new_ltk):
        '''
        Constructor.
        '''
        super(LtkProc, self).__init__()
        
        # Compute the end frame arbitration ID
        self._ltk_pub_st = 1044736
        self._ltk_pub_end = self._ltk_pub_st #+ 50
        self._ltk_sig_st = 1044787
        self._ltk_sig_end = self._ltk_sig_st #+ 50
        
        logging.info("LtkProc: st: " + str(self._ltk_pub_st))
        
        self._pub = KeyFragMngr(self._ltk_pub_st, self._ltk_pub_end, self._on_frag_pub_completed)
        self._sig = KeyFragMngr(self._ltk_sig_st, self._ltk_sig_end, self._on_frag_sig_completed)
        
        self._callback_ltk = clbk_new_ltk
        
        self._pubdata = None
        self._sigdata = None
    
    def on_fragment(self, can_id, payload):

        if can_id == self._ltk_pub_st:
            self._pub.on_fragment(can_id, payload)
            return True
        elif can_id == self._ltk_sig_st:
            self._sig.on_fragment(can_id, payload)
            return True
        else:
            return False
    
    def _on_frag_pub_completed(self):
        self._pub.frag_counter = 0
        self._pubdata = self._pub.defragment_data()

    def _on_frag_sig_completed(self):
        self._pub.frag_counter = 0
        self._sigdata = self._sig.defragment_data()
        self._on_complete()

    def _on_frag_completed(self, can_id):
        '''
        Method overriden from base class once a fragment sequence is completed.
        '''
        
        if (can_id == self._ltk_pub_end):
            self._pubdata = self._pub.defragment_data()
        elif (can_id == self._ltk_sig_end):
            self._sigdata = self._sig.defragment_data()
            
            # Now try to use the components
            self._on_complete()
        else:
            logging.error("LtkProc: unknown end ID: " + str(can_id))
                
    def _on_complete(self):
        '''
        Called when all components should have been successfully completed.
        '''
        if (self._pubdata is None or self._sigdata is None):
            logging.error("LtkProc: reached completed state with non-available parts ")
            return

        logging.info("LtkProc: REACHED END OF STATE MACHINE!")
        
        self._callback_ltk(self._pubdata, self._sigdata)
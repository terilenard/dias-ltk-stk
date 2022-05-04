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

class StkProc(object):

    def __init__(self, id_st, clbk_new_stk):
        '''
        Constructor.
        '''
        super(StkProc, self).__init__()
        
        # Compute the end frame arbitration ID
        self._stk_st = 1044992
        self._stk_end = self._stk_st #+ 50
        
        logging.info("StkProc: st: " + str(self._stk_st))
        
        self._frag_mngr = KeyFragMngr(self._stk_st, self._stk_end, self._on_frag_completed)

        self._callback_stk = clbk_new_stk
        
        self._key_data = None
    
    def on_fragment(self, can_id, payload):
        return self._frag_mngr.on_fragment(can_id, payload)    
    
    def _on_frag_completed(self):
        '''
        Method overriden from base class once a fragment sequence is completed.
        '''
        self._key_data = self._frag_mngr.defragment_data()
            
            # Now try to use the components
        self._frag_mngr.frag_counter = 0
        self._on_complete()
                
    def _on_complete(self):
        '''
        Called when all components should have been successfully completed.
        '''
        if (self._key_data is None):
            logging.error("StkProc: reached completed state with non-available parts ")
            return

        logging.info("StkProc: REACHED END OF STATE MACHINE!")
        
        self._callback_stk(self._key_data)
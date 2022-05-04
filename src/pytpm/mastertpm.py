"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge
"""

from pytpm.coretpm import CoreTPM

class MasterTPM(CoreTPM):
    '''
    A class that defines the basic method to set up and operate a Master TPM
    '''

    def __init__(self):
        '''
        Constructor.
        '''
        CoreTPM.__init__(self)
    
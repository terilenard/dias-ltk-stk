# This is the implementation of the Master TPM (connected to the CCU).

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
    
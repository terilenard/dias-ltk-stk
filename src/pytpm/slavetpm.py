# This is the implementation of the Slave TPM (connected to the CCU).

from pytpm.coretpm import CoreTPM

class SlaveTPM(CoreTPM):
    '''
    A class that defines the basic method to set up and operate a Slave TPM
    '''

    def __init__(self):
        '''
        Constructor.
        '''
        CoreTPM.__init__(self)
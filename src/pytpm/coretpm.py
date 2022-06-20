"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge, Teri Lenard
"""

from pytpm.tpm2tools import *

from random import randint
from utils.utils import write_binary_file, read_binary_file
import logging
logger = logging.getLogger(__name__)

TPM2T_PRIMARYCTX_FILE = "primary.ctx"
TPM2T_PRIMARYCTX_PERSFILE = "persprimary.ctx"

TPM2T_PUBCTX_FOLDER = "ASYMKEYCTX"
TPM2T_PUBCTX_FILE = "pubk.ctx"
TPM2T_PRVCTX_FILE = "prvk.ctx"
TPM2T_LOADEDPUBKCTX_FILE = "loadedk.ctx"
TPM2T_PUBCTX_PERSFILE = "perspubk.ctx"

TPM2T_SYMKPUBPART = "sympub.ctx"
TPM2T_SYMKSENSPART = "symsens.ctx"

TPM2T_EXTKEYSTORE_FOLDER = "EXTKEYSTORE"
TPM2T_EXTNAME_FILE = "extkey"
TPM2T_EXTEXTENSION_FILE = ".ctx"

TPM2T_KDISTRO_FOLDER = "KDISTROKEYS"
TPM2T_KDISTROENCEX_FILE = "pkextenc"
TPM2T_KDISTROPRPUB_FILE = "pkprim_pubenc"
TPM2T_KDISTROPRSENS_FILE = "pkprim_sensenc"
TPM2T_KDISTROPRLOADED_FILE = "pkprim_loaded"
TPM2T_KDISTROSIGNEX_FILE = "sign"
TPM2T_KDISTROEXT_FILE = ".dat"

#TPM2T_SYMPUBNAME_FILE = "symkey_pub"
#TPM2T_SYMSENSNAME_FILE = "symkey_sens"
#TPM2T_SYMEXTENSION_FILE = ".ctx"
#TPM2T_SYMKEYLOADED_FILE = "loadedk"

TPM2T_MHMACKEY_FOLDER = "MHMACKEYS"

TPM2T_TEMP1_FILE = "tpmtemp1.dat"
TPM2T_TEMP2_FILE = "tpmtemp2.dat"
TPM2T_TEMP3_FILE = "tpmtemp3.dat"
TPM2T_TEMP4_FILE = "tpmtemp4.dat"
TPM2T_TEMP5_FILE = "tpmtemp5.dat"

TPM2T_SIGDATA_FILE = "tpmsigdata"
TPM2T_SIGSIG_FILE = "tpmsigsig"
TPM2T_DEC_FILE = "tpmdecf"

class CoreTPM(object):
    '''
    A class that defines the basic method to set up and operate a Master TPM
    '''

    def __init__(self):
        '''
        Constructor.
        '''
        super(CoreTPM, self).__init__()

        # Define basic handlers for the primary key
        self._h_primaryk = None
        self._hp_primaryk = None # persistent
        self._f_primaryk = None

        # Define basic handlers for the public/private 
        self._h_pub_asymk = None
        self._hl_pub_asymk = None # loaded
        self._hp_pub_asymk = None # persistent
        self._h_sens_asymk = None
        self._f_asymk = None

        # Define handlers and data structures for the external keys
        self._f_ext = None
        self._ext_keys = {}
        self._ext_idx = 1

        # Define handlers and data structures for distributed keys
        self._f_kdk = None
        self._kd_keys = {}
        self._kd_idx = 1

        # Define handlers and data structure for managed hmac keys
        self._f_hmack = None
        self._hmac_keys = {}
        self._hmac_idx = 1

        self.ltk_path = None
        
    
    def init_key_handlers(self, folderName):
        '''
        Initialize basic key handlers - assuming that the Master TPM has been properly provisioned!
        '''
        # Store the base folder and set the primary key handler
        self._f_primaryk = folderName
        self._h_primaryk = self._f_primaryk + "/" + TPM2T_PRIMARYCTX_FILE
        self._hp_primaryk = self._f_primaryk + "/" + TPM2T_PRIMARYCTX_PERSFILE
        
        # Also prepare the folder identifier for the external keys
        self._f_ext = self._f_primaryk + "/" + TPM2T_EXTKEYSTORE_FOLDER
        
        self._f_asymk = self._f_primaryk + "/" + TPM2T_PUBCTX_FOLDER
        self._h_pub_asymk = self._f_asymk + "/" + TPM2T_PUBCTX_FILE
        self._hl_pub_asymk = self._f_asymk + "/" + TPM2T_LOADEDPUBKCTX_FILE
        self._hp_pub_asymk = self._f_asymk + "/" +  TPM2T_PUBCTX_PERSFILE
        self._h_sens_asymk = self._f_asymk + "/" + TPM2T_PRVCTX_FILE
        
        # Prepare the folder for the symmetric keys
        self._f_kdk = self._f_asymk + "/" + TPM2T_KDISTRO_FOLDER
        
        # Prepare the folder for managed hmac keys
        self._f_mhmack = self._f_asymk + "/" + TPM2T_MHMACKEY_FOLDER

        self.ltk_path = self._f_ext + "/" + TPM2T_DEC_FILE + "1" + ".dat"


    def load_post_provision(self):

        TPM2_DICTIONARY_LOCKOUT()

        #self.flush_handlers()
        
        if (TPM2_Provision(self._f_primaryk, TPM2T_PRIMARYCTX_FILE) == False):
            print("Creating primary.ctx failed")
            return False

        if (TPM2_LoadKey(self._h_primaryk, self._h_pub_asymk, self._h_sens_asymk, self._hl_pub_asymk) == False):
            print("Loading asymetric keys failed")
            return False
        
        return True

    def flush_handlers(self):
        return TPM2_FlushContext()
        
    def provision_core(self, folderName):
        '''
        The main Master/Slave TPM provisioning method.
        '''

        # Store the base folder and set the primary key handler
        self._f_primaryk = folderName
        self._h_primaryk = self._f_primaryk + "/" + TPM2T_PRIMARYCTX_FILE
        self._hp_primaryk = self._f_primaryk + "/" + TPM2T_PRIMARYCTX_PERSFILE

        # Also prepare the folder identifier for the external keys
        self._f_ext = self._f_primaryk + "/" + TPM2T_EXTKEYSTORE_FOLDER

        # First, flush any transient objects
        if (TPM2_FlushContext() == False):
            return False

        # Provision the primary key
        if (TPM2_Provision(self._f_primaryk, TPM2T_PRIMARYCTX_FILE) == False):
            return False

        self._f_asymk = folderName + "/" + TPM2T_PUBCTX_FOLDER
        self._h_pub_asymk = self._f_asymk + "/" + TPM2T_PUBCTX_FILE
        self._hl_pub_asymk = self._f_asymk + "/" + TPM2T_LOADEDPUBKCTX_FILE
        self._hp_pub_asymk = self._f_asymk + "/" +  TPM2T_PUBCTX_PERSFILE
        self._h_sens_asymk = self._f_asymk + "/" + TPM2T_PRVCTX_FILE

        # Next, create an exportable private/public key pair. The public key can be extracted and included in a certificate.
        # The certificate, including the public part can then be distributed and used to verify signatures.
        if (TPM2_CreateAsymKey(self._h_primaryk, self._f_asymk, TPM2T_PUBCTX_FILE, TPM2T_PRVCTX_FILE) == False):
            return False

        # Lastly, make the two prior objects persistent in the TPM
        #if (TPM2_EvictControl(self._h_primaryk, self._hp_primaryk) == False):
        #    return False

        # For the second key, we need to load it first to the TPM transient object area
        if (TPM2_LoadKey(self._h_primaryk, self._h_pub_asymk, self._h_sens_asymk, self._hl_pub_asymk) == False):
            return False

        #if (TPM2_EvictControl(self._hl_pub_asymk, self._hp_pub_asymk) == False):
        #    return False

        # Prepare the folder for the symmetric keys
        self._f_kdk = self._f_asymk + "/" + TPM2T_KDISTRO_FOLDER
        if (TPM2_CreateFolder(self._f_kdk) == False):
            return False

        # Prepare the folder for managed hmac keys
        self._f_mhmack = self._f_asymk + "/" + TPM2T_MHMACKEY_FOLDER
        if (TPM2_CreateFolder(self._f_mhmack) == False):
            return False

        return True


    def load_external_key(self, keyFileName, tpm_ctx=True):
        '''
        Loads an external key (as transient) and stores it in a special folder.
        '''

        # Prepare the handlers and new (internal) identifier
        # self._ext_idx = self._ext_idx + 1
        self._ext_keys[self._ext_idx] = self._f_ext + "/" + TPM2T_EXTNAME_FILE + str(self._ext_idx) + TPM2T_EXTEXTENSION_FILE

        alg_type = None
        if (tpm_ctx == False):
            alg_type = "rsa"

        if (TPM2_LoadExternalPubKey(keyFileName, self._f_ext, alg_type, TPM2T_EXTNAME_FILE + str(self._ext_idx) + TPM2T_EXTEXTENSION_FILE) == True):
            return self._ext_idx

        return -1


    def generate_ext_sym_key(self, ext_key_idx, key_size):
        '''
        Generate a new symmetric key and seal it with the external key.
        '''

        if (ext_key_idx not in self._ext_keys):
            print("External key not found in internal keystore: " + str(ext_key_id))
            return None

        # Generate the sequence of random bytes and stores them in a given file

        # Prepare the handlers and new (internal) identifier
        #self._sym_idx = self._sym_idx + 1
        #pubk = self._f_symk + "/" + TPM2T_SYMPUBNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #sensk = self._f_symk + "/" + TPM2T_SYMSENSNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #self._sym_keys[self._sym_idx] = (pubk, sensk, None)

        # Generate a random sequence of bytes - this will constitute the new symmetric key
        randf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
        if (TPM2_Getrandom(key_size, randf) == False):
            return None

        # Encrypt the key with the external key
        pubencf = self._f_kdk + "/" + TPM2T_KDISTROENCEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_RSAEncrypt(self._ext_keys[ext_key_idx], randf, pubencf) == False):
            return None

        # DELETE the random number from disk
        if (TPM2_DeleteFile(randf) == False):
            return None

        # Compute hash
        hashf = self._f_kdk + "/" + TPM2T_TEMP2_FILE
        ticketf = self._f_kdk + "/" + TPM2T_TEMP3_FILE
        if (TPM2_Hash(pubencf, hashf, ticketf) == False):
            return None

        # Digitally sign the result
        signf = self._f_kdk + "/" + TPM2T_KDISTROSIGNEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_Sign(self._hl_pub_asymk, hashf, ticketf, signf) == False):
            return None

        # DELETE the hash and the ticket from disk
        if (TPM2_DeleteFile(hashf) == False):
            return None
        if (TPM2_DeleteFile(ticketf) == False):
            return None

        return (pubencf, signf)


    def generate_sealed_sym_key(self, key_size):
        '''
        Generate a new symmetric key and seal it with our primary key. The key can later be decrypted each time it is required to be sealed with an external key.
        '''

        # Prepare the handlers and new (internal) identifier
        # self._kd_idx = self._kd_idx + 1
        #pubk = self._f_symk + "/" + TPM2T_SYMPUBNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #sensk = self._f_symk + "/" + TPM2T_SYMSENSNAME_FILE + str(self._sym_idx) + TPM2T_SYMEXTENSION_FILE
        #self._sym_keys[self._sym_idx] = (pubk, sensk, None)

        # Generate a random sequence of bytes - this will constitute the new symmetric key
        randf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
        if (TPM2_Getrandom(key_size, randf) == False):
            return -1

        pubf = self._f_kdk + "/" + TPM2T_KDISTROPRPUB_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE
        sensf = self._f_kdk + "/" + TPM2T_KDISTROPRSENS_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE

        # Seal the key with the primary key
        if (TPM2_SealObject(self._h_primaryk, randf, pubf, sensf) == False):
            return -1

        # DELETE the random number from disk
        if (TPM2_DeleteFile(randf) == False):
            return -1

        # Store the result
        self._kd_keys[self._kd_idx] = (pubf, sensf)

        return self._kd_idx

    def load_sealed_sym_key(self, ext_key_idx, sealed_key_idx):
 
            # Get the key handlers from our internal keystore
            extk = self._f_ext + "/" + TPM2T_EXTNAME_FILE + str(self._ext_idx) + TPM2T_EXTEXTENSION_FILE
            pubdk = self._f_kdk + "/" + TPM2T_KDISTROPRPUB_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE
            sensdk = self._f_kdk + "/" + TPM2T_KDISTROPRSENS_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE

            # First, the object needs to be loaded. We will obtain a context file.
            loadedf = self._f_kdk + "/" + TPM2T_KDISTROPRLOADED_FILE + str(sealed_key_idx) + TPM2T_KDISTROEXT_FILE
            if (TPM2_LoadKey(self._h_primaryk, pubdk, sensdk, loadedf) == False):
                return None

            # Next, proceed with the unseal operation.
            unsealed_kf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
            if (TPM2_UnsealObject(loadedf, unsealed_kf) == False):
                return None

            # Now, we have the unsealed key, we can encrypt it with the public external key.
            pubencf = self._f_kdk + "/" + TPM2T_KDISTROENCEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
            if (TPM2_RSAEncrypt(extk, unsealed_kf, pubencf) == False):
                return None

            # DELETE the unsealed object from disk
            if (TPM2_DeleteFile(unsealed_kf) == False):
                return None

            signf = self._f_kdk + "/" + TPM2T_KDISTROSIGNEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
            if (TPM2_Sign(self._hl_pub_asymk, None, pubencf, signf) == False):
                return None

            return (pubencf, signf)

    def export_sealed_sym_key(self, ext_key_idx, sealed_key_idx):
        '''
        Export the given sealed key with the help of the external key.
        '''

        # Verify if everything is in place
        if (ext_key_idx not in self._ext_keys):
            print("External key not found in internal keystore: " + str(ext_key_idx))
            return None
        if (sealed_key_idx not in self._kd_keys):
            print("Distributed key not found in internal keystore: " + str(sealed_key_idx))
            return None

        # Get the key handlers from our internal keystore
        extk = self._ext_keys[ext_key_idx]
        (pubdk, sensdk) = self._kd_keys[sealed_key_idx]

        # First, the object needs to be loaded. We will obtain a context file.
        loadedf = self._f_kdk + "/" + TPM2T_KDISTROPRLOADED_FILE + str(sealed_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_LoadKey(self._h_primaryk, pubdk, sensdk, loadedf) == False):
            return None

        # Next, proceed with the unseal operation.
        unsealed_kf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
        if (TPM2_UnsealObject(loadedf, unsealed_kf) == False):
            return None

        # TODO: ADD KEY IDX!!!!
        #rr = read_binary_file(unsealed_kf)
        #print("****SENT KEY: " + str(rr))

        # Now, we have the unsealed key, we can encrypt it with the public external key.
        pubencf = self._f_kdk + "/" + TPM2T_KDISTROENCEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_RSAEncrypt(extk, unsealed_kf, pubencf) == False):
            return None

        # DELETE the unsealed object from disk
        if (TPM2_DeleteFile(unsealed_kf) == False):
            return None

        # Compute hash
        #hashf = self._f_kdk + "/" + TPM2T_TEMP2_FILE
        #ticketf = self._f_kdk + "/" + TPM2T_TEMP3_FILE
        #if (TPM2_Hash(pubencf, hashf, ticketf) == False):
        #    return None

        # Digitally sign the result
        #signf = self._f_kdk + "/" + TPM2T_KDISTROSIGNEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        #if (TPM2_Sign(self._hl_pub_asymk, hashf, ticketf, signf) == False):
        #    return None
        signf = self._f_kdk + "/" + TPM2T_KDISTROSIGNEX_FILE + str(ext_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_Sign(self._hl_pub_asymk, None, pubencf, signf) == False):
            return None

        # DELETE the hash and the ticket from disk
        #if (TPM2_DeleteFile(hashf) == False):
        #    return None
        #if (TPM2_DeleteFile(ticketf) == False):
        #    return None

        return (pubencf, signf)

    def memory_export_sealed_key(self, sealed_key_idx):
        '''
        Export the selaed key to memory and return it.
        '''
        # if (sealed_key_idx not in self._kd_keys):
        #     print("Distributed key not found in internal keystore: " + str(sealed_key_idx))
        #     return None

        pubdk = self._f_kdk + "/" + TPM2T_KDISTROPRPUB_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE
        sensdk = self._f_kdk + "/" + TPM2T_KDISTROPRSENS_FILE + str(self._kd_idx) + TPM2T_KDISTROEXT_FILE

        # First, the object needs to be loaded. We will obtain a context file.
        loadedf = self._f_kdk + "/" + TPM2T_KDISTROPRLOADED_FILE + str(sealed_key_idx) + TPM2T_KDISTROEXT_FILE
        if (TPM2_LoadKey(self._h_primaryk, pubdk, sensdk, loadedf) == False):
            return None

        # Next, proceed with the unseal operation.
        unsealed_kf = self._f_kdk + "/" + TPM2T_TEMP1_FILE
        if (TPM2_UnsealObject(loadedf, unsealed_kf) == False):
            return None

        ret_key = read_binary_file(unsealed_kf)

        # DELETE the unsealed object from disk
        if (TPM2_DeleteFile(unsealed_kf) == False):
            return None

        return ret_key

    def rsa_decrypt(self, mem_data):
        '''
        Decrypts the given data with private context key.
        '''
        rr = "1"
        fdata = self._f_ext + "/" + TPM2T_SIGDATA_FILE + rr + ".dat"
        fkey = self._f_ext + "/" + TPM2T_DEC_FILE + rr + ".dat"
        
        if (write_binary_file(fdata, mem_data) == False):
            return False
        
        # Get the key handlers from our internal keystore
        res = None
        if (TPM2_RSADecrypt(self._hl_pub_asymk, fdata, fkey) == True):
            res = read_binary_file(fkey)
        
        #TPM2_DeleteFile(fkey)
        #TPM2_DeleteFile(fdata)
        
        return res

    def generate_managed_hmak_key(self, key_idx):
        '''
        Generate a new managed HMAC key.
        '''

        if key_idx not in self._sym_keys:
            print("Unknown key with idx: " + str(key_idx))
            return False

        # Extract public and sensitive part
        (pubk,sensk) = self._sym_keys[key_idx]

        # Compute loaded key handler
        loadedk = self._f_symk + "/" + TPM2T_SYMKEYLOADED_FILE + str(key_idx) + TPM2T_SYMEXTENSION_FILE

        if (TPM2_LoadKey(self._hp_pub_asymk, pubk, sensk, loadedk) == False):
            return False

        # Store the new handler back to the keystore
        self._sym_keys[key_idx] = (pubk, sensk, loadedk)

        return True

    def verify_signature(self, mem_data, mem_sig, ext_key_idx):
        '''
        Verifies the data signature - considering that the data is stored in memory.
        '''
        if (ext_key_idx not in self._ext_keys):
            logging.debug("External key not found in internal keystore: " + str(ext_key_id))
            return None
        
        rr = "1"
        fdata = self._f_ext + "/" + TPM2T_SIGDATA_FILE + rr + ".dat"
        fsig = self._f_ext + "/" + TPM2T_SIGSIG_FILE + rr + ".dat"
        
        if (write_binary_file(fdata, mem_data) == False):
           logging.debug("Write binary fail fdata")
           return False
        if (write_binary_file(fsig, mem_sig) == False):
            logging.debug("Write binary file faile fsig")
            TPM2_DeleteFile(fdata)
            return False
        
        # Get the key handlers from our internal keystore
        extk = self._ext_keys[ext_key_idx]
        res = TPM2_Verify(extk, fdata, fsig)
        logging.debug("Index {} verify res {}".format(extk, res))
        #TPM2_DeleteFile(fdata)
        #TPM2_DeleteFile(fsig)
        return res

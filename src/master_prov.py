#!/usr/bin/python3
"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge
"""
# Version number
__version__ = "0.1"

# System imports
from datetime import datetime
import sys

from pytpm.mastertpm import MasterTPM


def log_msg(msg):
    s = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    s += " - " + msg
    print(s)


def print_help():
    print("This is the Master provisioning software, version: " + __version__)
    print("Usage: python3 master_prov [-h] [-e key-file-list]")
    print("       -h: displays this help")
    print("       -e key-file-list: external key file list separated by space")


def proc_args():
    
    if (len(sys.argv) < 2):
        return None
        
    if (sys.argv[1] == "-h"):
        print_help()
        return None
        
    if (sys.argv[1] != "-e"):
        print("Unknown option: " + sys.argv[1])
        return None
        
    if (len(sys.argv) == 2):
        print("Not enough arguments!")
        print_help()
        return None
    
    key_files = []
    idx = 2
    while (idx < len(sys.argv)):
        key_files.append(sys.argv[idx])
        idx += 1

    return key_files

if __name__ == '__main__':
    log_msg("This is the Master provisioning software, version: " + __version__ )

    # Process program arguments
    key_files = proc_args()

    # Create master object
    master = MasterTPM()
    master.provision_core('MASTER_TPMCTX')
    log_msg("Provisioning completed!")



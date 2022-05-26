"""
This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.

Developed by NISLAB - Network and Information Security Laboratory
at George Emil Palade University of Medicine, Pharmacy, Science and
Technology of Târgu Mureş <https://nislab.umfst.ro/>

Contributors: Bela Genge
"""

import sys, os
import argparse
import logging
import logging.handlers
import signal

from utils.utils import get_configuration
from master_core.master_mngr import MasterMngr

__version__ = "0.1"

LOG_VALUES = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "notset": logging.NOTSET
}

def log_setup(config):

    log_level = LOG_VALUES[config.get("Log", "level")]
    formatter = logging.Formatter('%(asctime)s - %(levelname)-8s %(message)s')

    # Setup file logger
    file_handler = None
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            config.get("Log", "filename"),
            maxBytes=int(config.get("Log", "maxBytes")),
            backupCount=int(config.get("Log", "backupCount")))
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
    except Exception as ex:
        print("Exception while init logger: " + str(ex))

    # Setup console logger
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.addHandler(console_handler)
    if file_handler:
        logger.addHandler(file_handler)

    logger.setLevel(log_level)


def run_mngr(config):

    log_setup(config)
    
    shared_secret = None
    ltk_size = 256
    stk_size = 128
    ext_pub_key = None
    vbus_name = None
    vbus_bitrate = None
    ltk_st = None
    stk_st = None
    mqtt_user = None
    mqtt_passwd = None
    mqtt_host = None
    mqtt_port = None
    ltk_timer = None
    stk_timer = None
    
    try:
        shared_secret = config.get("Secrets", "shared_secret")
        stk_size = config.get("Secrets", "stk_size")
        ext_pub_key = config.get("Secrets", "ext_pub_key")
        vbus_name = config.get("CAN", "vbus")
        vbus_bitrate = config.get("CAN", "bitrate")
        ltk_st = config.get("CAN", "ltk_st")
        stk_st = config.get("CAN", "stk_st")
        mqtt_user = config.get("mqtt", "user")
        mqtt_passwd = config.get("mqtt", "passwd")
        mqtt_host = config.get("mqtt", "host")
        mqtt_port = int(config.get("mqtt", "port"))
        ltk_cycle = int(config.get("Timers", "ltk_cycle"))
        stk_cycle = int(config.get("Timers", "stk_cycle"))
    except Exception as ex:
        logging.info("Main: unable to get init params: " + str(ex))
    
    logging.info("Master Key manager version: " + __version__)
    
    logging.info("Main: shared_secret: " + str(shared_secret))
    logging.info("Main: ltk_size: " + str(ltk_size))
    logging.info("Main: stk_size: " + str(stk_size))
    logging.info("Main: ext_pub_key: " + str(ext_pub_key))
    logging.info("Main: vbus_name: " + str(vbus_name))
    logging.info("Main: vbus_bitrate: " + str(vbus_bitrate))
    logging.info("Main: ltk_st: " + str(ltk_st))
    logging.info("Main: stk_st: " + str(stk_st))
    logging.info("Main: mqtt_user: " + mqtt_user)
    logging.info("Main: mqtt_passwd: " + mqtt_passwd)
    logging.info("Main: mqtt_host: " + mqtt_host)
    logging.info("Main: mqtt_port: " + str(mqtt_port))
    logging.info("Main: ltk_cycle: " + str(ltk_cycle))
    logging.info("Main: stk_cycle: " + str(stk_cycle))
    
    global key_mngr
    key_mngr = MasterMngr(shared_secret, ltk_size, stk_size,
                ext_pub_key, vbus_name, vbus_bitrate, ltk_st, stk_st,
                ltk_cycle, stk_cycle, mqtt_user, mqtt_passwd, 
                mqtt_host, mqtt_port)
    
    try:
        key_mngr.run_mngr_loop()

    except Exception as ex:
        logging.error("Main: Exception while running loop: " + str(ex))

def signal_handler(signum, frame):
    logging.info("Main: Stopping ...")
    key_mngr.stop_mngr_loop()
    logging.info("Main: Stopped!")

if __name__ == '__main__':

    sys.path.append(os.getcwd())

    # Parse arguments
    parser = argparse.ArgumentParser(description="The Master Key Manager module.")
    parser.add_argument(
        "--config", "-c",
        help="the path and name of the configuration file",
        required=True)
    parser.add_argument(
        "--version", help="display the version",
        action="version", version="%(prog)s {}".format(__version__))

    args = parser.parse_args()
    config = get_configuration(args.config)

    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    run_mngr(config)
    
    logging.info("Main: exited")
# ABAC auto-loading and object attribute management service
# Copyright (C) 2021 Hariyala Omakara Naga Sai Varshith

import signal
import os
import sys
import json
import click
from pathlib import Path
from multiprocessing.connection import Listener
from .common import check_root, path_is_covered
from .config import CONFIG_ROOT, CONFIG_AVP_FILE, CONFIG_OBJ_ATTRS_FILE, PORT
from .load import load_obj_attr, load_user_attr, load_policy, load_path_scope

# global listener object
listener = None
AUTHKEY = b"abac-local"

def is_owner(object_path, requester_id):
    if requester_id == 0:
        return True
    owner_id = os.stat(object_path).st_uid
    return requester_id == owner_id

def check_obj_initialized():
    if not Path(CONFIG_ROOT + CONFIG_OBJ_ATTRS_FILE).is_file():
        sys.exit("ABAC config not initialized. Please run 'abac init' and try again.")

def signal_handler(sig, frame):
    print("Stopping ABAC object attribute service...")
    global listener
    if listener:
        listener.close()
    sys.exit()

def get_available_avps():
    with open(CONFIG_ROOT + CONFIG_AVP_FILE) as f:
        avps = json.load(f)["obj"]
    return avps

def list_attr(path):
    if not path_is_covered(path):
        return {}
    with open(CONFIG_ROOT + CONFIG_OBJ_ATTRS_FILE) as f:
        attrs = json.load(f)["objects"]
        if path not in attrs:
            return {}
        return attrs[path]

def update_attr(path, avps):
    if not path_is_covered(path):
        return "OUT_OF_SCOPE"
    with open(CONFIG_ROOT + CONFIG_OBJ_ATTRS_FILE) as f:
        attrs = json.load(f)
    if len(avps) == 0:
        attrs["objects"].pop(path, None)
    else:
        attrs["objects"][path] = avps
    with open(CONFIG_ROOT + CONFIG_OBJ_ATTRS_FILE, 'w') as f:
        json.dump(attrs, f)
    # reload the object attributes into the kernel
    load_obj_attr()
    return "OK"

@click.command()
def server():
    """
    Starts the ABAC attribute server. This server is responsible for managing object attributes.
    This server is started automatically by the system.
    """
    check_root()
    check_obj_initialized()

    # load attributes into the kernel
    load_user_attr()
    load_obj_attr()
    load_policy()
    load_path_scope()
    print("Attributes loaded into the kernel")

    address = ('localhost', 4848)
    signal.signal(signal.SIGINT, signal_handler)
    print(f"ABAC Object attribute service listening on {address[0]}:{address[1]}")
    with Listener(address, authkey=AUTHKEY) as listener:
        while True:
            with listener.accept() as conn:
                try:
                    msg = conn.recv()
                except OSError:
                    # Ignore clients that disconnect during the connection handshake
                    # or before sending a complete message.
                    continue
                print(msg)
                # each message MUST have the action key
                if 'action' not in msg:
                    print("Invalid message. Connection closed\n", msg)
                    conn.close()
                    continue
                if msg["action"] == "AVAILABLE":
                    payload = {"avps" : get_available_avps()}
                elif 'uid' not in msg:
                    # for remaining actions, the UID is required to check for ownership
                    print("Invalid message. Connection closed\n", msg)
                    conn.close()
                    continue
                elif not is_owner(msg["object"], msg['uid']):
                    payload = {"error": "You are not the owner of this object"}
                elif msg["action"] == "LIST":
                    payload = {"avps" : list_attr(msg["object"])}
                elif msg["action"] == "UPDATE":
                    status = update_attr(msg["object"], msg["avps"])
                    if status == "OUT_OF_SCOPE":
                        payload = {"error": "This path is outside the configured ABAC include/exclude scope"}
                    else:
                        payload = {"status" : status}
                print(payload)
                conn.send(payload)
                conn.close()
    # the loop never comes here. listener is closed by the signal handler
    listener.close()

# Common utility methods
# Copyright (C) 2021 Hariyala Omakara Naga Sai Varshith

import os
import sys
import json
from pathlib import Path

from .config import CONFIG_ROOT, CONFIG_PATH_SCOPE_FILE

def check_root():
    # check if user is root
    if os.geteuid() != 0:
        sys.exit("Only root can run this command. Try running with sudo or login as root.")

def validate_str(string):
    # valid string must be alphanumeric strings without spaces
    # this validation applies to usernames, attribute names and attribute values
    return string != None and string != "" and ' ' not in string and string.isalnum()


def normalize_path(path):
    return str(Path(path).resolve())


def load_path_scope():
    path = CONFIG_ROOT + CONFIG_PATH_SCOPE_FILE
    if not Path(path).is_file():
        return {"include": [], "exclude": []}
    with open(path) as f:
        scope = json.load(f)
    return {
        "include": [normalize_path(item) for item in scope.get("include", [])],
        "exclude": [normalize_path(item) for item in scope.get("exclude", [])],
    }


def path_is_covered(path, scope=None):
    target = normalize_path(path)
    scope = scope or load_path_scope()
    includes = scope.get("include", [])
    excludes = scope.get("exclude", [])

    included = True
    if len(includes) != 0:
        included = any(target.startswith(prefix) for prefix in includes)
    if not included:
        return False
    if any(target.startswith(prefix) for prefix in excludes):
        return False
    return True

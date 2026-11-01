# ABAC include/exclude path scope management

import json
import sys
from pathlib import Path

import click

from .common import check_root, normalize_path, load_path_scope
from .config import CONFIG_ROOT, CONFIG_PATH_SCOPE_FILE
from .load import load_path_scope as load_scope_into_kernel


scope_path = CONFIG_ROOT + CONFIG_PATH_SCOPE_FILE


def ensure_scope_initialized():
    if not Path(scope_path).is_file():
        sys.exit(f"ABAC config not initialized. {scope_path} missing")


def save_scope(scope):
    with open(scope_path, "w") as f:
        json.dump(scope, f, indent=4)


def print_paths(header, paths):
    print(header)
    if len(paths) == 0:
        print("(none)")
        return
    for index, value in enumerate(paths):
        print(f"[{index}] {value}")


@click.command()
@click.argument("action", type=click.Choice(["list", "add", "delete", "load"]))
@click.option("-t", "type_", type=click.Choice(["include", "exclude"]), help="Path scope type")
@click.argument("path_value", type=str, required=False)
def scope(action, type_, path_value):
    """Manage ABAC include/exclude path scope."""

    check_root()
    ensure_scope_initialized()

    if action == "load":
        load_scope_into_kernel()
        return

    scope_data = load_path_scope()

    if action == "list":
        print_paths("Include paths", scope_data["include"])
        print()
        print_paths("Exclude paths", scope_data["exclude"])
        return

    if type_ is None:
        sys.exit("Scope type flag '-t' is required")
    if path_value is None:
        sys.exit("A path value is required")

    normalized = normalize_path(path_value)

    if action == "add":
        if normalized in scope_data[type_]:
            sys.exit(f"{normalized} already exists in {type_} paths")
        scope_data[type_].append(normalized)
        scope_data[type_] = sorted(set(scope_data[type_]))
        save_scope(scope_data)
        load_scope_into_kernel()
        print(f"Added {normalized} to {type_} paths")
        return

    if action == "delete":
        if normalized not in scope_data[type_]:
            sys.exit(f"{normalized} not found in {type_} paths")
        scope_data[type_].remove(normalized)
        save_scope(scope_data)
        load_scope_into_kernel()
        print(f"Deleted {normalized} from {type_} paths")

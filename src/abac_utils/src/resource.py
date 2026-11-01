"""Persistent ABAC resource-object management."""

import json
import re
import sys
from pathlib import Path

import click

from .common import check_root
from .config import CONFIG_OBJ_ATTRS_FILE, CONFIG_ROOT
from .load import load_obj_attr

RESOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9_/-]*$")
ATTR = re.compile(r"^[a-zA-Z0-9_]+=[a-zA-Z0-9_]+$")
RESOURCE_PATH = Path(CONFIG_ROOT) / CONFIG_OBJ_ATTRS_FILE


def load_store():
    if not RESOURCE_PATH.is_file():
        sys.exit(f"ABAC config not initialized. {RESOURCE_PATH} missing")
    with RESOURCE_PATH.open() as handle:
        data = json.load(handle)
    data.setdefault("objects", {})
    data.setdefault("resources", {})
    return data


def save_store(data):
    temp = RESOURCE_PATH.with_suffix(".json.tmp")
    with temp.open("w") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.flush()
    temp.replace(RESOURCE_PATH)


@click.command()
@click.argument("action", type=click.Choice(["add", "list", "delete"]))
@click.argument("resource_id", required=False)
@click.option("--attr", "attributes", multiple=True, help="Attribute in NAME=VALUE form.")
def resource(action, resource_id, attributes):
    """Manage non-filesystem ABAC resource objects."""
    check_root()
    data = load_store()
    resources = data["resources"]

    if action == "list":
        for key in sorted(resources):
            click.echo(f"{key}: " + ",".join(f"{k}={v}" for k, v in resources[key].items()))
        return

    if not resource_id or not RESOURCE_ID.fullmatch(resource_id):
        sys.exit("Resource ID must contain only letters, digits, _, -, and /.")

    if action == "delete":
        if resource_id not in resources:
            sys.exit(f"Resource {resource_id} not found")
        del resources[resource_id]
        save_store(data)
        load_obj_attr()
        click.echo(f"Deleted {resource_id}")
        return

    if not attributes:
        sys.exit("At least one --attr NAME=VALUE is required")
    parsed = {}
    for value in attributes:
        if not ATTR.fullmatch(value):
            sys.exit(f"Invalid resource attribute: {value}")
        key, item = value.split("=", 1)
        parsed[key] = item
    resources[resource_id] = parsed
    save_store(data)
    load_obj_attr()
    click.echo(f"Loaded {resource_id}")

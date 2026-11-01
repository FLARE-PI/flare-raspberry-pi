"""Dynamic environment attributes for the Phase 3 resource policy path."""

import json
import os
import re
import subprocess
import time
from pathlib import Path

import click

from .common import check_root
from .config import ABAC_MOUNT, CONFIG_ENV_ATTRS_FILE, CONFIG_ENV_EVENTS_FILE, CONFIG_ROOT, KERN_ENV_STATUS_FILE
from .load import load_env_attr

NAME = re.compile(r"^[a-zA-Z0-9_]+$")
VALUE = re.compile(r"^[a-zA-Z0-9_]+$")
ENV_PATH = Path(CONFIG_ROOT) / CONFIG_ENV_ATTRS_FILE
EVENT_PATH = Path(CONFIG_ROOT) / CONFIG_ENV_EVENTS_FILE


def read_env():
    with ENV_PATH.open() as handle:
        data = json.load(handle)
    data.setdefault("env", {})
    return data


def write_env(data):
    temporary = ENV_PATH.with_suffix(".json.tmp")
    with temporary.open("w") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(ENV_PATH)


def kernel_status():
    status = Path(ABAC_MOUNT) / KERN_ENV_STATUS_FILE
    if not status.is_file():
        return {"generation": None, "last_update_ns": None}
    return dict(line.split("=", 1) for line in status.read_text().splitlines() if "=" in line)


def append_event(event):
    with EVENT_PATH.open("a") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def set_values(values, source):
    data = read_env()
    changed = {key: value for key, value in values.items() if data["env"].get(key) != value}
    observed_ns = time.monotonic_ns()
    if not changed:
        return False
    data["env"].update(changed)
    write_env(data)
    submitted_ns = time.monotonic_ns()
    load_env_attr()
    updated_ns = time.monotonic_ns()
    append_event({
        "source": source,
        "observed_ns": observed_ns,
        "submitted_ns": submitted_ns,
        "confirmed_ns": updated_ns,
        "kernel": kernel_status(),
        "changed": changed,
    })
    return True


def temperature_state():
    output = subprocess.check_output(["vcgencmd", "measure_temp"], text=True).strip()
    value = float(output.split("=", 1)[1].split("'", 1)[0])
    if value >= 75:
        return value, "critical"
    if value >= 60:
        return value, "high"
    return value, "normal"


@click.group()
def env():
    """Inspect, set, and collect ABAC environmental attributes."""


@env.command("show")
def show():
    check_root()
    click.echo(json.dumps(read_env()["env"], indent=2, sort_keys=True))


@env.command("set")
@click.argument("name")
@click.argument("value")
def set_(name, value):
    check_root()
    if not NAME.fullmatch(name) or not VALUE.fullmatch(value):
        raise click.UsageError("Names and values must be alphanumeric or underscore.")
    click.echo("updated" if set_values({name: value}, "manual") else "unchanged")


@env.command("collect")
@click.option("--interval", type=float, default=2.0, show_default=True)
@click.option("--once", is_flag=True, default=False)
def collect(interval, once):
    """Poll Pi CPU temperature and update normalized temperature_state."""
    check_root()
    while True:
        value, state = temperature_state()
        changed = set_values({"temperature_state": state}, "cpu_temperature")
        click.echo(f"temperature_c={value:.1f} state={state} changed={str(changed).lower()}")
        if once:
            return
        time.sleep(interval)

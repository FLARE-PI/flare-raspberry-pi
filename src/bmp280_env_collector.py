#!/usr/bin/env python3
"""Publish a complete, validated BMP280 environment map on every sample."""

import argparse
import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from bmp280_reader import BMP280, parse_address


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def now_monotonic_ns():
    """Return one monotonic clock domain for collector timing evidence."""
    raw_clock = getattr(time, "CLOCK_MONOTONIC_RAW", None)
    if raw_clock is not None:
        return time.clock_gettime_ns(raw_clock)
    return time.monotonic_ns()


def validate_threshold(value):
    try:
        threshold = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("TEMP_HIGH_C must be a finite number") from error
    if not (-40.0 <= threshold <= 85.0):
        raise ValueError("TEMP_HIGH_C must be within -40.0..85.0 C")
    if threshold != threshold or threshold in (float("inf"), float("-inf")):
        raise ValueError("TEMP_HIGH_C must be finite")
    return threshold


def read_runtime_threshold(path, last_known_valid):
    """Read the optional atomic runtime override, retaining a valid fallback."""
    if not path.exists():
        return last_known_valid, "default"
    try:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if len(lines) != 1 or not lines[0].startswith("TEMP_HIGH_C="):
            raise ValueError("expected exactly one non-comment TEMP_HIGH_C=value line")
        return validate_threshold(lines[0].split("=", 1)[1]), "runtime"
    except (OSError, ValueError) as error:
        return last_known_valid, "retained-invalid: %s" % error


def read_maintenance_mode(path, last_known_valid):
    """Read one trusted administrative context value, retaining safe state."""
    if not path.exists():
        return last_known_valid, "default"
    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_uid != 0:
            raise ValueError("control must be a root-owned regular file")
        if metadata.st_mode & 0o022:
            raise ValueError("control must not be group/other writable")
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if len(lines) != 1 or not lines[0].startswith("maintenance_mode="):
            raise ValueError("expected exactly one maintenance_mode=off|on line")
        value = lines[0].split("=", 1)[1]
        if value not in ("off", "on"):
            raise ValueError("maintenance_mode must be off or on")
        return value, "runtime"
    except (OSError, ValueError) as error:
        return last_known_valid, "retained-invalid: %s" % error


def atomic_json_write(path, data):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def read_json(path, default):
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def append_event(path, event):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_kernel_status(path):
    if not path.exists():
        return {}
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


def acquire_exclusive_lock(path):
    """Prevent a second collector from reading the BMP280 concurrently."""
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError("BMP280 collector lock is already held: %s" % path)
    return fd


def publish(sample, threshold_c, threshold_source, config_path, state_path, event_path,
            env_node, status_node, maintenance_mode, maintenance_source):
    new_state = "high" if sample["temperature_c"] >= threshold_c else "normal"
    normalized_timestamp = now_utc()
    normalized_monotonic_ns = now_monotonic_ns()
    last = read_json(state_path, {})
    old_state = last.get("temperature_state")
    old_maintenance_mode = last.get("maintenance_mode")
    kernel_before = read_kernel_status(status_node)
    event = {
        "sensor_timestamp": sample["timestamp"],
        "temperature_c": sample["temperature_c"],
        "pressure_hpa": sample["pressure_hpa"],
        "threshold_c": threshold_c,
        "threshold_source": threshold_source,
        "old_temperature_state": old_state,
        "new_temperature_state": new_state,
        "old_maintenance_mode": old_maintenance_mode,
        "maintenance_mode": maintenance_mode,
        "maintenance_source": maintenance_source,
        "normalized_timestamp": normalized_timestamp,
        "sample_monotonic_ns": sample["sample_monotonic_ns"],
        "normalization_monotonic_ns": normalized_monotonic_ns,
        "securityfs_update_monotonic_ns": None,
        "securityfs_update_timestamp": None,
        "securityfs_result": "unchanged",
    }
    config = read_json(config_path, {"env": {}})
    if not isinstance(config, dict) or not isinstance(config.get("env", {}), dict):
        raise RuntimeError("invalid ABAC environment config: %s" % config_path)
    complete_environment = {
        "maintenance_mode": maintenance_mode,
        "temperature_state": new_state,
    }
    if config.get("env") != complete_environment:
        atomic_json_write(config_path, {"env": complete_environment})
    payload = "".join("%s=%s\n" % item for item in sorted(complete_environment.items()))
    try:
        with env_node.open("w", encoding="utf-8") as handle:
            handle.write(payload or "CLEAR\n")
        event["securityfs_update_timestamp"] = now_utc()
        event["securityfs_update_monotonic_ns"] = now_monotonic_ns()
        event["kernel_env_status"] = read_kernel_status(status_node)
        if event["kernel_env_status"].get("generation") == kernel_before.get("generation"):
            event["securityfs_result"] = "heartbeat"
        else:
            event["securityfs_result"] = "updated"
        atomic_json_write(state_path, {
            "maintenance_mode": maintenance_mode,
            "temperature_state": new_state,
            "updated_at": event["securityfs_update_timestamp"],
            "kernel_generation": event["kernel_env_status"].get("generation"),
        })
    except Exception as error:
        event["securityfs_update_timestamp"] = now_utc()
        event["securityfs_result"] = "error: %s" % error
        append_event(event_path, event)
        raise
    append_event(event_path, event)
    return event


def publish_test_environment(environment, state_path, event_path, env_node, status_node,
                             sequence):
    """Publish a complete synthetic pair through the collector's sole writer path."""
    kernel_before = read_kernel_status(status_node)
    payload = "".join("%s=%s\n" % item for item in sorted(environment.items()))
    event = {
        "test_mode": "atomicity",
        "sequence": sequence,
        "environment": dict(environment),
        "securityfs_result": "error",
    }
    with env_node.open("w", encoding="utf-8") as handle:
        handle.write(payload)
    current = read_kernel_status(status_node)
    event["kernel_env_status"] = current
    event["securityfs_result"] = (
        "heartbeat" if current.get("generation") == kernel_before.get("generation")
        else "updated"
    )
    atomic_json_write(state_path, {
        "maintenance_mode": environment["maintenance_mode"],
        "temperature_state": environment["temperature_state"],
        "updated_at": now_utc(),
        "kernel_generation": current.get("generation"),
        "test_sequence": sequence,
    })
    append_event(event_path, event)
    return event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="/dev/i2c-1")
    parser.add_argument("--address", type=parse_address, default=0x76)
    env_threshold = os.environ.get("TEMP_HIGH_C")
    parser.add_argument("--temp-high-c", type=float, default=env_threshold,
                        required=env_threshold is None,
                        help="high threshold; defaults to TEMP_HIGH_C")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--samples", type=int, default=1,
                        help="number of samples; zero polls until interrupted")
    parser.add_argument("--config", type=Path, default=Path("/etc/abac/env_attr.json"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/abac/bmp280_env_state.json"))
    parser.add_argument("--events", type=Path, default=Path("/var/log/abac/bmp280_env_events.jsonl"))
    parser.add_argument("--runtime-threshold-config", type=Path,
                        default=Path("/etc/abac/bmp280_env.conf"),
                        help="optional atomic TEMP_HIGH_C runtime override")
    parser.add_argument("--maintenance-mode-config", type=Path,
                        default=Path("/etc/abac/maintenance_mode.conf"),
                        help="root-owned maintenance_mode=off|on control")
    parser.add_argument("--lock-path", type=Path, default=Path("/run/abac-bmp280-env.lock"))
    parser.add_argument("--env-node", type=Path, default=Path("/sys/kernel/security/abac/env_attr"))
    parser.add_argument("--status-node", type=Path, default=Path("/sys/kernel/security/abac/env_status"))
    parser.add_argument("--test-alternate-pairs", type=int, default=0,
                        help="root-only atomicity mode: publish this many complete A/B maps")
    args = parser.parse_args()
    if args.samples < 0 or args.interval <= 0 or args.test_alternate_pairs < 0:
        parser.error("samples must be non-negative and interval must be positive")
    if os.geteuid() != 0:
        parser.error("collector must run as root to update ABAC state")
    if not args.env_node.is_file():
        parser.error("ABAC env_attr node is unavailable: %s" % args.env_node)

    try:
        initial_threshold = validate_threshold(args.temp_high_c)
    except ValueError as error:
        parser.error(str(error))

    lock_fd = acquire_exclusive_lock(args.lock_path)
    try:
        if args.test_alternate_pairs:
            maps = (
                {"temperature_state": "normal", "maintenance_mode": "off"},
                {"temperature_state": "high", "maintenance_mode": "on"},
            )
            for index in range(args.test_alternate_pairs):
                event = publish_test_environment(maps[index % 2], args.state, args.events,
                                                 args.env_node, args.status_node, index)
                print(json.dumps(event, sort_keys=True))
            return 0
        sample_number = 0
        threshold_c = initial_threshold
        maintenance_mode = "off"
        with BMP280(args.device, args.address) as sensor:
            while args.samples == 0 or sample_number < args.samples:
                try:
                    threshold_c, threshold_source = read_runtime_threshold(
                        args.runtime_threshold_config, threshold_c)
                    maintenance_mode, maintenance_source = read_maintenance_mode(
                        args.maintenance_mode_config, maintenance_mode)
                    sample = sensor.sample()
                    sample["sample_monotonic_ns"] = now_monotonic_ns()
                    event = publish(sample, threshold_c, threshold_source, args.config,
                                    args.state, args.events, args.env_node, args.status_node,
                                    maintenance_mode, maintenance_source)
                    print(json.dumps(event, sort_keys=True))
                except Exception as error:
                    event = {
                        "sensor_timestamp": now_utc(),
                        "threshold_c": args.temp_high_c,
                        "securityfs_update_timestamp": None,
                        "securityfs_result": "sensor_error: %s" % error,
                    }
                    append_event(args.events, event)
                    print(json.dumps(event, sort_keys=True), file=sys.stderr)
                    return 1
                sample_number += 1
                if args.samples == 0 or sample_number < args.samples:
                    time.sleep(args.interval)
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    sys.exit(main())

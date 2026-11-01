"""Resolver-independent, DAC-compatible future workload compilation."""

import csv
import json
from collections import OrderedDict
from pathlib import Path

from .acm import load_acm
from .emit import sha256_file, write_json, write_ndjson
from .schema import MuSimAValidationError
from .validate import validate_base_log


def _maps(generated_dir):
    root = Path(generated_dir)
    return (
        json.loads((root / "subject_map.json").read_text(encoding="utf-8")),
        json.loads((root / "object_map.json").read_text(encoding="utf-8")),
    )


def _request(request_id, subject_id, object_id, environment_id, decision, subject_map, object_map):
    return {
        "environment_id": environment_id,
        "expected_decision": decision,
        "future_linux_path": object_map[object_id]["future_linux_path"],
        "linux_uid": subject_map[subject_id]["linux_uid"],
        "object_id": object_id,
        "operation": "READ",
        "request_id": request_id,
        "subject_id": subject_id,
    }


def compile_correctness(dataset, source_path, generated_dir):
    """Write the exhaustive source-ACM CORRECTNESS workload."""
    root = Path(generated_dir)
    subject_map, object_map = _maps(root)
    acm = load_acm(source_path, dataset)
    requests = []
    request_id = 1
    for subject_id in dataset.subjects:
        for object_id in dataset.objects:
            for environment_id in dataset.environments:
                decision = "ALLOW" if acm.decision(subject_id, object_id, environment_id) else "DENY"
                requests.append(_request(
                    request_id, subject_id, object_id, environment_id, decision, subject_map, object_map
                ))
                request_id += 1
    trace_path = root / "traces" / "correctness.ndjson"
    write_ndjson(trace_path, requests)
    write_json(root / "traces" / "correctness_manifest.json", {
        "expected_allow_count": sum(item["expected_decision"] == "ALLOW" for item in requests),
        "expected_deny_count": sum(item["expected_decision"] == "DENY" for item in requests),
        "operation": "READ",
        "request_count": len(requests),
        "sha256": sha256_file(trace_path),
        "source_acm": Path(source_path).name,
    })
    return len(requests)


def compile_base_trace(dataset, source_path, log_path, generated_dir):
    """Write ordered dynamic and grouped authorization-only BASE-MIXED traces."""
    validation = validate_base_log(dataset, source_path, log_path)
    if validation["mismatch_count"]:
        raise MuSimAValidationError("cannot compile a log that disagrees with its ACM")
    root = Path(generated_dir)
    subject_map, object_map = _maps(root)
    requests = []
    batches = OrderedDict((environment_id, []) for environment_id in dataset.environments)
    with Path(log_path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for request_id, row in enumerate(reader, start=1):
            decision = "ALLOW" if row["access"] == "permit" else "DENY"
            request = _request(
                request_id, row["subject"], row["object"], row["environment"], decision,
                subject_map, object_map,
            )
            requests.append(request)
            batches[request["environment_id"]].append(request)
    if len(requests) != validation["requests"]:
        raise MuSimAValidationError("compiled request count differs from validated source log")

    traces = root / "traces"
    dynamic_path = traces / "base_mixed_dynamic.ndjson"
    write_ndjson(dynamic_path, requests)
    batch_dir = traces / "authorization_batches"
    batch_dir.mkdir(exist_ok=True)
    batch_manifest = {"batches": [], "operation": "READ", "source_log": Path(log_path).name,
                      "source_log_sha256": sha256_file(log_path)}
    for environment_id, batch in batches.items():
        path = batch_dir / "{}.ndjson".format(environment_id)
        write_ndjson(path, batch)
        batch_manifest["batches"].append({
            "environment_id": environment_id,
            "request_count": len(batch),
            "sha256": sha256_file(path),
        })
    write_json(traces / "base_mixed_authorization_batches.json", batch_manifest)
    write_json(traces / "base_mixed_dynamic_manifest.json", {
        "allow_count": validation["allow_count"],
        "deny_count": validation["deny_count"],
        "mismatch_count": validation["mismatch_count"],
        "operation": "READ",
        "request_count": len(requests),
        "sha256": sha256_file(dynamic_path),
        "source_log": Path(log_path).name,
        "source_log_sha256": sha256_file(log_path),
    })
    return {"batches": len(batches), **validation}

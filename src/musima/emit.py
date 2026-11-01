"""Deterministic emission of maintained ABAC configuration artifacts."""

import hashlib
import json
import subprocess
from pathlib import Path

from .schema import UNIVERSAL_OBJECT_ATTRIBUTE, UNIVERSAL_SUBJECT_ATTRIBUTE, UNIVERSAL_VALUE


DEFAULT_UID_BASE = 200000
DEFAULT_BENCHMARK_ROOT = "/home/secured/musima"


def dataset_slug(logical_id):
    return logical_id.lower().replace("_", "-")


def canonical_json(data):
    return json.dumps(data, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def write_json(path, data):
    Path(path).write_text(canonical_json(data), encoding="utf-8")


def write_ndjson(path, records):
    with Path(path).open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def converter_git_commit(repository_root):
    try:
        return subprocess.check_output(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _contains_only_wildcards(rule, section):
    return all(value == "*" for value in getattr(rule, section).values())


def _policy_rule(rule, use_universal_subject, use_universal_object):
    user = {name: value for name, value in rule.subject.items() if value != "*"}
    obj = {name: value for name, value in rule.object.items() if value != "*"}
    env = {name: value for name, value in rule.environment.items() if value != "*"}
    if not user and use_universal_subject:
        user[UNIVERSAL_SUBJECT_ATTRIBUTE] = UNIVERSAL_VALUE
    if not obj and use_universal_object:
        obj[UNIVERSAL_OBJECT_ATTRIBUTE] = UNIVERSAL_VALUE
    return {"effect": rule.effect, "env": env, "obj": obj, "op": "READ", "user": user}


def convert_dataset(dataset, output_dir, uid_base=DEFAULT_UID_BASE,
                    benchmark_root=DEFAULT_BENCHMARK_ROOT, repository_root=None):
    """Write a fresh, deterministic converted dataset directory."""
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output directory must be empty: {}".format(output_dir))
    if uid_base < 1000:
        raise ValueError("uid base must be at least 1000")
    output_dir.mkdir(parents=True, exist_ok=True)
    environment_dir = output_dir / "environments"
    environment_dir.mkdir()
    traces_dir = output_dir / "traces"
    traces_dir.mkdir()

    slug = dataset_slug(dataset.logical_id)
    dataset_root = "{}/{}".format(benchmark_root.rstrip("/"), slug)
    object_root = "{}/objects".format(dataset_root)
    use_universal_subject = any(_contains_only_wildcards(rule, "subject") for rule in dataset.rules)
    use_universal_object = any(_contains_only_wildcards(rule, "object") for rule in dataset.rules)

    subject_map = {}
    users = {}
    for index, subject_id in enumerate(dataset.subjects):
        uid = uid_base + index
        attrs = dict(dataset.subject_assignments[subject_id])
        if use_universal_subject:
            attrs[UNIVERSAL_SUBJECT_ATTRIBUTE] = UNIVERSAL_VALUE
        subject_map[subject_id] = {"linux_uid": uid}
        users[subject_id] = {"avps": attrs, "uid": uid}

    object_map = {}
    objects = {}
    for object_id in dataset.objects:
        path = "{}/{}".format(object_root, object_id)
        attrs = dict(dataset.object_assignments[object_id])
        if use_universal_object:
            attrs[UNIVERSAL_OBJECT_ATTRIBUTE] = UNIVERSAL_VALUE
        object_map[object_id] = {"future_linux_path": path}
        objects[path] = attrs

    avps = {
        "env": {name: list(dataset.environment_values[name]) for name in dataset.environment_attributes},
        "obj": {name: list(dataset.object_values[name]) for name in dataset.object_attributes},
        "user": {name: list(dataset.subject_values[name]) for name in dataset.subject_attributes},
    }
    if use_universal_subject:
        avps["user"][UNIVERSAL_SUBJECT_ATTRIBUTE] = [UNIVERSAL_VALUE]
    if use_universal_object:
        avps["obj"][UNIVERSAL_OBJECT_ATTRIBUTE] = [UNIVERSAL_VALUE]

    rules = [_policy_rule(rule, use_universal_subject, use_universal_object) for rule in dataset.rules]
    for environment_id in dataset.environments:
        state_dir = environment_dir / environment_id
        state_dir.mkdir()
        write_json(state_dir / "env_attr.json", {"env": dataset.environment_assignments[environment_id]})

    write_json(output_dir / "subject_map.json", subject_map)
    write_json(output_dir / "object_map.json", object_map)
    write_json(output_dir / "user_attr.json", {"users": users})
    write_json(output_dir / "obj_attr.json", {"objects": objects, "resources": {}})
    write_json(output_dir / "policy.json", {"rules": rules})
    write_json(output_dir / "avp.json", avps)
    write_json(output_dir / "path_scope.json", {"exclude": [], "include": [dataset_root]})

    source_commit = converter_git_commit(repository_root) if repository_root else "unavailable"
    manifest = {
        "benchmark_root": benchmark_root,
        "converter_git_commit": source_commit,
        "deny_rule_count": len(dataset.deny_rules),
        "environment_count": len(dataset.environments),
        "logical_dataset_id": dataset.logical_id,
        "object_count": len(dataset.objects),
        "operation_mapping": "READ_ONLY",
        "permit_rule_count": len(dataset.permit_rules),
        "source_filename": dataset.source_filename,
        "source_sha256": dataset.source_sha256,
        "subject_count": len(dataset.subjects),
        "translation_assumptions": [
            "MuSimA permit rules map to ABAC ALLOW rules.",
            "MuSimA deny rules map to ABAC DENY rules with deny-overrides.",
            "MuSimA wildcard predicates are omitted from their ABAC rule section.",
            "All requests use READ; MuSimA has no operation dimension.",
        ],
        "uid_base": uid_base,
        "wildcard_translation_mode": "omit_predicate",
        "translator_internal_attributes": {
            "object_universal": UNIVERSAL_OBJECT_ATTRIBUTE if use_universal_object else None,
            "subject_universal": UNIVERSAL_SUBJECT_ATTRIBUTE if use_universal_subject else None,
            "value": UNIVERSAL_VALUE if use_universal_subject or use_universal_object else None,
        },
    }
    write_json(output_dir / "manifest.json", manifest)
    return output_dir

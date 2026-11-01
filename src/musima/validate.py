"""Independent source and emitted-artifact authorization evaluators.

This module deliberately does not import the converter/emitter. It reads
generated JSON back from disk and evaluates only its serialized representation.
"""

import csv
import json
from pathlib import Path

from .acm import load_acm
from .schema import MuSimAValidationError


def _matches(required, actual):
    return all(actual.get(name) == value for name, value in required.items())


def evaluate_source(dataset, subject_id, object_id, environment_id):
    """Evaluate source MuSimA rules directly, without converted artifacts."""
    subject = dataset.subject_assignments[subject_id]
    obj = dataset.object_assignments[object_id]
    environment = dataset.environment_assignments[environment_id]
    allow = False
    for rule in dataset.rules:
        if not _matches({key: value for key, value in rule.subject.items() if value != "*"}, subject):
            continue
        if not _matches({key: value for key, value in rule.object.items() if value != "*"}, obj):
            continue
        if not _matches({key: value for key, value in rule.environment.items() if value != "*"}, environment):
            continue
        if rule.effect == "DENY":
            return "DENY"
        allow = True
    return "ALLOW" if allow else "DENY"


class GeneratedEvaluator:
    """Evaluate emitted maintained-ABAC JSON without conversion-module imports."""

    def __init__(self, generated_dir):
        root = Path(generated_dir)
        self.subject_map = json.loads((root / "subject_map.json").read_text(encoding="utf-8"))
        self.object_map = json.loads((root / "object_map.json").read_text(encoding="utf-8"))
        self.users = json.loads((root / "user_attr.json").read_text(encoding="utf-8"))["users"]
        self.objects = json.loads((root / "obj_attr.json").read_text(encoding="utf-8"))["objects"]
        self.rules = json.loads((root / "policy.json").read_text(encoding="utf-8"))["rules"]
        self.environment_dir = root / "environments"

    def _environment(self, environment_id):
        return json.loads(
            (self.environment_dir / environment_id / "env_attr.json").read_text(encoding="utf-8")
        )["env"]

    def evaluate(self, subject_id, object_id, environment_id):
        if subject_id not in self.subject_map or object_id not in self.object_map:
            raise MuSimAValidationError("generated mapping lacks requested entity")
        subject = self.users[subject_id]
        uid = self.subject_map[subject_id]["linux_uid"]
        if subject["uid"] != uid:
            raise MuSimAValidationError("subject map and generated user attributes disagree")
        user_attributes = subject["avps"]
        path = self.object_map[object_id]["future_linux_path"]
        object_attributes = self.objects[path]
        environment = self._environment(environment_id)
        allow = False
        for rule in self.rules:
            if rule.get("op") != "READ":
                continue
            if not _matches(rule.get("user", {}), user_attributes):
                continue
            if not _matches(rule.get("obj", {}), object_attributes):
                continue
            if not _matches(rule.get("env", {}), environment):
                continue
            if rule.get("effect", "ALLOW") == "DENY":
                return "DENY"
            if rule.get("effect", "ALLOW") != "ALLOW":
                raise MuSimAValidationError("generated policy contains an unknown effect")
            allow = True
        return "ALLOW" if allow else "DENY"


def _comparison_counts():
    return {
        "allows": 0,
        "denies": 0,
        "false_allows": 0,
        "false_denies": 0,
        "matches": 0,
    }


def _record_comparison(counts, expected, actual):
    if expected == "ALLOW":
        counts["allows"] += 1
    else:
        counts["denies"] += 1
    if expected == actual:
        counts["matches"] += 1
    elif actual == "ALLOW":
        counts["false_allows"] += 1
    else:
        counts["false_denies"] += 1


def validate_all_tuples(dataset, source_path, generated_dir):
    """Compare raw and emitted-policy evaluators to every source ACM tuple."""
    acm = load_acm(source_path, dataset)
    generated = GeneratedEvaluator(generated_dir)
    raw = _comparison_counts()
    emitted = _comparison_counts()
    tuples_tested = 0
    for subject_id in dataset.subjects:
        for object_id in dataset.objects:
            for environment_id in dataset.environments:
                expected = "ALLOW" if acm.decision(subject_id, object_id, environment_id) else "DENY"
                _record_comparison(raw, expected, evaluate_source(dataset, subject_id, object_id, environment_id))
                _record_comparison(emitted, expected, generated.evaluate(subject_id, object_id, environment_id))
                tuples_tested += 1
    return {"emitted_abac": emitted, "raw_musima": raw, "tuples_tested": tuples_tested}


def validate_base_log(dataset, source_path, log_path):
    """Validate ordered BASE-MIXED rows directly against the source ACM."""
    acm = load_acm(source_path, dataset)
    counts = {"allow_count": 0, "deny_count": 0, "mismatch_count": 0, "requests": 0}
    with Path(log_path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["subject", "object", "environment", "access"]:
            raise MuSimAValidationError("BASE-MIXED log header is unsupported")
        for row in reader:
            try:
                expected = "ALLOW" if acm.decision(row["subject"], row["object"], row["environment"]) else "DENY"
            except (KeyError, MuSimAValidationError) as error:
                raise MuSimAValidationError("BASE-MIXED log contains an invalid entity") from error
            actual = "ALLOW" if row["access"] == "permit" else "DENY" if row["access"] == "deny" else None
            if actual is None:
                raise MuSimAValidationError("BASE-MIXED log contains an invalid decision")
            counts["requests"] += 1
            counts["allow_count" if actual == "ALLOW" else "deny_count"] += 1
            if actual != expected:
                counts["mismatch_count"] += 1
    return counts

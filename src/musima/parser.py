"""MuSimA source-bundle parsing and normalization."""

import hashlib
import json
import zipfile
from pathlib import Path

from .schema import Dataset, MuSimAValidationError, RESERVED_PREFIX, Rule


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _member_name(names, suffix):
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise MuSimAValidationError(
            "expected exactly one {} member, found {}".format(suffix, matches)
        )
    return matches[0]


def _as_identifiers(data, key):
    values = tuple(data.get(key, ()))
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise MuSimAValidationError("{} must contain non-empty string identifiers".format(key))
    if len(values) != len(set(values)):
        raise MuSimAValidationError("{} contains duplicate identifiers".format(key))
    return values


def _values(data, key, attributes):
    values = data.get(key)
    if not isinstance(values, dict) or set(values) != set(attributes):
        raise MuSimAValidationError("{} does not match its attribute namespace".format(key))
    normalized = {}
    for attribute in attributes:
        choices = tuple(values[attribute])
        if not choices or any(not isinstance(value, str) or not value for value in choices):
            raise MuSimAValidationError("{} has invalid values for {}".format(key, attribute))
        if len(choices) != len(set(choices)):
            raise MuSimAValidationError("{} has duplicate values for {}".format(key, attribute))
        normalized[attribute] = choices
    return normalized


def _assignments(data, key, entities, attributes, allowed_values):
    source = data.get(key)
    if not isinstance(source, dict) or set(source) != set(entities):
        raise MuSimAValidationError("{} does not match its entity namespace".format(key))
    normalized = {}
    for entity in entities:
        values = source[entity]
        if not isinstance(values, list) or len(values) != len(attributes):
            raise MuSimAValidationError("{} has invalid assignments for {}".format(key, entity))
        assignment = dict(zip(attributes, values))
        for attribute, value in assignment.items():
            if value not in allowed_values[attribute]:
                raise MuSimAValidationError(
                    "{} has invalid value {} for {}".format(key, value, attribute)
                )
        normalized[entity] = assignment
    return normalized


def _parse_rule(text, effect, subject_attributes, object_attributes, environment_attributes,
                subject_values, object_values, environment_values):
    if not isinstance(text, str) or not text:
        raise MuSimAValidationError("rule must be a non-empty string")
    pairs = {}
    for predicate in text.split(","):
        if "=" not in predicate:
            raise MuSimAValidationError("invalid rule predicate: {}".format(predicate))
        name, value = (part.strip() for part in predicate.split("=", 1))
        if not name or not value or name in pairs:
            raise MuSimAValidationError("invalid rule predicate: {}".format(predicate))
        pairs[name] = value

    namespaces = (
        (subject_attributes, subject_values),
        (object_attributes, object_values),
        (environment_attributes, environment_values),
    )
    expected = set(subject_attributes) | set(object_attributes) | set(environment_attributes)
    if set(pairs) != expected:
        raise MuSimAValidationError("rule does not define exactly the expected attributes")
    sections = []
    for attributes, allowed in namespaces:
        section = {}
        for attribute in attributes:
            value = pairs[attribute]
            if value != "*" and value not in allowed[attribute]:
                raise MuSimAValidationError("rule has invalid {} value {}".format(attribute, value))
            section[attribute] = value
        sections.append(section)
    return Rule(effect=effect, subject=sections[0], object=sections[1], environment=sections[2])


def _check_reserved_names(*attribute_sets):
    for attributes in attribute_sets:
        for attribute in attributes:
            if attribute.startswith(RESERVED_PREFIX):
                raise MuSimAValidationError(
                    "source attribute {} uses reserved translator prefix {}".format(
                        attribute, RESERVED_PREFIX
                    )
                )


def load_dataset(source_path, logical_id=None):
    """Load one immutable MuSimA ZIP into a validated normalized model."""
    path = Path(source_path)
    if not path.is_file():
        raise MuSimAValidationError("source archive is missing: {}".format(path))
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        output_member = _member_name(names, "output.json")
        _member_name(names, "ACM.txt")
        _member_name(names, "access_data.txt")
        raw = json.loads(archive.read(output_member))

    subjects = _as_identifiers(raw, "S")
    objects = _as_identifiers(raw, "O")
    environments = _as_identifiers(raw, "E")
    subject_attributes = _as_identifiers(raw, "SA")
    object_attributes = _as_identifiers(raw, "OA")
    environment_attributes = _as_identifiers(raw, "EA")
    _check_reserved_names(subject_attributes, object_attributes, environment_attributes)

    subject_values = _values(raw, "SAV", subject_attributes)
    object_values = _values(raw, "OAV", object_attributes)
    environment_values = _values(raw, "EAV", environment_attributes)
    subject_assignments = _assignments(raw, "SV", subjects, subject_attributes, subject_values)
    object_assignments = _assignments(raw, "OV", objects, object_attributes, object_values)
    environment_assignments = _assignments(raw, "EV", environments, environment_attributes, environment_values)

    arguments = (subject_attributes, object_attributes, environment_attributes,
                 subject_values, object_values, environment_values)
    permit_rules = tuple(_parse_rule(rule, "ALLOW", *arguments)
                         for rule in raw.get("permit_rules", ()))
    deny_rules = tuple(_parse_rule(rule, "DENY", *arguments)
                       for rule in raw.get("deny_rules", ()))
    if not permit_rules and not deny_rules:
        raise MuSimAValidationError("dataset has no policy rules")

    return Dataset(
        logical_id=logical_id or path.stem,
        source_filename=path.name,
        source_sha256=sha256_file(path),
        subjects=subjects,
        objects=objects,
        environments=environments,
        subject_attributes=subject_attributes,
        object_attributes=object_attributes,
        environment_attributes=environment_attributes,
        subject_values=subject_values,
        object_values=object_values,
        environment_values=environment_values,
        subject_assignments=subject_assignments,
        object_assignments=object_assignments,
        environment_assignments=environment_assignments,
        permit_rules=permit_rules,
        deny_rules=deny_rules,
    )

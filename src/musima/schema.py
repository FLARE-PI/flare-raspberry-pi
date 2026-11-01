"""Normalized, Linux-independent MuSimA data structures."""

from dataclasses import dataclass
from typing import Mapping, Tuple


RESERVED_PREFIX = "__musima_"
UNIVERSAL_SUBJECT_ATTRIBUTE = "__musima_any_subject"
UNIVERSAL_OBJECT_ATTRIBUTE = "__musima_any_object"
UNIVERSAL_VALUE = "1"


class MuSimAValidationError(ValueError):
    """Raised when a MuSimA source bundle violates the supported schema."""


@dataclass(frozen=True)
class Rule:
    effect: str
    subject: Mapping[str, str]
    object: Mapping[str, str]
    environment: Mapping[str, str]


@dataclass(frozen=True)
class Dataset:
    logical_id: str
    source_filename: str
    source_sha256: str
    subjects: Tuple[str, ...]
    objects: Tuple[str, ...]
    environments: Tuple[str, ...]
    subject_attributes: Tuple[str, ...]
    object_attributes: Tuple[str, ...]
    environment_attributes: Tuple[str, ...]
    subject_values: Mapping[str, Tuple[str, ...]]
    object_values: Mapping[str, Tuple[str, ...]]
    environment_values: Mapping[str, Tuple[str, ...]]
    subject_assignments: Mapping[str, Mapping[str, str]]
    object_assignments: Mapping[str, Mapping[str, str]]
    environment_assignments: Mapping[str, Mapping[str, str]]
    permit_rules: Tuple[Rule, ...]
    deny_rules: Tuple[Rule, ...]

    @property
    def rules(self):
        return self.permit_rules + self.deny_rules

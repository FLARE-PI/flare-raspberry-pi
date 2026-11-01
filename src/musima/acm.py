"""Direct source ACM parsing and tuple lookup."""

import io
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .schema import MuSimAValidationError


@dataclass(frozen=True)
class AccessControlMatrix:
    subjects: tuple
    objects: tuple
    environments: tuple
    rows: tuple

    def decision(self, subject_id, object_id, environment_id):
        try:
            subject_index = self.subjects.index(subject_id)
            object_index = self.objects.index(object_id)
            environment_index = self.environments.index(environment_id)
        except ValueError as error:
            raise MuSimAValidationError("ACM lookup uses an unknown entity") from error
        return self.rows[subject_index * len(self.objects) + object_index][environment_index]


def load_acm(source_path, dataset):
    path = Path(source_path)
    with zipfile.ZipFile(path) as archive:
        members = [name for name in archive.namelist() if name.endswith("ACM.txt")]
        if len(members) != 1:
            raise MuSimAValidationError("expected one ACM.txt member")
        rows = []
        with archive.open(members[0]) as raw:
            for line in io.TextIOWrapper(raw, encoding="utf-8"):
                fields = line.split()
                if not fields:
                    continue
                if len(fields) != len(dataset.environments) or any(field not in {"0", "1"} for field in fields):
                    raise MuSimAValidationError("ACM contains an invalid row")
                rows.append(tuple(int(field) for field in fields))
    expected = len(dataset.subjects) * len(dataset.objects)
    if len(rows) != expected:
        raise MuSimAValidationError("ACM has {} rows, expected {}".format(len(rows), expected))
    return AccessControlMatrix(dataset.subjects, dataset.objects, dataset.environments, tuple(rows))

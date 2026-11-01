# FLARE source snapshot

This is an anonymous, source-only preparation for a future public FLARE
repository. It is intentionally separate from the checksum-backed experimental
evidence bundle. It contains implementation snapshots, configuration examples,
and the historical Raspberry Pi integration patch, but no private device logs,
raw experimental results, Git history, credentials, or manuscript files.

## What is included

- `src/abac_lsm/`: ABAC LSM implementation snapshot.
- `src/abac_utils/`: userspace control utility snapshot.
- `src/musima/`: dependency-free MuSimA translator and offline validation
  source.
- `src/phase3_gpio_client.c`: GPIO v2 helper source.
- `src/bmp280_*.py`: BMP280 collector/helper source.
- `kernel_patch/`: historical Raspberry Pi Phase 3 integration patch.
- `configs/`: translated MuSimA CORRECTNESS configuration and systemd/collector
  examples.
- `LICENSES/` and `THIRD_PARTY_NOTICES.md`: retained required attribution.

## Deliberate limits

This snapshot is ready for code review and a new GitHub repository, not for
claiming exact reconstruction of the evaluated p2/p3/p4/base kernels. The
ordered final patches, kernel configurations, and deployment manifests for
those releases have not yet been recovered. Do not deploy the historical patch
or copied services to a live system without an independently reviewed build,
rollback, and hardware-safety procedure.

The companion offline-evidence package is intentionally not included here. It
should be published separately after a distribution decision because it is
approximately 327 MB and contains raw measurement data.

## Local inspection

No network access or privileged operations are required to inspect the Python
modules:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -c \
  'import musima.acm, musima.cli, musima.emit, musima.parser, musima.schema, musima.trace, musima.validate'
```

This checks that the included dependency-free MuSimA modules import. It does
not build a kernel or operate hardware.

## Before public release

1. Select a license for original FLARE work.
2. Review GPL-2.0 obligations for derived code and preserve all notices.
3. Recover and checksum the final p2/p3/p4/base patch/configuration series if
   exact kernel rebuildability is a release goal.
4. Perform a final PII, credential, and license scan after any further files
   are added.
5. Create a new anonymous GitHub repository only after those decisions.

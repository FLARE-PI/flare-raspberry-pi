# Repository scope and recovery status

## Ready now

This repository can be published as an anonymous source snapshot after a
license decision. It is clean of local Git metadata, private device data,
personal paths, host/IP strings, and credentials. The retained code supports
inspection of the LSM, userspace control plane, MuSimA adapter, GPIO helper,
BMP280 collector, configuration examples, and the historical Phase 3 patch.

## Deferred recovery

The p2/p3/p4/base recovery is intentionally deferred. In particular, this
folder does not yet contain a complete ordered patch series, exact final kernel
`.config` files, module/DTB manifests, or a kernel-build script that reproduces
each evaluated release. This is a reproducibility gap, not a reason to alter
the existing evidence or fabricate a build recipe.

## Suggested public layout

Keep this code repository lightweight. Publish the evidence bundle separately
as a versioned release asset or archival record, with its own checksums. Do not
commit SD-card images, kernel build directories, caches, credentials, raw
device logs, or unreviewed generated data.

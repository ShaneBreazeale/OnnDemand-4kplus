# License scope

## Original OnnDemand contributions

Original contributions made for OnnDemand by ShaneBreazeale and its contributors
are licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
This includes the original host CLI in `src/onndemand`, the original SSH server
in `native/rootssh`, new OnnDemand launchers, packaging/build utilities, tests,
and documentation, subject to the third-party and legacy exclusions below.

The grant covers only rights held by the respective contributors. It does not
claim ownership of, or change the terms of, pre-existing third-party material.
For a file containing both inherited material and new original contributions,
the Apache-2.0 grant applies to those new contributions only.

## Third-party components

Vendored payload sources and their modifications retain the license and notices
under `vendor/coffey`. SSH dependencies and bundled native helpers retain their
applicable Apache-2.0, BSD-3-Clause, and MIT notices. Existing copyrights, source
attribution, modification notices, and license texts must be preserved.
See [THIRD_PARTY.md](THIRD_PARTY.md) and [NOTICE](NOTICE).

The distribution metadata identifies Apache-2.0 for OnnDemand together with the
BSD-3-Clause and MIT terms of bundled components. This is not an offer to choose
one license for all components.

## Inherited 4K Pro material: excluded from this grant

This repository retains material from
[openensemble/onn-4k-pro-2026-unlock-root](https://github.com/openensemble/onn-4k-pro-2026-unlock-root).
The upstream notices state that no open-source license is granted for the
original workflow, helper sources, and tests. Those inherited portions are
**not relicensed by this project**. No additional permission to use, modify,
or redistribute them is granted here; obtain permission from their rights
holders where required.

The inherited content is identifiable in the upstream snapshot at commit
`5b096b378d38d99235e8ca86c64bf214dc198e6a`. The paths below identify that content,
including inherited portions of files later modified. Fully new replacement
text and original later additions are covered as described above.

```
.github/workflows/pages.yml
.gitignore
NATIVE_SHA256.json
README.md
THIRD_PARTY.md
assets/images/onn-4k-pro-2026.png
bin/armeabi-v7a/read_state
bin/armeabi-v7a/unlock_once
connection.py
connection_identity.py
console_ui.py
docs/BUILD.md
docs/HOST_TOOLS.md
docs/MANUAL.md
docs/PAGES.md
docs/RECOVERY.md
docs/RESULTS.md
dsu_recovery.py
evidence/VALIDATION.json
guide.py
guide_core.py
host_build.py
native/dsu_console.c
native/flash_init_boot.sh.in
native/read_state.c
native/test_unlock_logic.c
native/unlock_logic.h
native/unlock_once.c
onn2026.py
profile.json
root_workflow.py
site/.nojekyll
site/assets/favicon.svg
site/assets/onn-4k-pro-2026.png
site/index.html
site/script.js
site/sitemap.xml
site/styles.css
tests/test_android_identity.py
tests/test_connection.py
tests/test_console_ui.py
tests/test_dsu_recovery.py
tests/test_erofs_tools.py
tests/test_flash.py
tests/test_guards.py
tests/test_guide.py
tests/test_host_build.py
tests/test_interrupts.py
tests/test_reboots.py
tests/test_slot_report.py
tests/test_slots.py
tests/test_workflow.py
tools/build_dsu.py
tools/build_native.py
tools/erofs_metadata.py
tools/erofs_tools.py
tools/extract_dsu_ota.py
tools/extract_full_ota.py
tools/slot_report.py
```

The installable OnnDemand wheel does not include the legacy 4K Pro workflow,
its firmware profile, or its original native helpers. Retaining those materials
in the repository does not make them Apache-2.0 or establish permission to
redistribute them. Removing or relicensing legacy material requires a separate
provenance and permission review.

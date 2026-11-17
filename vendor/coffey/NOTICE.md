# Coffey payload source provenance

Reference: https://github.com/yakidango-official/GhostLock-H80GT
Upstream revision: 33541d1a852a926f782602aa34d79cfbffbd4bb6
License: Apache-2.0; see LICENSE. Upstream credits IonStack/CyberMeowfia and
KernelSnitch contributors. Original notices in source files are preserved.

These files are the local coffey port, not an unmodified upstream checkout.
The core main/util/slide/sysctl/common/env_defaults sources and the coffey target
were modified for the onn. 4K Plus build 15051976. This snapshot preserves the
source used by the existing local build-cur payload. Only the coffey target and
its required KernelSnitch headers are included; no downloaded firmware,
per-device state, account data, or private keys are included.

Build with tools/build_release_assets.py using Android NDK 28.2.13676358.
The builder records source content hashes and compiler revision in the bundled
asset manifest. Binary checksums establish integrity relative to those pins;
they are not an independent signature or proof that a root attempt is safe.

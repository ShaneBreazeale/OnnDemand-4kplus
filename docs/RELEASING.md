# Building and releasing OnnDemand

## Install and run

From a checkout:

```sh
uv tool install .
onndemand --version
onndemand --help
```

For development, `uv run onndemand --help` uses an editable project environment.
`python3 onndemand.py` and the older `tools/coffey-ssh.py` launcher remain
available in a checkout. Installed tools use bundled package files, never paths
under an ignored `work/exploit` directory.

The runtime needs Python 3.10+, Bash, ADB, and an SSH client. The package includes
verified ARM64 and ARMv7 SSH helpers and the coffey root payload; Go and the NDK
are build-time requirements only. Linux and macOS are the supported host
platforms for the current Bash-based launcher. Native Windows is not supported;
WSL requires its own working ADB connection.

## State and package data

Checkout commands retain the existing `work/` state location. Installed commands
use `~/.local/share/onndemand`. Set `ONNDEMAND_HOME` to choose another writable
location or share state between a checkout and an installed tool. Client keys
are stored under `ssh/client/` within that location. Do not point installed state
at site-packages.

Read-only helpers and scripts live under `onndemand/assets` inside the wheel.
The package's manifest pins each native helper and the loader by SHA256 and size.
The CLI verifies its default SSH helper before deployment; the root launcher
verifies the root binary and loader before execution. Explicitly supplied
`--server-binary` files are user overrides, with a local digest checked again
after upload. There are no default downloads of executable payloads at runtime.

Checksum verification detects corruption relative to the package pins. It is
not a separate signing authority: install distributions from a source you trust.

## Native source and builds

`vendor/coffey` contains the required local coffey port, target table, upstream
revision, modification notice, and Apache-2.0 license. The root loader is tracked
at `src/onndemand/assets/payload/rootloop.sh`. Neither depends on ignored work
files. `native/rootssh` holds the SSH server and locked Go module checksums.

The release assets are built with Android NDK **28.2.13676358** and Go
**1.27.4**. Rebuild with:

```sh
python3 tools/build_release_assets.py --ndk /path/to/android-ndk-r28c --go /path/to/go
python3 tools/build_release_assets.py --check
```

The builder uses fixed target flags, disables Go VCS/path/build-ID embedding, and
writes the compiler revisions, source hashes, binary hashes, and sizes into
`src/onndemand/assets/manifest.json`. Review changes to both source and pins.
Source edits require rebuilding before release. Two builds using the pinned
local toolchains produced the same bundled assets. The vendored C payload also
matched the previously tested local `build-cur` binary byte-for-byte.
Cross-host byte identity between the macOS and Linux NDK toolchains has not
been measured here.

To deliberately build the SSH helper during setup, use `onndemand --build-server`.
This requires Go and uses the SSH sources included in the installed package.
The default uses the verified prebuilt helper instead.

## Version and startup banner

The package version is derived with hatch-vcs from Git release tags. A clean
`v1.2.3` tag produces package version `1.2.3`; prerelease tags such as
`v1.2.3rc1` are supported. Untagged or modified builds report a development
version. Build the wheel from the tagged commit, not from an edited release tree.

The generated `_version.py` travels in both the source distribution and wheel.
Installed commands do not need Git or a checkout to report their release version.
`onndemand --version` writes only the version to stdout and does not require ADB.
An interactive invocation displays the OnnDemand banner and packaged version
on stderr. `--no-banner` suppresses it; redirected output does not get a banner.

## Distribution validation

```sh
uv build
python3 tools/check_distribution.py dist/*.whl
```

The wheel check verifies all bundled native assets, required scripts, console
entry point, and exclusion of private/generated state. For a tagged release:

```sh
python3 tools/check_distribution.py dist/*.whl --tag v1.2.3
```

Install the wheel or source distribution in a clean environment outside this
checkout and run `onndemand --version` and `onndemand --help`. Test a Git install
from the intended release tag as well. An isolated local `v0.1.0` fixture was
built, checked, and installed via uv from Git; the installed CLI reported exactly
`0.1.0`. That fixture did not create a tag in the real project or publish anything.

The release workflow checks tracked asset pins, runs packaging/setup tests,
builds the source distribution and wheel, validates a tag's version, installs
outside the checkout, and uploads distribution artifacts with `SHA256SUMS`.
It does not automatically publish to PyPI or create a GitHub Release. Review
artifacts and checks before publishing a release.

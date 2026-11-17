#!/usr/bin/env python3
"""Guarded temporary-root session for an onn, using a loader you supply.

This tool owns the risky part of temporary root that is easy to get wrong: it
stages one pinned binary, makes the shell it leaves behind prove it is really
uid 0 with block-device access, and then either runs one command or hands the
live session to another tool. It contains no exploit and never claims root on
the loader's word.

The loader contract is deliberately small:

  * run as the ordinary shell user;
  * gain kernel-level privilege however it does that;
  * replace itself with a root shell: ``execl("/system/bin/sh", "sh", NULL)``.

Its stdin, stdout and stderr are a pipe from this process, so the shell that
results *is* the session used for verification and for the requested command.

A loader that prints "root" and exits is rejected: the proof is ``id -u`` run
after the loader returns a shell, plus a read of a block device that the ordinary
shell cannot open.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import struct
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
STAGE_DIR = "/data/local/tmp"
MAX_LOADER_BYTES = 8 * 1024 * 1024
MAX_ANSWER_BYTES = 64 << 20


class Stop(Exception):
    """A static, shareable explanation; never include raw transport output."""


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_loader(path, pin):
    """Refuse anything that is not a small, pinned ELF for ARM or AArch64."""
    path = Path(path)
    if not path.is_file():
        raise Stop("The loader file does not exist.")
    size = path.stat().st_size
    if not 0 < size <= MAX_LOADER_BYTES:
        raise Stop("The loader must be between 1 byte and %d MiB." % (MAX_LOADER_BYTES >> 20))
    with path.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise Stop("The loader is not an ELF binary.")
    machine = struct.unpack("<H" if header[5] == 1 else ">H", header[18:20])[0]
    if machine not in (40, 183):
        raise Stop("The loader is not ARM (EM_ARM) or AArch64 (EM_AARCH64).")
    actual = sha256_file(path)
    if not re.fullmatch(r"[0-9a-f]{64}", pin or "") or actual != pin:
        raise Stop("The loader SHA-256 does not match the pin; refusing to stage it.")
    return {"name": path.name, "bytes": size, "sha256": actual,
            "arch": "arm" if machine == 40 else "aarch64"}


class RootSession:
    """Byte- and line-oriented conversation with a shell started by a loader."""

    def __init__(self, proc):
        self.proc = proc
        self.marker = ("ONN-TR-" + secrets.token_hex(8)).encode()

    def _read(self, size, timeout):
        try:
            ready, _, _ = select.select([self.proc.stdout.fileno()], [], [], timeout)
        except (OSError, ValueError) as error:
            raise Stop("The root session is no longer readable.") from error
        if not ready:
            raise Stop("The root session stopped answering; the loader probably failed.")
        chunk = os.read(self.proc.stdout.fileno(), size)
        if not chunk:
            raise Stop("The root session closed before it answered; the loader did not "
                       "leave a shell.")
        return chunk

    def _until(self, pattern, timeout):
        data = b""
        while not re.search(pattern, data):
            data += self._read(4096, timeout)
            if len(data) > MAX_ANSWER_BYTES:
                raise Stop("The root session produced more output than the safety limit.")
        return data

    def text(self, script, timeout=60):
        """Run a script and return its combined output plus the last status."""
        self.proc.stdin.write(("{ %s\n} 2>&1\nprintf '\\n%s %%s\\n' \"$?\"\n" %
                               (script, self.marker.decode())).encode())
        self.proc.stdin.flush()
        data = self._until(re.escape(self.marker) + rb" -?[0-9]+\n", timeout)
        match = re.search(re.escape(self.marker) + rb" (-?[0-9]+)\n", data)
        if not match:
            raise Stop("The root session did not terminate its answer.")
        head = data[:match.start()].decode("utf-8", "replace").strip("\r\n")
        return {"text": head, "returncode": int(match.group(1))}

    def read_exact(self, command, size, timeout=900):
        """Run a command whose stdout is exactly ``size`` raw bytes."""
        if size <= 0:
            raise Stop("Refusing a raw read of an unknown or empty length.")
        self.proc.stdin.write((command + "\n").encode())
        self.proc.stdin.flush()
        data = b""
        while len(data) < size:
            data += self._read(min(1 << 20, size - len(data)), timeout)
        leftover = self.text(":", timeout=30)
        if leftover["text"]:
            raise Stop("Unexpected bytes followed the raw payload; refusing to trust it.")
        return data

    def stream_to(self, stream, command, timeout=3600):
        """Stream a command's stdout into a file until a random end marker.

        Returns the number of payload bytes written. Memory use stays bounded, so
        this is safe for a multi-gigabyte tar of /data.
        """
        marker = ("ONN-END-" + secrets.token_hex(12)).encode()
        needle = b"\n" + marker + b" "
        self.proc.stdin.write(("(\n" + command + "\n) 2>/dev/null\nprintf '\\n" +
                               marker.decode() + " %s\\n' \"$?\"\n").encode())
        self.proc.stdin.flush()
        pending = b""
        written = 0
        while True:
            chunk = self._read(1 << 20, timeout)
            pending += chunk
            if needle in pending:
                head, _, status = pending.partition(needle)
                while b"\n" not in status:
                    if len(status) > 3:
                        raise Stop("The streamed command returned a malformed status.")
                    status += self._read(4096, timeout)
                code = status.split(b"\n", 1)[0]
                if not re.fullmatch(rb"[0-9]{1,3}", code):
                    raise Stop("The streamed command returned a malformed status.")
                if int(code) != 0:
                    raise Stop("The streamed command failed (exit %d); payload is incomplete." % int(code))
                stream.write(head)
                written += len(head)
                return written
            keep = len(needle) - 1
            if len(pending) > keep:
                stream.write(pending[:-keep])
                written += len(pending) - keep
                pending = pending[-keep:]
            if written > (64 << 30):
                raise Stop("The streamed payload exceeded the 64 GiB safety limit.")

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def run_adb(adb, serial, argv, timeout=60, binary=False):
    try:
        return subprocess.run([adb, "-s", serial, *argv], capture_output=True,
                              text=not binary, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as error:
        raise Stop("ADB did not answer within %d seconds." % timeout) from error
    except OSError as error:
        raise Stop("Cannot execute ADB: " + str(error)) from error


def binding(adb, serial):
    """Identity that must not change across a session."""
    result = run_adb(adb, serial, ["shell",
        "getprop ro.serialno; getprop ro.build.fingerprint; getprop ro.bootloader; "
        "getprop ro.boot.slot_suffix; cat /proc/sys/kernel/random/boot_id"])
    lines = (result.stdout or "").splitlines()
    if len(lines) < 5 or not lines[4].strip():
        raise Stop("Cannot read the device identity; check the ADB connection.")
    return {"serial": lines[0].strip(), "fingerprint": lines[1].strip(),
            "bootloader": lines[2].strip(), "slot": lines[3].strip(),
            "boot_id": lines[4].strip()}


def prove(session, slot_letter):
    """Run the proof over a live session; raise unless every read succeeds."""
    result = session.text("id -u\ncat /proc/self/attr/current\ngetenforce\n"
                          "cat /proc/sys/kernel/random/boot_id")
    lines = result["text"].splitlines()
    facts = {
        "uid": int(lines[0]) if lines and lines[0].strip().isdigit() else None,
        "domain": lines[1].strip() if len(lines) > 1 else "",
        "selinux": lines[2].strip() if len(lines) > 2 else "",
        "boot_id": lines[3].strip() if len(lines) > 3 else "",
        "block_bytes": None,
    }
    if facts["uid"] != 0:
        raise Stop("The session is not uid 0 (id -u returned %s)." %
                   (facts["uid"] if facts["uid"] is not None else "nothing"))
    node = "/dev/block/by-name/init_boot_" + (slot_letter or "a")
    size = session.text("wc -c < %s 2>/dev/null || echo denied" % node)["text"].strip()
    if not size.isdigit() or int(size) <= 0:
        raise Stop("A uid-0 shell was obtained, but block devices are still unreadable; "
                   "SELinux or the domain is blocking the backup.")
    facts["block_bytes"] = int(size)
    facts["block_probe"] = node
    return facts


@contextmanager
def open_session(adb, serial, loader, pin, pty=False, state=None):
    """Stage, start, prove and always clean up one loader."""
    state = state if state is not None else {}
    verified = verify_loader(loader, pin)
    staged = STAGE_DIR + "/onn-tr-" + secrets.token_hex(6)
    state.update({"staged": staged, "cleanup_removed": False})
    pushed = run_adb(adb, serial, ["push", str(Path(loader)), staged], timeout=120)
    if pushed.returncode != 0:
        raise Stop("Could not upload the loader to " + STAGE_DIR + ".")
    chmod = run_adb(adb, serial, ["shell", "chmod 700 " + staged], timeout=30)
    if chmod.returncode != 0:
        cleanup(adb, serial, staged, state)
        raise Stop("Could not make the staged loader executable.")
    before = binding(adb, serial)
    argv = [adb, "-s", serial, "shell", "-t" if pty else "-T", staged]
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, bufsize=0)
    except OSError as error:
        cleanup(adb, serial, staged, state)
        raise Stop("Cannot start the loader: " + str(error)) from error
    session = RootSession(proc)
    try:
        facts = prove(session, (before["slot"] or "_a").lstrip("_"))
        after = binding(adb, serial)
        if after["boot_id"] != before["boot_id"]:
            raise Stop("The onn rebooted during the loader run; the session is not valid.")
        if (after["fingerprint"], after["serial"]) != (before["fingerprint"], before["serial"]):
            raise Stop("The device identity changed during the loader run.")
        facts.update({"slot_before": before["slot"], "slot_after": after["slot"],
                      "fingerprint": after["fingerprint"]})
        yield session, verified, facts
    finally:
        session.close()
        cleanup(adb, serial, staged, state)


def cleanup(adb, serial, staged, state=None):
    """Remove the staged loader and record whether the removal is proven."""
    try:
        result = run_adb(adb, serial, ["shell", "rm -f %s; test ! -e %s && echo removed" %
                                       (staged, staged)], timeout=30)
        removed = "removed" in (result.stdout or "")
    except Stop:
        removed = False
    if state is not None:
        state["cleanup_removed"] = removed
    return removed


@contextmanager
def direct_session(adb, serial):
    """Reuse an already-rooted device without staging a loader."""
    before = binding(adb, serial)
    try:
        proc = subprocess.Popen([adb, "-s", serial, "shell", "-T"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    except OSError as error:
        raise Stop("Cannot start an ADB shell: " + str(error)) from error
    session = RootSession(proc)
    try:
        facts = prove(session, (before["slot"] or "_a").lstrip("_"))
        yield session, None, facts
    finally:
        session.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="ADB serial or IP:port of one onn")
    parser.add_argument("--adb", default="adb", help="ADB executable or path")
    parser.add_argument("--loader", type=Path, required=True,
                        help="Loader binary that follows the documented contract")
    parser.add_argument("--loader-sha256", required=True, help="Pinned SHA-256 of that binary")
    parser.add_argument("--exec", dest="command",
                        help="Shell command to run as root after the proof")
    parser.add_argument("--pty", action="store_true",
                        help="Use a pty for the loader (only if it needs a terminal)")
    parser.add_argument("--profile", type=Path, default=ROOT / "profile.coffey.json")
    parser.add_argument("--output-dir", type=Path,
                        help="Receipt directory; default under ignored work/temp-root/")
    args = parser.parse_args(argv)
    adb = shutil.which(args.adb)
    if not adb:
        parser.error("ADB was not found; install Android platform-tools or use --adb")
    try:
        profile = json.loads(args.profile.read_text())
    except (OSError, ValueError):
        parser.error("Cannot read the reference profile; supply a valid --profile JSON file")
    output = args.output_dir or (ROOT / "work/temp-root" /
        (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]))
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError:
        parser.error("Cannot create the receipt directory; choose a new writable --output-dir")
    state = {}
    receipt = {"schema": "onn-temp-root-v1", "at": datetime.now(timezone.utc).isoformat(),
               "profile": profile.get("id"), "loader": None, "root_obtained": False,
               "proof": None, "cleanup_removed": False, "reboot_requested": False,
               "settings_changed": False, "partitions_written": False}
    try:
        with open_session(adb, args.target, args.loader, args.loader_sha256,
                          pty=args.pty, state=state) as (session, verified, facts):
            receipt.update({"loader": verified, "root_obtained": True, "proof": facts,
                            "profile_matches": profile.get("fingerprint") ==
                            facts.get("fingerprint")})
            if args.command:
                result = session.text(args.command, timeout=900)
                receipt["command"] = {"ran": True, "returncode": result["returncode"],
                                      "output_sha256": hashlib.sha256(
                                          result["text"].encode()).hexdigest()}
                sys.stdout.write(result["text"])
    except Stop as error:
        receipt["stop_reason"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        receipt["cleanup_removed"] = state.get("cleanup_removed", False)
    receipt["receipt"] = str(output / "session.json")
    fd = os.open(output / "session.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(json.dumps(receipt, indent=2) + "\n")
    print("Receipt: " + str(output / "session.json"))
    if not receipt["root_obtained"]:
        return 3
    if not receipt["cleanup_removed"]:
        print("Warning: the staged loader may still be in " + STAGE_DIR, file=sys.stderr)
        return 4
    if receipt.get("stop_reason"):
        return 5
    if args.command:
        return receipt.get("command", {}).get("returncode", 5)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Exercise the debloater against a stateful fake ADB, never a device."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "tools/coffey-debloat.sh"
FAKE_ADB = r'''
import json, os, sys
from pathlib import Path
path = Path(os.environ["FAKE_ADB_STATE"])
state = json.loads(path.read_text())
args = sys.argv[1:]
if args[:1] == ["-s"]:
    args = args[2:]
if args == ["get-state"]:
    print("device")
    sys.exit(0)
assert args[0] == "shell", args
command = " ".join(args[1:])
state["commands"].append(command)
rc = 0
for part in command.split(" && "):
    words = part.split()
    if part == "getprop ro.product.device":
        print("coffey")
    elif part.startswith("pm list packages"):
        for package, info in state["packages"].items():
            if info["installed"]:
                print("package:" + package)
    elif words[:2] in (["pm", "uninstall"], ["pm", "disable-user"],
                       ["pm", "install-existing"], ["pm", "enable"]):
        package = words[-1]
        info = state["packages"][package]
        operation = words[1]
        if operation in state.get("fail", []):
            rc = 1
            break
        if operation == "uninstall":
            info["installed"] = False
        elif operation == "disable-user":
            info["enabled"] = False
        elif operation == "install-existing":
            info["installed"] = True
        elif operation == "enable":
            info["enabled"] = True
    else:
        raise AssertionError(command)
path.write_text(json.dumps(state))
sys.exit(rc)
'''


class DebloatTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "tools").mkdir()
        self.script = self.root / "tools/coffey-debloat.sh"
        shutil.copyfile(SCRIPT, self.script)
        (self.root / "adb").write_text("#!" + sys.executable + "\n" + FAKE_ADB)
        (self.root / "adb").chmod(0o755)
        self.state_path = self.root / "state.json"
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        FAKE_ADB_STATE=str(self.state_path))

    def initialize(self, packages, fail=()):
        self.state_path.write_text(json.dumps({"packages": packages, "fail": fail, "commands": []}))

    def run_script(self, *args):
        return subprocess.run(["bash", str(self.script), *args], env=self.env,
                              capture_output=True, text=True, timeout=15)

    def state(self):
        return json.loads(self.state_path.read_text())

    def test_every_critical_package_is_protected(self):
        packages = re.search(r'CRITICAL="(.*?)"', SCRIPT.read_text(), re.S).group(1).split()
        self.initialize({p: {"installed": True, "enabled": True} for p in packages})
        result = self.run_script("--remove", " ".join(packages), "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(c.startswith(("pm uninstall", "pm disable-user"))
                             for c in self.state()["commands"]))
        self.assertTrue(all(p["installed"] and p["enabled"]
                            for p in self.state()["packages"].values()))

    def test_uninstall_and_disable_records_restore_their_operation(self):
        package = "example.optional.app"
        for operation, fail in (("uninstalled", []), ("disabled", ["uninstall"])):
            with self.subTest(operation=operation):
                self.initialize({package: {"installed": True, "enabled": True}}, fail)
                result = self.run_script("--remove", package, "--yes")
                self.assertEqual(result.returncode, 0, result.stderr)
                record = Path(re.search(r'record: (.*)', result.stdout).group(1))
                self.assertEqual(record.read_text(), package + " " + operation + "\n")
                state = self.state()
                self.assertFalse(state["packages"][package][
                    "installed" if operation == "uninstalled" else "enabled"])
                result = self.run_script("--restore", str(record))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.state()["packages"][package],
                                 {"installed": True, "enabled": True})

    def test_safe_list_records_disable_fallback(self):
        package = "com.google.android.feedback"
        self.initialize({package: {"installed": True, "enabled": True}}, ["uninstall"])
        result = self.run_script("--apply-safe", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        record = Path(re.search(r'record: (.*)', result.stdout).group(1))
        self.assertEqual(record.read_text(), package + " disabled\n")
        self.assertEqual(self.run_script("--restore", str(record)).returncode, 0)
        self.assertTrue(self.state()["packages"][package]["enabled"])

    def test_legacy_records_restore_uninstalled_and_disabled_apps(self):
        self.initialize({"example.removed": {"installed": False, "enabled": True},
                         "example.disabled": {"installed": True, "enabled": False}})
        record = self.root / "legacy.txt"
        record.write_text("example.removed\nexample.disabled")
        result = self.run_script("--restore", str(record))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(p["installed"] and p["enabled"]
                            for p in self.state()["packages"].values()))

    def test_restore_failure_returns_failure(self):
        self.initialize({"example.disabled": {"installed": True, "enabled": False}}, ["enable"])
        record = self.root / "disabled.txt"
        record.write_text("example.disabled disabled\n")
        result = self.run_script("--restore", str(record))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("[*] restored", result.stdout)


if __name__ == "__main__":
    unittest.main()

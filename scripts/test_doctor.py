"""No tool, KVM device, dependency service or network is used by these tests."""

import contextlib
import io
import json
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import doctor
import check_linux_host


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.path = patch("doctor.shutil.which", return_value="/tools/node")
        self.path.start()
        self.addCleanup(self.path.stop)

    def probe(self):
        return doctor.probe(["node", "--version"], r"^v(\d+\.\d+\.\d+)\b", "Use Node 24.9+", minimum=(24, 9, 0))

    def test_missing_tool_does_not_spawn(self):
        with patch("doctor.shutil.which", return_value=None), patch("doctor.subprocess.run") as run:
            self.assertEqual(self.probe()["status"], "missing")
            run.assert_not_called()

    def test_version_floor(self):
        for version, status in [("24.8.9", "failed"), ("24.9.0", "passed"), ("25.0.0", "passed")]:
            with self.subTest(version=version), patch("doctor.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "v" + version, "")):
                self.assertEqual(self.probe()["status"], status)

    def test_nonzero_and_unrecognized_output_are_redacted(self):
        for code, output in [(1, "secret-token"), (0, "private-path secret-token")]:
            with self.subTest(code=code), patch("doctor.subprocess.run", return_value=subprocess.CompletedProcess([], code, output, output)):
                report = self.probe()
                self.assertEqual(report["status"], "failed")
                self.assertNotIn("secret-token", json.dumps(report))
                self.assertNotIn("private-path", json.dumps(report))

    def test_timeout_and_exec_failure_are_redacted(self):
        for error in [subprocess.TimeoutExpired([], 3, output="secret"), OSError("secret")]:
            with self.subTest(error=type(error)), patch("doctor.subprocess.run", side_effect=error):
                result = self.probe()
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("secret", json.dumps(result))

    def test_no_shell_stdin_or_automatic_rust_install(self):
        with patch("doctor.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "rustc 1.92.0 (hash date)", "")) as run:
            result = doctor.probe(["rustc", "--version"], r"^rustc (\d+\.\d+\.\d+)\b", "Install explicitly", exact="1.92.0", rust_channel="1.92.0")
        self.assertEqual(result["status"], "passed")
        command, = run.call_args.args
        self.assertEqual(command, ["/tools/node", "--version"])
        args = run.call_args.kwargs
        self.assertNotIn("shell", args)
        self.assertEqual(args["stdin"], subprocess.DEVNULL)
        self.assertEqual(args["timeout"], 3)
        self.assertEqual(args["env"]["RUSTUP_AUTO_INSTALL"], "0")
        self.assertEqual(args["env"]["RUSTUP_TOOLCHAIN"], "1.92.0")
        self.assertEqual(args["env"]["CARGO_NET_OFFLINE"], "true")

    def test_exact_pin_rejects_other_compiler(self):
        with patch("doctor.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "rustc 1.93.0", "")):
            result = doctor.probe(["rustc", "--version"], r"^rustc (\d+\.\d+\.\d+)\b", "Use pin", exact="1.92.0")
        self.assertEqual(result["status"], "failed")


class ProfileTests(unittest.TestCase):
    def test_mac_runtime_fails_without_probing_kvm_or_tools(self):
        with patch("doctor.platform.system", return_value="Darwin"), patch("doctor.inspect_host") as host, patch("doctor.probe") as probe:
            report = doctor.inspect("linux-runtime")
        host.assert_not_called()
        probe.assert_not_called()
        self.assertFalse(report["ready"])
        self.assertEqual(report["schema_version"], 1)
        self.assertIn("No services", report["scope"])

    def test_mac_control_plane_does_not_imply_linux_readiness(self):
        with patch("doctor.platform.system", return_value="Darwin"), patch("doctor.inspect_host") as host, patch("doctor.probe", return_value=doctor.check("tool", "passed", "Version 1.0")) as probe:
            report = doctor.inspect("control-plane")
        host.assert_not_called()
        self.assertTrue(report["ready"])
        self.assertEqual(probe.call_count, 7)
        self.assertIn("supported x86_64 release gates", report["scope"])

    def test_unsupported_platform_fails_control_plane(self):
        with patch("doctor.platform.system", return_value="Windows"), patch("doctor.probe", return_value=doctor.check("tool", "passed", "Version 1.0")):
            self.assertFalse(doctor.inspect("control-plane")["ready"])

    def test_prerelease_node_does_not_satisfy_stable_floor(self):
        with patch("doctor.platform.system", return_value="Darwin"), patch("doctor.shutil.which", return_value="/tools/version"), patch("doctor.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "v24.9.0-rc.1", "")):
            report = doctor.inspect("control-plane")
        node = next(item for item in report["checks"] if item["name"] == "node")
        self.assertEqual(node["status"], "failed")

    def test_kvm_failure_is_not_masked_by_matching_binaries(self):
        with patch("doctor.platform.system", return_value="Linux"), patch("doctor.inspect_host", return_value={"architecture": "x86_64", "errors": ["Cannot access the KVM API (errno 13)"]}), patch("doctor.probe", return_value=doctor.check("tool", "passed", "Version 1.17.0")):
            report = doctor.inspect("linux-runtime")
        self.assertFalse(report["ready"])
        self.assertIn("errno 13", report["checks"][1]["detail"])

    def test_matching_pair_and_development_evidence(self):
        with patch("doctor.platform.system", return_value="Linux"), patch("doctor.inspect_host", return_value={"architecture": "aarch64", "errors": []}), patch("doctor.probe", return_value=doctor.check("tool", "passed", "Version 1.17.0")):
            report = doctor.inspect("linux-runtime")
        self.assertTrue(report["ready"])
        self.assertTrue(any(item["name"] == "evidence-scope" and item["status"] == "info" for item in report["checks"]))

    def test_binary_version_mismatch_fails(self):
        with patch("doctor.platform.system", return_value="Linux"), patch("doctor.inspect_host", return_value={"architecture": "x86_64", "errors": []}), patch("doctor.probe", side_effect=[doctor.check("firecracker", "passed", "Version 1.17.0"), doctor.check("jailer", "passed", "Version 1.16.0")]):
            report = doctor.inspect("linux-runtime")
        self.assertFalse(report["ready"])
        self.assertEqual(report["checks"][-1]["name"], "firecracker-jailer-pair")

    def test_json_and_exit_status_for_required_failure(self):
        with patch("doctor.platform.system", return_value="Darwin"), contextlib.redirect_stdout(io.StringIO()) as output:
            status = doctor.main(["--profile", "linux-runtime", "--json"])
        self.assertEqual(status, 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report["ready"])
        self.assertEqual(report["profile"], "linux-runtime")

    def test_text_and_success_exit(self):
        report = {"profile": "control-plane", "scope": doctor.SCOPE, "ready": True, "checks": []}
        with patch("doctor.inspect", return_value=report), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(doctor.main([]), 0)
        self.assertIn("prerequisites", output.getvalue())


class LinuxPreflightTests(unittest.TestCase):
    def test_mac_does_not_open_kvm(self):
        with patch("check_linux_host.platform.system", return_value="Darwin"), patch("check_linux_host.platform.machine", return_value="arm64"), patch("check_linux_host.platform.release", return_value="test-kernel"), patch("check_linux_host.os.open") as opened:
            report = check_linux_host.inspect_host()
        opened.assert_not_called()
        self.assertTrue(report["errors"])

    def test_missing_controllers_and_kvm_permission_failure(self):
        with patch.dict(sys.modules, {"fcntl": types.ModuleType("fcntl")}), patch("check_linux_host.platform.system", return_value="Linux"), patch("check_linux_host.platform.machine", return_value="aarch64"), patch("check_linux_host.platform.release", return_value="test-kernel"), patch("check_linux_host.os.O_CLOEXEC", 0, create=True), patch("check_linux_host.os.open", side_effect=PermissionError(13, "private path")), patch("check_linux_host.Path.read_text", return_value="cpu io"):
            report = check_linux_host.inspect_host()
        self.assertIn("Cannot access the KVM API (errno 13)", report["errors"])
        self.assertIn("Missing cgroup v2 controllers: memory, pids", report["errors"])
        self.assertNotIn("private path", json.dumps(report))


if __name__ == "__main__":
    unittest.main()

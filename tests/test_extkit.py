"""fixture tests for extkit's selection/build workflow."""

import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "mkosi.extra/usr/bin/extkit"
loader = importlib.machinery.SourceFileLoader("extkit", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class ExtensionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config = self.root / "extkit.conf"
        self.config = config
        config.write_text(
            "[Paths]\n"
            f"StateDirectory={self.root / 'state'}\n"
            f"RootDirectory={self.root / 'live'}\n"
            f"BaseDirectory={self.root / 'base'}\n"
            "BaseFileSystem=erofs\n"
            f"RuntimeDirectory={self.root}\n"
            f"EnabledSysextDirectory={self.root / 'enabled-sysext'}\n"
            f"EnabledConfextDirectory={self.root / 'enabled-confext'}\n"
            "[Build]\nErofsTool=mkfs.erofs\n"
        )
        module.configure(config)
        (module.ROOT / "etc").mkdir(parents=True)
        (self.root / "base/etc").mkdir(parents=True)
        (module.ROOT / "usr/lib").mkdir(parents=True)
        (module.ROOT / "usr/lib/os-release").write_text(
            "ID=opensuse-microos\nVERSION_ID=20260918\nSYSEXT_LEVEL=glibc-2.44\n"
        )
        (module.ROOT / "etc/example.conf").write_text("new=1\n")
        (module.ROOT / "usr/bin/example").parent.mkdir(parents=True)
        (module.ROOT / "usr/bin/example").write_text("new executable\n")
        (self.root / "base/etc/example.conf").write_text("old=1\n")

    def test_diff_and_path_only_staging(self):
        output = io.StringIO()
        with redirect_stdout(output):
            module.command_diff(SimpleNamespace(kind="confext", paths=["/etc/example.conf"]))
        self.assertIn("-old=1", output.getvalue())
        self.assertIn("+new=1", output.getvalue())

        module.command_stage(SimpleNamespace(kind="confext", name="local", paths=["/etc/example.conf"]))
        selection = module.load_selection("local")
        self.assertEqual(selection["paths"], ["/etc/example.conf"])
        self.assertNotIn("new=1", module.selection_file("local").read_text())

    def test_added_binary_symlink_and_unchanged_diffs(self):
        (module.ROOT / "etc/added.conf").write_text("added\n")
        (module.ROOT / "etc/binary").write_bytes(b"new\0data")
        (Path(module.BASE_DIRECTORY) / "etc/binary").write_bytes(b"old\0data")
        (module.ROOT / "etc/link").symlink_to("new-target")
        (Path(module.BASE_DIRECTORY) / "etc/link").symlink_to("old-target")
        (module.ROOT / "etc/same").write_text("same\n")
        (Path(module.BASE_DIRECTORY) / "etc/same").write_text("same\n")
        output = io.StringIO()
        with redirect_stdout(output):
            module.command_diff(SimpleNamespace(
                kind=None, paths=["/etc/added.conf", "/etc/binary", "/etc/link", "/etc/same"]
            ))
        self.assertIn("ADDED /etc/added.conf", output.getvalue())
        self.assertIn("BINARY CHANGED /etc/binary", output.getvalue())
        self.assertIn("old-target", output.getvalue())
        self.assertIn("new-target", output.getvalue())
        self.assertIn("UNCHANGED /etc/same", output.getvalue())

    def test_selection_duplicates_unstage_and_type_filter(self):
        args = SimpleNamespace(kind=None, name="mixed", paths=[
            "/etc/example.conf", "/etc/example.conf", "/usr/bin/example"
        ])
        module.command_stage(args)
        self.assertEqual(len(module.load_selection("mixed")["paths"]), 2)
        output = io.StringIO()
        with redirect_stdout(output):
            module.command_staged(SimpleNamespace(kind="sysext", name="mixed"))
        self.assertEqual(output.getvalue(), "sysext\t/usr/bin/example\n")
        module.command_unstage(SimpleNamespace(kind=None, name="mixed", paths=["/etc/example.conf"]))
        self.assertEqual(module.load_selection("mixed")["paths"], ["/usr/bin/example"])
        self.assertEqual((module.ROOT / "etc/example.conf").read_text(), "new=1\n")

    def test_invalid_paths_and_missing_staged_files(self):
        for path in ("etc/example.conf", "/var/log/example", "/etc/../usr/bin/example",
                     "/etc/extension-release.d/extension-release.bad"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                module.relative_path(path)
        (module.ROOT / "etc/directory").mkdir()
        (module.ROOT / "etc/alias").symlink_to("directory")
        for path in ("/etc/directory", "/etc/alias/file", "/etc/missing"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                module.command_stage(SimpleNamespace(kind=None, name="bad", paths=[path]))
        module.command_stage(SimpleNamespace(kind=None, name="gone", paths=["/etc/example.conf"]))
        (module.ROOT / "etc/example.conf").unlink()
        with self.assertRaises(ValueError):
            module.command_build(SimpleNamespace(kind=None, name="gone", version="1"))
        self.assertFalse((module.store_dir("confext") / "gone_1.raw").exists())

    def test_legacy_selection_migration(self):
        selection_dir = module.STATE / "selections"
        selection_dir.mkdir(parents=True)
        for kind, path in (("confext", "/etc/example.conf"), ("sysext", "/usr/bin/example")):
            (selection_dir / f"{kind}-old.json").write_text(json.dumps({
                "kind": kind, "name": "old", "paths": [path]
            }))
        self.assertEqual(module.load_selection("old")["paths"],
                         ["/etc/example.conf", "/usr/bin/example"])
        self.assertTrue((selection_dir / "old.json").is_file())

    def test_build_uses_content_at_build_time_and_stays_disabled(self):
        module.command_stage(SimpleNamespace(kind="confext", name="local", paths=["/etc/example.conf"]))
        (module.ROOT / "etc/example.conf").write_text("later=2\n")

        def fake_erofs(command, check):
            tree = Path(command[2])
            self.assertEqual((tree / "etc/example.conf").read_text(), "later=2\n")
            self.assertIn("VERSION_ID=20260918", (tree / "etc/extension-release.d/extension-release.local").read_text())
            Path(command[1]).write_bytes(b"test-image")

        with patch.object(module.subprocess, "run", side_effect=fake_erofs):
            module.command_build(SimpleNamespace(kind=None, name="local", version="1"))
        image = module.store_dir("confext") / "local_1.raw"
        self.assertEqual(image.read_bytes(), b"test-image")

    def test_rejects_wrong_tree_and_missing_image(self):
        with self.assertRaises(ValueError):
            module.relative_path("/etc/example.conf", "sysext")
        with self.assertRaises(ValueError):
            module.command_enable(SimpleNamespace(kind="confext", name="local", version="1"))

    def test_packaged_configuration(self):
        packaged = SCRIPT.parents[2] / "etc/extkit.conf"
        module.configure(packaged)
        self.assertEqual(module.STATE, Path("/.state/extkit"))
        self.assertEqual(module.OVERLAY_UPPER, Path("/.overlay-upper/upper"))
        self.assertEqual(module.BASE_DEVICE, Path("/dev/mapper/root"))
        self.assertEqual(module.enabled_dir("confext"), Path("/var/lib/confexts"))

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            module.configure(self.root / "absent.conf")
        bad = self.root / "bad.conf"
        bad.write_text(self.config.read_text().replace(
            f"StateDirectory={self.root / 'state'}", "StateDirectory=relative/state"
        ))
        with self.assertRaises(ValueError):
            module.configure(bad)
        module.configure(self.config)

    def test_copy_preserves_mode_symlink_and_release_level(self):
        script = module.ROOT / "usr/bin/example"
        script.chmod(0o751)
        (module.ROOT / "etc/example-link").symlink_to("example.conf")
        module.command_stage(SimpleNamespace(kind=None, name="metadata", paths=[
            "/usr/bin/example", "/etc/example-link"
        ]))

        def fake_erofs(command, check):
            tree = Path(command[2])
            if Path(command[1]).name == "sysext.raw":
                self.assertEqual(stat.S_IMODE((tree / "usr/bin/example").stat().st_mode), 0o751)
                release = (tree / "usr/lib/extension-release.d/extension-release.metadata").read_text()
                self.assertIn("SYSEXT_LEVEL=glibc-2.44", release)
            else:
                self.assertEqual(os.readlink(tree / "etc/example-link"), "example.conf")
                release = (tree / "etc/extension-release.d/extension-release.metadata").read_text()
                self.assertIn("VERSION_ID=20260918", release)
            Path(command[1]).write_bytes(b"image")

        with patch.object(module.subprocess, "run", side_effect=fake_erofs):
            module.command_build(SimpleNamespace(kind=None, name="metadata", version="1"))

    def test_build_type_filter_existing_version_and_failure_cleanup(self):
        module.command_stage(SimpleNamespace(kind=None, name="mixed", paths=[
            "/etc/example.conf", "/usr/bin/example"
        ]))

        def fake_erofs(command, check):
            Path(command[1]).write_bytes(b"image")

        with patch.object(module.subprocess, "run", side_effect=fake_erofs):
            module.command_build(SimpleNamespace(kind="sysext", name="mixed", version="1"))
        self.assertTrue((module.store_dir("sysext") / "mixed_1.raw").exists())
        self.assertFalse((module.store_dir("confext") / "mixed_1.raw").exists())
        with self.assertRaises(ValueError):
            module.command_build(SimpleNamespace(kind="sysext", name="mixed", version="1"))

        def fail_second(command, check):
            if Path(command[1]).name == "confext.raw":
                raise subprocess.CalledProcessError(1, command)
            Path(command[1]).write_bytes(b"image")

        with patch.object(module.subprocess, "run", side_effect=fail_second):
            with self.assertRaises(subprocess.CalledProcessError):
                module.command_build(SimpleNamespace(kind=None, name="mixed", version="2"))
        self.assertFalse((module.store_dir("sysext") / "mixed_2.raw").exists())
        self.assertFalse((module.store_dir("confext") / "mixed_2.raw").exists())

    def test_enable_disable_and_list(self):
        image = module.store_dir("sysext") / "test_1.raw"
        image.parent.mkdir(parents=True)
        image.write_bytes(b"image")
        enabled = self.root / "enabled"
        with patch.object(module, "enabled_dir", return_value=enabled):
            module.command_enable(SimpleNamespace(kind="sysext", name="test", version="1"))
            self.assertEqual((enabled / "test.raw").resolve(), image)
            output = io.StringIO()
            with redirect_stdout(output):
                module.command_list(SimpleNamespace(kind=None))
            self.assertIn("sysext\ttest\ttest_1.raw\tenabled", output.getvalue())
            module.command_disable(SimpleNamespace(kind="sysext", name="test"))
            self.assertFalse((enabled / "test.raw").exists())

    def test_multiple_versions_filter_and_enable_conflict(self):
        for kind in module.KINDS:
            directory = module.store_dir(kind)
            directory.mkdir(parents=True)
            for version in ("1", "2"):
                (directory / f"test_{version}.raw").write_bytes(b"image")
        module.command_enable(SimpleNamespace(kind=None, name="test", version="1"))
        output = io.StringIO()
        with redirect_stdout(output):
            module.command_list(SimpleNamespace(kind="confext"))
        self.assertIn("confext\ttest\ttest_1.raw\tenabled", output.getvalue())
        self.assertIn("confext\ttest\ttest_2.raw\tdisabled", output.getvalue())
        self.assertNotIn("sysext", output.getvalue())
        with self.assertRaises(ValueError):
            module.command_enable(SimpleNamespace(kind=None, name="test", version="2"))
        self.assertEqual((module.enabled_dir("sysext") / "test.raw").resolve(),
                         module.store_dir("sysext") / "test_1.raw")
        module.command_disable(SimpleNamespace(kind=None, name="test"))
        with self.assertRaises(ValueError):
            module.command_disable(SimpleNamespace(kind=None, name="test"))

    def test_changes_scans_temp_upperdir_and_filters_type(self):
        upper = self.root / "upper"
        for path in ("etc/changed.conf", "usr/bin/tool", "opt/app/file", "var/log/ignored"):
            target = upper / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("changed")
        result = SimpleNamespace(stdout=f"rw,lowerdir=/base,upperdir={upper},workdir=/work\n")
        output = io.StringIO()
        with patch.object(module, "ROOT", Path("/")), patch.object(module.subprocess, "run", return_value=result):
            with redirect_stdout(output):
                module.command_changes(SimpleNamespace(kind=None))
        self.assertIn("/etc/changed.conf", output.getvalue())
        self.assertIn("/usr/bin/tool", output.getvalue())
        self.assertIn("/opt/app/file", output.getvalue())
        self.assertNotIn("/var/log/ignored", output.getvalue())
        output = io.StringIO()
        with patch.object(module, "ROOT", Path("/")), patch.object(module.subprocess, "run", return_value=result):
            with redirect_stdout(output):
                module.command_changes(SimpleNamespace(kind="confext"))
        self.assertEqual(output.getvalue(), "/etc/changed.conf\n")

    def test_changes_uses_exposed_upper_without_scanning_live_root(self):
        upper = self.root / "exposed-upper"
        (upper / "etc").mkdir(parents=True)
        (upper / "etc/changed.conf").write_text("changed")
        output = io.StringIO()
        with patch.object(module, "ROOT", Path("/")), \
             patch.object(module, "OVERLAY_UPPER", upper), \
             patch.object(module.os.path, "ismount", return_value=True), \
             patch.object(module.subprocess, "run", side_effect=AssertionError("findmnt should not run")):
            with redirect_stdout(output):
                module.command_changes(SimpleNamespace(kind=None))
        self.assertEqual(output.getvalue(), "/etc/changed.conf\n")

    def test_initrd_upper_hook_is_present_and_valid_shell(self):
        root = SCRIPT.parents[3]
        hook = root / "mkosi.initrd.extra/usr/libexec/extkit-volatile-root"
        unit = root / "mkosi.initrd.extra/etc/systemd/system/systemd-volatile-root.service.d/10-extkit-upper.conf"
        self.assertTrue(os.access(hook, os.X_OK))
        subprocess.run(["bash", "-n", str(hook)], check=True)
        self.assertIn("ExecStart=/usr/libexec/extkit-volatile-root", unit.read_text())

    def test_cli_with_temp_configuration(self):
        def cli(*arguments):
            return subprocess.run(
                ["python3", str(SCRIPT), "--config", str(self.config), *arguments],
                check=True, text=True, capture_output=True,
            ).stdout

        cli("stage", "cli-test", "/etc/example.conf", "/usr/bin/example")
        self.assertEqual(module.load_selection("cli-test")["paths"],
                         ["/etc/example.conf", "/usr/bin/example"])
        self.assertEqual(cli("staged", "cli-test", "--type", "confext"),
                         "confext\t/etc/example.conf\n")
        cli("unstage", "cli-test", "/usr/bin/example")
        self.assertEqual(cli("staged", "cli-test"), "confext\t/etc/example.conf\n")

    def test_mixed_selection_builds_and_enables_two_images(self):
        module.command_stage(SimpleNamespace(
            kind=None, name="mixed", paths=["/etc/example.conf", "/usr/bin/example"]
        ))
        self.assertEqual(module.load_selection("mixed")["paths"],
                         ["/etc/example.conf", "/usr/bin/example"])

        def fake_erofs(command, check):
            tree = Path(command[2])
            image = Path(command[1])
            if image.name == "confext.raw":
                self.assertTrue((tree / "etc/example.conf").is_file())
                self.assertFalse((tree / "usr/bin/example").exists())
            else:
                self.assertTrue((tree / "usr/bin/example").is_file())
                self.assertFalse((tree / "etc/example.conf").exists())
            image.write_bytes(b"image")

        with patch.object(module.subprocess, "run", side_effect=fake_erofs):
            module.command_build(SimpleNamespace(kind=None, name="mixed", version="1"))
        self.assertTrue((module.store_dir("sysext") / "mixed_1.raw").is_file())
        self.assertTrue((module.store_dir("confext") / "mixed_1.raw").is_file())
        module.command_enable(SimpleNamespace(kind=None, name="mixed", version="1"))
        self.assertTrue((module.enabled_dir("sysext") / "mixed.raw").is_symlink())
        self.assertTrue((module.enabled_dir("confext") / "mixed.raw").is_symlink())
        module.command_disable(SimpleNamespace(kind=None, name="mixed"))
        self.assertFalse((module.enabled_dir("sysext") / "mixed.raw").exists())
        self.assertFalse((module.enabled_dir("confext") / "mixed.raw").exists())

    def test_real_erofs_image_when_tools_are_available(self):
        tools = SCRIPT.parents[3] / "mkosi.tools/usr/sbin"
        mkfs = shutil.which("mkfs.erofs") or str(tools / "mkfs.erofs")
        fsck = shutil.which("fsck.erofs") or str(tools / "fsck.erofs")
        if not Path(mkfs).is_file() or not Path(fsck).is_file():
            self.skipTest("erofs-utils is not available")
        module.EROFS_TOOL = mkfs
        module.command_stage(SimpleNamespace(
            kind=None, name="local", paths=["/etc/example.conf", "/usr/bin/example"]
        ))
        module.command_build(SimpleNamespace(kind=None, name="local", version="1"))
        images = {kind: module.store_dir(kind) / "local_1.raw" for kind in module.KINDS}
        dissect = shutil.which("systemd-dissect")
        for image in images.values():
            subprocess.run([fsck, str(image)], check=True, capture_output=True)
            if dissect:
                subprocess.run([dissect, "--validate", str(image)], check=True, capture_output=True)
        for kind, command in (("confext", "systemd-confext"), ("sysext", "systemd-sysext")):
            tool = shutil.which(command)
            if not tool:
                continue
            installed = module.ROOT / ("var/lib/confexts" if kind == "confext" else "var/lib/extensions")
            installed.mkdir(parents=True)
            shutil.copyfile(images[kind], installed / "local.raw")
            result = subprocess.run(
                [tool, f"--root={module.ROOT}", "list", "--no-pager"],
                check=True, text=True, capture_output=True,
            )
            self.assertIn("local", result.stdout)


if __name__ == "__main__":
    unittest.main()

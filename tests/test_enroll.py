"""Tests for project enrollment. Every test uses a throwaway ENGRAM_HOME."""
import builtins
import json
import os
import subprocess
import time
import unittest
from unittest import mock

from test_engram import Base, PLUGIN
from test_v03 import InProcess

SECRET_VALUE = "hunter2planted"
ENV_MARKER = "ENVFILEMARKER"
KEY_MARKER = "KEYFILEMARKER"


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


class Repo(Base):
    def setUp(self):
        super().setUp()
        self.proj = self.tmp / "target"
        self.proj.mkdir()

    def populate(self, root=None):
        root = root or self.proj
        write(root, "README.md", "# Title\n")                       # 8 chars
        write(root, "package.json", "{}\n")                         # 3
        write(root, "src/main.py", "print(1)\n")                    # 9
        write(root, "src/util.py", "x = 1\n")                       # 6
        write(root, ".env", "PASS=%s %s\n" % (SECRET_VALUE, ENV_MARKER))
        write(root, ".env.local", ENV_MARKER)
        write(root, "certs/server.pem", KEY_MARKER)
        write(root, "certs/app.key", KEY_MARKER)
        write(root, "id_rsa", KEY_MARKER)
        write(root, "credentials.json", KEY_MARKER)
        write(root, "package-lock.json", "x" * 500)
        write(root, "node_modules/lib/index.js", "x" * 500)
        write(root, "venv/lib/site.py", "x" * 500)
        write(root, "dist/bundle.js", "x" * 500)
        (root / "logo.png").write_bytes(b"\x89PNG\x00" * 100)
        (root / "blob.dat").write_bytes(b"abc\x00def" * 100)
        return 26

    def plan(self, path=None, cwd=None):
        p = self.cli("enroll-plan", path or self.proj, "--json", cwd=cwd)
        self.assertEqual(p.returncode, 0, p.err)
        return json.loads(p.out)

    def git(self, *args, root=None):
        subprocess.run(["git", "-C", str(root or self.proj), "-c", "user.name=t", "-c",
                        "user.email=t@example.com"] + list(args), check=True, capture_output=True)


class PlanResolution(Repo):
    def test_folder_identity_and_display_name(self):
        plan = self.plan()
        self.assertEqual(plan["display"], "target")
        self.assertTrue(plan["identity"].endswith("/target"))
        self.assertFalse(plan["known"])
        self.assertFalse(plan["enrolled"])

    def test_git_remote_is_the_identity(self):
        self.git("init", "-q")
        self.git("remote", "add", "origin", "git@github.com:acme/thing.git")
        self.assertEqual(self.plan()["identity"], "github.com/acme/thing")

    def test_subfolder_of_a_repo_resolves_to_the_repo_root(self):
        self.git("init", "-q")
        self.populate()
        plan = self.plan(self.proj / "src")
        self.assertEqual(plan["display"], "target")
        self.assertIn("README.md", plan["tiers"]["low"]["files"])

    def test_missing_path_fails_clearly(self):
        p = self.cli("enroll-plan", self.tmp / "nope")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not a folder", p.err)

    def test_planning_registers_nothing(self):
        self.plan()
        self.assertEqual(self.sql("SELECT COUNT(*) FROM projects WHERE id<>0")[0][0], 0)

    def test_same_named_folders_are_separate_identities(self):
        a, b = self.tmp / "a" / "same", self.tmp / "b" / "same"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        self.assertNotEqual(self.plan(a)["identity"], self.plan(b)["identity"])


class PlanMeasure(Repo):
    def test_counts_only_readable_files(self):
        chars = self.populate()
        plan = self.plan()
        self.assertEqual((plan["files"], plan["chars"]), (4, chars))

    def test_output_never_contains_skipped_paths_or_contents(self):
        self.populate()
        p = self.cli("enroll-plan", self.proj, "--json")
        for text in (SECRET_VALUE, ENV_MARKER, KEY_MARKER, ".env", "server.pem", "id_rsa", "credentials.json"):
            self.assertNotIn(text, p.out + p.err)

    def test_symlinks_are_not_followed(self):
        outside = write(self.tmp, "outside/secret.txt", "x" * 100)
        try:
            os.symlink(str(outside), str(self.proj / "link.txt"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        write(self.proj, "a.txt", "ab")
        self.assertEqual(self.plan()["chars"], 2)

    def test_text_output_labels_estimates(self):
        self.populate()
        out = self.cli("enroll-plan", self.proj).out
        self.assertIn("estimate", out.lower())
        for tier in ("low", "medium", "max"):
            self.assertIn(tier, out)

    def test_json_shape_and_estimates(self):
        self.populate()
        plan = self.plan()
        self.assertEqual(plan["default_tier"], "medium")
        caps = {t: plan["tiers"][t]["max_notes"] for t in ("low", "medium", "max")}
        self.assertEqual(caps, {"low": 8, "medium": 15, "max": 30})
        for t in plan["tiers"].values():
            self.assertGreaterEqual(t["estimated_tokens"], t["chars"] // 4)
            self.assertGreater(t["estimated_tokens"], t["chars"] // 4, "includes fixed overhead")
        self.assertIn("estimate", plan["note"].lower())

    def test_each_tier_reads_at_least_as_much_as_the_one_below(self):
        self.populate()
        tiers = self.plan()["tiers"]
        self.assertLessEqual(set(tiers["low"]["files"]), set(tiers["medium"]["files"]))
        self.assertLessEqual(set(tiers["medium"]["files"]), set(tiers["max"]["files"]))

    def test_low_is_readme_and_manifests_only(self):
        self.populate()
        self.assertCountEqual(self.plan()["tiers"]["low"]["files"], ["README.md", "package.json"])

    def test_medium_adds_entry_points_and_most_changed_files(self):
        self.populate()
        write(self.proj, "src/deep/hot.py", "a\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("commit", "-qm", "one")
        for i in range(3):
            write(self.proj, "src/deep/hot.py", "a%d\n" % i)
            self.git("commit", "-qam", "edit %d" % i)
        tiers = self.plan()["tiers"]
        self.assertIn("src/main.py", tiers["medium"]["files"])
        self.assertIn("src/deep/hot.py", tiers["medium"]["files"])
        self.assertNotIn("src/util.py", tiers["medium"]["files"])
        self.assertIn("src/util.py", tiers["max"]["files"])
        self.assertNotIn("src/deep/hot.py", tiers["low"]["files"])

    def test_read_caps_truncate_and_say_so(self):
        for i in range(4):
            write(self.proj, "mod%d.py" % i, "x" * 450000)
        tier = self.plan()["tiers"]["max"]
        self.assertTrue(tier["truncated"])
        self.assertLessEqual(tier["chars"], 1200000)
        self.assertGreater(tier["passes"], 1)

    def test_empty_folder_is_fine(self):
        plan = self.plan()
        self.assertEqual((plan["files"], plan["chars"]), (0, 0))


class SkippedFilesAreNeverOpened(InProcess, Repo):
    def test_no_skipped_path_reaches_open(self):
        self.populate()
        opened = []
        real_open = builtins.open

        def recording(path, *a, **k):
            opened.append(str(path))
            return real_open(path, *a, **k)
        with mock.patch("builtins.open", recording):
            files, chars, _ = self.m.measure(str(self.proj))
        self.assertEqual(sorted(files), ["README.md", "package.json", "src/main.py", "src/util.py"])
        for path in opened:
            for banned in (".env", ".pem", ".key", "id_rsa", "credentials", "lock", "node_modules",
                           "venv", "dist", "logo.png"):
                self.assertNotIn(banned, os.path.relpath(path, str(self.proj)))

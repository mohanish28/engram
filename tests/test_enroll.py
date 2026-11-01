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


class Enrollment(Repo):
    WORDS = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet")

    def start(self, tier="low", path=None, **kw):
        args = ["enroll-start", path or self.proj, "--tier", tier]
        if kw.get("name"):
            args += ["--name", kw["name"]]
        p = self.cli(*args)
        self.assertEqual(p.returncode, 0, p.err)
        return p

    def locator(self):
        return self.plan()["identity"]

    def save(self, text):
        return self.cli("add", "--project", self.locator(), "--topic", "general", text)

    def rows(self):
        return self.sql("SELECT tier, max_notes, estimated_tokens, notes_saved, status FROM enrollments ORDER BY id")

    def test_start_registers_private_project_and_record(self):
        self.populate()
        self.start("medium")
        self.assertEqual(self.sql("SELECT display, scope FROM projects WHERE id<>0"), [("target", "private")])
        (tier, cap, est, saved, status), = self.rows()
        self.assertEqual((tier, cap, saved, status), ("medium", 15, 0, "active"))
        self.assertEqual(est, self.plan()["tiers"]["medium"]["estimated_tokens"])

    def test_start_uses_a_custom_display_name(self):
        self.start(name="My Project")
        self.assertEqual(self.sql("SELECT display FROM projects WHERE id<>0")[0][0], "My Project")
        self.assertEqual(self.plan()["display"], "My Project")

    def test_start_keeps_an_existing_shared_scope(self):
        self.start()
        self.cli("enroll-finish", self.proj, "--notes-saved", 0)
        self.cli("scope", "set", self.locator(), "shared")
        self.start()
        self.assertEqual(self.sql("SELECT scope FROM projects WHERE id<>0")[0][0], "shared")

    def test_add_refuses_past_the_cap_with_a_clear_message(self):
        self.start("low")
        for w in self.WORDS[:8]:
            self.saved_id(self.save(w))
        p = self.save(self.WORDS[8])
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("refused", p.err)
        self.assertIn("cap", p.err)
        self.assertIn("8", p.err)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memories")[0][0], 8)
        self.assertEqual(self.rows()[0][3], 8)

    def test_caps_for_each_tier(self):
        for tier, cap in (("low", 8), ("medium", 15), ("max", 30)):
            with self.subTest(tier=tier):
                self.start(tier)
                self.assertEqual(self.rows()[-1][1], cap)

    def test_duplicates_and_refused_secrets_do_not_use_up_the_cap(self):
        self.start("low")
        self.saved_id(self.save("alpha"))
        self.assertIn("duplicate", self.save("alpha").out)
        self.assertNotEqual(self.save("ssh password hunter2 on box").returncode, 0)
        self.assertEqual(self.rows()[0][3], 1)

    def test_planted_secret_in_a_readme_is_refused_when_saved(self):
        line = "Deploy with password %s on the box" % SECRET_VALUE
        write(self.proj, "README.md", line + "\n")
        self.start("low")
        p = self.save(line)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("refused", p.err)
        self.assertNotIn(SECRET_VALUE, p.out + p.err)
        self.assertNotIn(SECRET_VALUE.encode(), self.db_path.read_bytes())

    def test_add_from_inside_the_project_is_capped_too(self):
        self.start("low")
        for w in self.WORDS[:8]:
            self.saved_id(self.save(w))
        self.assertNotEqual(self.add(self.WORDS[8], cwd=self.proj).returncode, 0)

    def test_other_projects_and_global_notes_are_not_capped(self):
        self.start("low")
        for w in self.WORDS[:8]:
            self.saved_id(self.save(w))
        self.saved_id(self.add("note in another project"))
        self.saved_id(self.add("--global", "global note"))

    def test_finish_closes_the_run_and_lifts_the_cap(self):
        self.start("low")
        for w in self.WORDS[:8]:
            self.saved_id(self.save(w))
        p = self.cli("enroll-finish", self.proj, "--notes-saved", 8)
        self.assertEqual(p.returncode, 0, p.err)
        self.assertEqual(self.rows()[0][3:], (8, "finished"))
        self.saved_id(self.save(self.WORDS[8]))
        self.assertEqual(self.rows()[0][3], 8, "later notes are not part of the run")

    def test_finish_records_the_cli_count_and_flags_a_wrong_report(self):
        self.start("low")
        self.saved_id(self.save("alpha"))
        p = self.cli("enroll-finish", self.proj, "--notes-saved", 5)
        self.assertEqual(self.rows()[0][3], 1)
        self.assertIn("counted 1", p.out)

    def test_finish_without_an_active_run_fails(self):
        p = self.cli("enroll-finish", self.proj, "--notes-saved", 0)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("no active enrollment", p.err)

    def test_restarting_abandons_the_previous_run(self):
        self.start("low")
        self.start("medium")
        self.assertEqual([r[4] for r in self.rows()], ["abandoned", "active"])

    def test_a_stale_run_stops_capping_after_a_day(self):
        self.start("low")
        for w in self.WORDS[:8]:
            self.saved_id(self.save(w))
        self.sql("UPDATE enrollments SET started=?", time.time() - 2 * 86400)
        self.saved_id(self.save(self.WORDS[8]))
        self.assertEqual(self.rows()[0][4], "abandoned")

    def test_record_contains_no_note_text(self):
        self.start("low")
        self.saved_id(self.save("zebraprivatemarker decision"))
        self.cli("enroll-finish", self.proj, "--notes-saved", 1)
        cols = [r[1] for r in self.sql("PRAGMA table_info(enrollments)")]
        self.assertCountEqual(cols, ["id", "project_id", "tier", "max_notes", "estimated_tokens",
                                     "notes_saved", "started", "finished", "status"])
        for row in self.sql("SELECT * FROM enrollments"):
            self.assertNotIn("zebraprivatemarker", " ".join(str(x) for x in row))

    def test_plan_reports_already_enrolled_and_note_count(self):
        self.start("low")
        self.saved_id(self.save("alpha"))
        self.saved_id(self.save("bravo"))
        self.cli("enroll-finish", self.proj, "--notes-saved", 2)
        plan = self.plan()
        self.assertEqual((plan["known"], plan["enrolled"], plan["note_count"]), (True, True, 2))
        self.assertIn("already enrolled", self.cli("enroll-plan", self.proj).out)

    def test_known_project_that_was_never_enrolled(self):
        self.saved_id(self.add("alpha", cwd=self.proj))
        plan = self.plan()
        self.assertEqual((plan["known"], plan["enrolled"], plan["note_count"]), (True, False, 1))

    def test_stats_shows_tier_estimate_and_notes_saved_only(self):
        self.populate()
        self.start("low")
        est = self.rows()[0][2]
        self.saved_id(self.save("alpha"))
        self.cli("enroll-finish", self.proj, "--notes-saved", 1)
        out = self.cli("stats").out
        self.assertRegex(out, r"target\s+low\s+%d\s+1\s+finished" % est)
        self.assertIn("estimated", out)
        self.assertNotIn("actual", out)

    def test_same_named_folders_get_separate_projects_and_runs(self):
        a, b = self.tmp / "a" / "same", self.tmp / "b" / "same"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        self.start("low", path=a)
        self.start("max", path=b)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM projects WHERE display='same'")[0][0], 2)
        self.assertEqual([r[4] for r in self.rows()], ["active", "active"])

"""Tests for the engram 0.3 feature set. Every test uses a throwaway ENGRAM_HOME."""
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import unittest
from unittest import mock

from test_engram import Base, CLI, NOTE_LINE, PLUGIN, SH, LAUNCHER

DAY = 86400
GH = "ghp_abcdefghijklmnopqrstuvwxyz012345"
PG = "postgres://admin:hunter2pw@db.example.com/app"
BEARER = "Bearer abcd1234efgh5678ijkl9012"
PROSE = "the password is hunter3pw"
ENTROPY = "Zx9Qm2Lp7Vb4Nc8Rt1Yw6Hs3"
SECRETS = {GH: "ghp_abcdef", PG: "hunter2pw", BEARER: "abcd1234", PROSE: "hunter3pw", ENTROPY: ENTROPY}
MARKERS = tuple(SECRETS.values())


def load_module(home):
    os.environ["ENGRAM_HOME"] = str(home)
    spec = importlib.util.spec_from_file_location("engram_under_test", str(CLI))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class InProcess(Base):
    def setUp(self):
        super().setUp()
        saved = os.environ.get("ENGRAM_HOME")
        self.addCleanup(lambda: os.environ.pop("ENGRAM_HOME", None) if saved is None
                        else os.environ.__setitem__("ENGRAM_HOME", saved))
        self.m = load_module(self.home)


class Scan(InProcess):
    def test_scan_finds_each_known_pattern(self):
        for text in SECRETS:
            with self.subTest(text=text[:10]):
                self.assertTrue(self.m.scan("note " + text + " end"))

    def test_scan_reports_kind_and_span(self):
        text = "use %s now" % GH
        f = self.m.scan(text)[0]
        self.assertEqual(f.kind, "github-token")
        self.assertEqual(text[f.start:f.end], GH)

    def test_entropy_ignores_git_shas_and_uuids(self):
        for tok in ("3f786850e387550fdab836ed7e6dc881de23001b",
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "123e4567-e89b-12d3-a456-426614174000"):
            with self.subTest(tok=tok):
                self.assertEqual(self.m.scan("see %s here" % tok), [])

    def test_entropy_ignores_words_paths_and_identifiers(self):
        for text in ("internationalization and characterization",
                     "plugins/engram/scripts/v2/engram_module_v3_helper.py",
                     "test_ten_year_old_importance_1_note_with_one_hit",
                     "aaaaaaaaaa1111111111aaaaaaaaaa"):
            with self.subTest(text=text):
                self.assertEqual(self.m.scan(text), [])

    def test_entropy_needs_letters_and_digits_and_20_chars(self):
        self.assertEqual(self.m.scan("Zx9Qm2Lp7Vb4Nc8Rt1Y"), [])  # 19 chars
        self.assertEqual(self.m.scan("ZxQmLpVbNcRtYwHsKjGfDa"), [])  # no digit
        self.assertTrue(self.m.scan("Zx9Qm2Lp7Vb4Nc8Rt1Yw"))  # 20 chars

    def test_redact_replaces_all_findings(self):
        out = self.m.redact(" and ".join(SECRETS))
        for marker in MARKERS:
            self.assertNotIn(marker, out)

    def test_secure_paths_sets_posix_modes(self):
        self.home.mkdir()
        with mock.patch.object(self.m.os, "chmod") as chmod:
            self.m.secure_paths(posix=True)
        modes = {os.path.basename(str(c.args[0])): c.args[1] for c in chmod.call_args_list}
        self.assertEqual(modes[self.home.name], 0o700)
        self.assertEqual(modes["memory.db"], 0o600)

    def test_secure_paths_is_best_effort_when_chmod_fails(self):
        with mock.patch.object(self.m.os, "chmod", side_effect=PermissionError):
            self.m.secure_paths(posix=True)


class Refusal(Base):
    def rows(self):
        return self.sql("SELECT COUNT(*) FROM memories")[0][0] if self.db_path.exists() else 0

    def assertRefused(self, proc):
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refused", proc.err)
        for marker in MARKERS:
            self.assertNotIn(marker, proc.out + proc.err)

    def test_add_refuses_each_secret_and_stores_nothing(self):
        for text in SECRETS:
            with self.subTest(text=text[:10]):
                self.assertRefused(self.add("note %s" % text))
                self.assertEqual(self.rows(), 0)

    def test_edit_refuses_and_keeps_old_text(self):
        i = self.saved_id(self.add("safe text"))
        self.assertRefused(self.cli("edit", i, "--text", PROSE))
        self.assertEqual(self.sql("SELECT text FROM memories WHERE id=?", i)[0][0], "safe text")

    def test_supersede_refuses_and_leaves_note_active(self):
        i = self.saved_id(self.add("safe text"))
        self.assertRefused(self.cli("supersede", i, GH))
        self.assertEqual(self.status(i), "active")
        self.assertEqual(self.rows(), 1)

    def test_merge_refuses_and_leaves_notes_active(self):
        a = self.saved_id(self.add("alpha text"))
        b = self.saved_id(self.add("bravo text"))
        self.assertRefused(self.cli("merge", a, b, "--text", PG))
        self.assertEqual((self.status(a), self.status(b)), ("active", "active"))

    def test_session_log_capture_redacts_instead_of_refusing(self):
        t = self.tmp / "t.jsonl"
        lines = [{"message": {"role": "user", "content": "deploy with %s please" % GH}},
                 {"message": {"role": "assistant", "content": [
                     {"type": "tool_use", "name": "Bash", "input": {}}] * 3}}]
        t.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
        self.hook("hook-capture", transcript_path=str(t), session_id="abcdefgh")
        text = self.sql("SELECT text FROM memories WHERE kind='episode'")[0][0]
        self.assertIn("deploy with [REDACTED]", text)
        self.assertNotIn(b"ghp_abcdef", self.db_path.read_bytes())


class EmitGate(Base):
    def plant(self, text):
        """A row that bypassed the save path, like an old or hand-edited one."""
        i = self.saved_id(self.add("alpha bravo canary note %d" % time.time_ns()))
        self.sql("UPDATE memories SET text=? WHERE id=?", "alpha bravo canary " + text, i)
        return i

    def outputs(self):
        return {
            "hook-start": self.hook("hook-start").out,
            "hook-prompt": self.hook("hook-prompt", prompt="alpha bravo canary").out,
            "search": self.cli("search", "alpha bravo canary").out,
            "review": self.cli("review").out,
            "stats": self.cli("stats").out,
        }

    def test_planted_secrets_never_reach_any_output(self):
        for text in SECRETS:
            self.plant(text)
        for name, out in self.outputs().items():
            for marker in MARKERS:
                with self.subTest(output=name, marker=marker):
                    self.assertNotIn(marker, out)

    def test_outputs_actually_show_the_planted_row(self):
        self.plant(GH)
        outs = self.outputs()
        for name in ("hook-start", "hook-prompt", "search", "review"):
            self.assertIn("[REDACTED]", outs[name], name)

    def test_print_is_only_called_inside_emit(self):
        src = CLI.read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"(?<![\w.])print\(", src)), 1)
        self.assertRegex(src, r"def emit\(text\):(?:\n .*)*\n\s+print\(")


class PurgeCompleteness(Base):
    def test_purge_leaves_nothing_in_any_table(self):
        i = self.saved_id(self.add("alpha zebrapurgemarker note"))
        self.cli("purge", i)
        for (t,) in self.sql("SELECT name FROM sqlite_master WHERE type='table'"):
            if "note_id" in [r[1] for r in self.sql("PRAGMA table_info(%s)" % t)]:
                self.assertEqual(self.sql("SELECT COUNT(*) FROM %s WHERE note_id=?" % t, i)[0][0], 0, t)
        self.assertNotIn(b"zebrapurgemarker", self.db_path.read_bytes())


@unittest.skipUnless(os.name == "posix", "POSIX permissions")
class RealPermissions(Base):
    def test_modes_on_disk(self):
        self.add("alpha")
        self.assertEqual(os.stat(self.home).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.db_path).st_mode & 0o777, 0o600)

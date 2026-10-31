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


class Tiers(Base):
    def old_note(self, *args):
        i = self.saved_id(self.add(*args))
        self.age(i, 40 * DAY)
        self.cli("prune")
        return i

    def tier(self, i):
        return self.sql("SELECT tier FROM memories WHERE id=?", i)[0][0]

    def test_recent_note_is_hot_and_31_day_old_note_is_cold(self):
        hot = self.saved_id(self.add("alpha recent"))
        self.age(hot, 29 * DAY)
        cold = self.old_note("alpha old")
        self.assertEqual((self.tier(hot), self.tier(cold)), ("hot", "cold"))

    def test_decisions_and_failures_at_importance_4_stay_hot(self):
        for kind in ("decision", "failure"):
            with self.subTest(kind=kind):
                i = self.old_note("--kind", kind, "--importance", "4", "%s alpha" % kind)
                self.assertEqual(self.tier(i), "hot")

    def test_decision_below_importance_4_goes_cold(self):
        self.assertEqual(self.tier(self.old_note("--kind", "decision", "alpha choice")), "cold")

    def test_demotion_deletes_nothing(self):
        i = self.old_note("alpha old")
        self.assertEqual(self.status(i), "active")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memories")[0][0], 1)

    def test_hot_index_contains_only_hot_active_notes(self):
        cold = self.old_note("alpha cold")
        hot = self.saved_id(self.add("bravo hot"))
        gone = self.saved_id(self.add("charlie gone"))
        self.cli("forget", gone)
        self.assertEqual([r[0] for r in self.sql("SELECT rowid FROM hot_fts")], [hot])

    def test_hot_search_ignores_cold_notes(self):
        cold = self.old_note("zebra cold marker")
        hot = self.saved_id(self.add("zebra hot marker"))
        old = os.environ.get("ENGRAM_HOME")
        m = load_module(self.home)
        self.addCleanup(lambda: os.environ.pop("ENGRAM_HOME") if old is None
                        else os.environ.__setitem__("ENGRAM_HOME", old))
        c = m.db()
        self.addCleanup(c.close)
        self.assertEqual([r["id"] for r in m.matches(c, "zebra", hot=True)], [hot])
        self.assertCountEqual([r["id"] for r in m.matches(c, "zebra")], [cold, hot])

    def test_session_start_ignores_cold_notes(self):
        self.old_note("zebra cold marker")
        self.assertNotIn("zebra", self.hook("hook-start").out)

    def test_explicit_search_finds_cold_notes(self):
        i = self.old_note("zebra cold marker")
        self.assertIn("#%d" % i, self.cli("search", "zebra").out)

    def test_clear_search_hit_promotes_a_cold_note(self):
        i = self.old_note("zebra cold marker")
        self.cli("search", "zebra")
        self.assertEqual(self.tier(i), "hot")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM hot_fts WHERE rowid=?", i)[0][0], 1)

    def test_weak_search_hit_does_not_refresh_last_use(self):
        i = self.old_note("zebra cold marker")
        before = self.sql("SELECT last_access, access_count FROM memories WHERE id=?", i)[0]
        out = self.cli("search", "zebra unrelated words").out
        self.assertIn("#%d" % i, out, "still listed")
        self.assertEqual(self.sql("SELECT last_access, access_count FROM memories WHERE id=?", i)[0], before)
        self.assertEqual(self.tier(i), "cold")

    def test_session_start_query_uses_the_hot_only_index(self):
        self.add("alpha")
        old = os.environ.get("ENGRAM_HOME")
        m = load_module(self.home)
        self.addCleanup(lambda: os.environ.pop("ENGRAM_HOME") if old is None
                        else os.environ.__setitem__("ENGRAM_HOME", old))
        plan = self.sql("EXPLAIN QUERY PLAN " + m.HOT_NOTES, "x", "y")
        self.assertIn("mem_hot", " ".join(str(r) for r in plan))


class Rollups(Base):
    def episode(self, text, days_ago, cwd=None):
        i = self.saved_id(self.add("placeholder %d" % time.time_ns(), cwd=cwd))
        when = time.time() - days_ago * DAY
        self.sql("UPDATE memories SET kind='episode', text=?, created=?, last_access=? WHERE id=?",
                 text, when, when, i)
        return i

    def session(self, sid, prompt, days_ago, files="", cwd=None):
        edited = "; edited 1 files (%s)" % files if files else ""
        return self.episode('[session %s] 2026-01-01: started with "%s"; 5 tool calls%s'
                            % (sid, prompt, edited), days_ago, cwd)

    def rollup_rows(self):
        return [r[0] for r in self.sql("SELECT text FROM memories WHERE kind='rollup' ORDER BY id")]

    def test_old_episodes_roll_up_and_are_deleted(self):
        a = self.session("aaaa", "first task", 60, "a.py")
        b = self.session("bbbb", "second task", 60, "b.py")
        self.cli("prune")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memories WHERE id IN (?,?)", a, b)[0][0], 0)
        rows = self.rollup_rows()
        self.assertEqual(len(rows), 1)
        self.assertRegex(rows[0], r"^Week of \d{4}-\d{2}-\d{2}, project proj: 2 sessions")
        for part in ("a.py", "b.py", "first task", "second task"):
            self.assertIn(part, rows[0])

    def test_recent_episodes_are_left_alone(self):
        i = self.session("aaaa", "recent task", 5)
        self.cli("prune")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memories WHERE id=?", i)[0][0], 1)
        self.assertEqual(self.rollup_rows(), [])

    def test_summary_is_deterministic(self):
        texts = []
        for _ in range(2):
            self.sql("DELETE FROM memories WHERE kind='rollup'") if self.db_path.exists() else None
            self.session("aaaa", "one", 60, "z.py")
            self.session("bbbb", "two", 60, "a.py")
            self.cli("prune")
            texts.append(self.rollup_rows()[0])
        self.assertEqual(texts[0], texts[1])

    def test_projects_get_separate_rollups(self):
        other = self.tmp / "other"
        other.mkdir()
        self.session("aaaa", "here", 60)
        self.session("bbbb", "there", 60, cwd=other)
        self.cli("prune")
        self.assertEqual(len(self.rollup_rows()), 2)

    def test_later_episode_merges_into_the_existing_week(self):
        self.session("aaaa", "one", 60)
        self.cli("prune")
        self.session("bbbb", "two", 60)
        self.cli("prune")
        rows = self.rollup_rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("2 sessions", rows[0])

    def test_rollups_are_cold_and_not_injected(self):
        self.session("aaaa", "zebra task", 60)
        self.cli("prune")
        self.assertEqual(self.sql("SELECT tier FROM memories WHERE kind='rollup'")[0][0], "cold")
        self.assertEqual(self.hook("hook-prompt", prompt="zebra task").out, "")
        self.assertIn("zebra", self.cli("search", "zebra").out)

    def test_session_end_hook_rolls_up_too(self):
        self.session("aaaa", "one", 60)
        self.hook("hook-capture")
        self.assertEqual(len(self.rollup_rows()), 1)


class Topics(Base):
    def topic(self, i):
        return self.sql("SELECT topic FROM memories WHERE id=?", i)[0][0]

    def test_near_duplicate_tag_gets_a_suggestion_and_still_saves(self):
        self.add("--topic", "database", "alpha note")
        p = self.add("--topic", "db", "bravo note")
        i = self.saved_id(p)
        self.assertEqual(self.topic(i), "db")
        self.assertRegex(p.out, r"TOPIC: 'db' is close to existing 'database'")

    def test_similar_spelling_gets_a_suggestion(self):
        self.add("--topic", "deployment", "alpha note")
        self.assertIn("TOPIC", self.add("--topic", "deployments", "bravo note").out)

    def test_exact_and_unrelated_tags_get_no_suggestion(self):
        self.add("--topic", "database", "alpha note")
        self.assertNotIn("TOPIC", self.add("--topic", "database", "bravo note").out)
        self.assertNotIn("TOPIC", self.add("--topic", "frontend", "charlie note").out)

    def test_tag_is_normalized(self):
        self.assertEqual(self.topic(self.saved_id(self.add("--topic", "Rate Limits!", "alpha"))), "rate-limits")

    def test_untagged_note_adopts_existing_topic_named_in_its_text(self):
        self.add("--topic", "postgres", "alpha note")
        self.assertEqual(self.topic(self.saved_id(self.add("Postgres needs tuning"))), "postgres")

    def test_untagged_note_defaults_to_general(self):
        self.assertEqual(self.topic(self.saved_id(self.add("alpha note"))), "general")

    def test_supersede_and_merge_keep_the_topic(self):
        a = self.saved_id(self.add("--topic", "database", "alpha one"))
        b = self.saved_id(self.add("--topic", "database", "bravo two"))
        out = self.cli("supersede", a, "charlie three").out
        c = int(re.search(r"superseded by #(\d+)", out).group(1))
        self.assertEqual(self.topic(c), "database")
        out = self.cli("merge", b, c, "--text", "delta four").out
        self.assertEqual(self.topic(int(re.search(r"into #(\d+)", out).group(1))), "database")


class Cards(Base):
    def card(self, i):
        rows = self.sql("SELECT key, project_id, topic, keywords, gist, tier, scope "
                        "FROM cards WHERE note_id=?", i)
        return rows[0] if rows else None

    def fts_count(self, i):
        return self.sql("SELECT COUNT(*) FROM cards_fts WHERE rowid=?", i)[0][0]

    def test_key_is_project_and_note_id(self):
        i = self.saved_id(self.add("alpha note"))
        pid = self.sql("SELECT project_id FROM memories WHERE id=?", i)[0][0]
        self.assertEqual(self.card(i)[0], "%d:%d" % (pid, i))

    def test_key_is_stable_when_text_changes(self):
        i = self.saved_id(self.add("alpha note"))
        key = self.card(i)[0]
        self.cli("edit", i, "--text", "completely different words")
        self.assertEqual(self.card(i)[0], key)

    def test_ids_are_not_reused_after_purge(self):
        i = self.saved_id(self.add("alpha note"))
        self.cli("purge", i)
        self.assertGreater(self.saved_id(self.add("bravo note")), i)

    def test_card_has_keywords_gist_topic_tier_and_private_scope(self):
        i = self.saved_id(self.add("--topic", "database", "Chose Postgres for multi-user. Details follow here."))
        _, _, topic, keywords, gist, tier, scope = self.card(i)
        self.assertEqual((topic, tier, scope), ("database", "hot", "private"))
        self.assertIn("postgres", keywords)
        self.assertEqual(gist, "Chose Postgres for multi-user.")

    def test_edit_updates_card(self):
        i = self.saved_id(self.add("alpha note"))
        self.cli("edit", i, "--text", "bravo words", "--topic", "newtopic")
        self.assertEqual(self.card(i)[2], "newtopic")
        self.assertEqual(self.card(i)[4], "bravo words")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM cards_fts WHERE cards_fts MATCH 'bravo'")[0][0], 1)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM cards_fts WHERE cards_fts MATCH 'alpha'")[0][0], 0)

    def test_supersede_swaps_cards(self):
        a = self.saved_id(self.add("alpha note"))
        out = self.cli("supersede", a, "bravo note").out
        b = int(re.search(r"superseded by #(\d+)", out).group(1))
        self.assertIsNone(self.card(a))
        self.assertEqual(self.fts_count(a), 0)
        self.assertEqual(self.card(b)[4], "bravo note")

    def test_merge_swaps_cards(self):
        a = self.saved_id(self.add("alpha note"))
        b = self.saved_id(self.add("bravo words"))
        out = self.cli("merge", a, b, "--text", "charlie text").out
        c = int(re.search(r"into #(\d+)", out).group(1))
        self.assertIsNone(self.card(a))
        self.assertIsNone(self.card(b))
        self.assertEqual(self.card(c)[4], "charlie text")

    def test_demote_and_promote_update_card_tier(self):
        i = self.saved_id(self.add("zebra note"))
        self.age(i, 40 * DAY)
        self.cli("prune")
        self.assertEqual(self.card(i)[5], "cold")
        self.cli("search", "zebra")
        self.assertEqual(self.card(i)[5], "hot")

    def test_forget_removes_card(self):
        i = self.saved_id(self.add("alpha note"))
        self.cli("forget", i)
        self.assertIsNone(self.card(i))
        self.assertEqual(self.fts_count(i), 0)

    def test_purge_removes_card_and_its_index_entry(self):
        i = self.saved_id(self.add("zebrapurgemarker note"))
        self.cli("purge", i)
        self.assertIsNone(self.card(i))
        self.assertEqual(self.fts_count(i), 0)
        self.assertNotIn(b"zebrapurgemarker", self.db_path.read_bytes())

    def test_episodes_get_no_card(self):
        t = self.tmp / "t.jsonl"
        t.write_text("\n".join(json.dumps(x) for x in [
            {"message": {"role": "user", "content": "work"}},
            {"message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Bash", "input": {}}] * 3}}]), encoding="utf-8")
        self.hook("hook-capture", transcript_path=str(t), session_id="abcdefgh")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memories WHERE kind='episode'")[0][0], 1)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM cards")[0][0], 0)

    def test_planted_secrets_never_reach_a_card(self):
        i = self.saved_id(self.add("alpha note"))
        for text in SECRETS:
            with self.subTest(text=text[:10]):
                self.sql("UPDATE memories SET text=? WHERE id=?", "planted " + text, i)
                self.cli("edit", i, "--topic", "retagged")
                row = " ".join(str(x) for x in self.card(i))
                fts = " ".join(str(x) for r in self.sql("SELECT topic, keywords, gist FROM cards_fts") for x in r)
                for marker in MARKERS:
                    self.assertNotIn(marker, row)
                    self.assertNotIn(marker, fts)


class SessionStartIndex(Base):
    def test_topic_index_with_counts(self):
        self.add("--topic", "database", "alpha note")
        self.add("--topic", "database", "bravo words")
        self.add("--topic", "frontend", "charlie text")
        self.assertIn("[engram] Topics: database (2), frontend (1)", self.hook("hook-start").out)

    def test_cold_notes_are_not_counted(self):
        i = self.saved_id(self.add("--topic", "database", "alpha note"))
        self.age(i, 40 * DAY)
        self.assertNotIn("database", self.hook("hook-start").out)

    def test_at_most_three_notes(self):
        for w in ("alpha", "bravo", "charlie", "delta"):
            self.add(w)
        lines = self.hook("hook-start").out.splitlines()
        self.assertEqual(len([x for x in lines if NOTE_LINE.match(x)]), 3)


class Scopes(Base):
    def setUp(self):
        super().setUp()
        self.other = self.tmp / "other"
        self.other.mkdir()

    def test_new_project_is_private_and_global_is_shared(self):
        self.add("alpha note")
        scopes = dict(self.sql("SELECT display, scope FROM projects"))
        self.assertEqual(scopes["proj"], "private")
        self.assertEqual(scopes["*"], "shared")

    def test_scope_set_updates_project_and_cards(self):
        i = self.saved_id(self.add("alpha note"))
        self.assertEqual(self.cli("scope", "set", "proj", "shared").returncode, 0)
        self.assertEqual(self.sql("SELECT scope FROM projects WHERE display='proj'")[0][0], "shared")
        self.assertEqual(self.sql("SELECT scope FROM cards WHERE note_id=?", i)[0][0], "shared")
        self.cli("scope", "set", "proj", "private")
        self.assertEqual(self.sql("SELECT scope FROM cards WHERE note_id=?", i)[0][0], "private")

    def test_scope_set_rejects_unknown_project_and_global(self):
        self.add("alpha note")
        self.assertNotEqual(self.cli("scope", "set", "nope", "shared").returncode, 0)
        self.assertNotEqual(self.cli("scope", "set", "*", "private").returncode, 0)

    def test_scope_set_rejects_ambiguous_name(self):
        a, b = self.tmp / "a" / "same", self.tmp / "b" / "same"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        self.add("alpha note", cwd=a)
        self.add("bravo note", cwd=b)
        self.assertNotEqual(self.cli("scope", "set", "same", "shared").returncode, 0)

    def test_scope_list_shows_projects(self):
        self.add("alpha note")
        self.assertRegex(self.cli("scope", "list").out, r"proj\s+private")

    def test_search_stays_in_current_project_by_default(self):
        self.add("zebra elsewhere note", cwd=self.other)
        self.cli("scope", "set", "other", "shared")
        self.assertEqual(self.cli("search", "zebra").out, "no matches")

    def test_private_project_is_searchable_when_named(self):
        self.add("zebra elsewhere note", cwd=self.other)
        self.assertIn("zebra", self.cli("search", "--project", "other", "zebra").out)

    def test_everywhere_finds_shared_but_not_private(self):
        self.add("zebra private note", cwd=self.other)
        third = self.tmp / "third"
        third.mkdir()
        self.add("zebra shared note", cwd=third)
        self.cli("scope", "set", "third", "shared")
        self.add("zebra local note")
        self.add("--global", "zebra global note")
        out = self.cli("search", "--everywhere", "zebra").out
        for word in ("shared", "local", "global"):
            self.assertIn("zebra %s" % word, out)
        self.assertNotIn("private", out)


class Cascade(Base):
    PROMPT = "zebra migration rollout"

    def shared_project(self, text, name="other"):
        d = self.tmp / name
        d.mkdir(exist_ok=True)
        i = self.saved_id(self.add(text, cwd=d))
        self.cli("scope", "set", name, "shared")
        return i

    def prompt(self, text=None):
        return self.hook("hook-prompt", prompt=text or self.PROMPT).out

    def test_escalates_to_shared_project_labelled_with_its_source(self):
        i = self.shared_project("zebra migration uses blue green")
        lines = self.prompt().splitlines()
        note = [x for x in lines if x.startswith("#%d " % i)]
        self.assertEqual(len(note), 1, lines)
        self.assertIn("|other|", note[0])

    def test_private_project_is_never_reached(self):
        d = self.tmp / "other"
        d.mkdir()
        self.add("zebra migration uses blue green", cwd=d)
        self.assertEqual(self.prompt(), "")

    def test_two_hot_matches_do_not_escalate(self):
        self.add("zebra migration first local")
        self.add("zebra rollout second local")
        self.shared_project("zebra migration rollout shared elsewhere")
        out = self.prompt()
        self.assertEqual(len([x for x in out.splitlines() if NOTE_LINE.match(x)]), 2)
        self.assertNotIn("elsewhere", out)

    def test_one_hot_match_escalates_and_total_stays_at_three(self):
        self.add("zebra migration first local")
        for w in ("aa", "bb", "cc", "dd"):
            self.shared_project("zebra migration rollout shared %s" % w)
        notes = [x for x in self.prompt().splitlines() if NOTE_LINE.match(x)]
        self.assertEqual(len(notes), 3)
        self.assertIn("first local", notes[0])

    def test_own_cold_note_is_reached_before_other_projects(self):
        i = self.saved_id(self.add("zebra migration old local decision"))
        self.age(i, 40 * DAY)
        self.cli("prune")
        self.shared_project("zebra migration rollout shared elsewhere")
        lines = [x for x in self.prompt().splitlines() if NOTE_LINE.match(x)]
        self.assertTrue(lines[0].startswith("#%d " % i), lines)

    def test_one_shared_word_is_not_enough_for_another_project(self):
        self.shared_project("zebra lives in the zoo")
        self.assertEqual(self.prompt("zebra"), "")

    def test_router_does_not_count_as_use(self):
        i = self.shared_project("zebra migration uses blue green")
        self.prompt()
        self.assertEqual(self.sql("SELECT access_count FROM memories WHERE id=?", i)[0][0], 0)

    def test_router_skips_forgotten_notes(self):
        i = self.shared_project("zebra migration uses blue green")
        self.cli("forget", i)
        self.assertEqual(self.prompt(), "")

    def test_canaries_do_not_reach_router_output(self):
        i = self.shared_project("zebra migration note placeholder")
        self.sql("UPDATE memories SET text=? WHERE id=?", "zebra migration " + GH, i)
        out = self.prompt()
        self.assertIn("#%d" % i, out)
        self.assertNotIn("ghp_abcdef", out)


class Vectors(Base):
    def setUp(self):
        super().setUp()
        self.trace = self.tmp / "embedded.txt"
        self.env.update(ENGRAM_EMBEDDER="stub", ENGRAM_EMBED_TRACE=str(self.trace))

    def traced(self):
        return self.trace.read_text(encoding="utf-8") if self.trace.exists() else ""

    def vectors(self):
        return self.sql("SELECT COUNT(*) FROM card_vectors")[0][0]

    def test_index_vectors_embeds_cards_only(self):
        self.add("--topic", "storage", "Databank backups run nightly. " + "Extra detail sentence here.")
        self.assertIn("indexed 1", self.cli("index-vectors").out)
        self.assertEqual(self.vectors(), 1)
        self.assertIn("Databank backups run nightly.", self.traced())
        self.assertNotIn("Extra detail sentence", self.traced().split("|", 1)[1] if "|" in self.traced() else "")

    def test_saving_does_not_embed(self):
        self.add("alpha note")
        self.assertEqual(self.traced(), "")

    def test_index_vectors_skips_already_indexed_cards(self):
        self.add("alpha note")
        self.cli("index-vectors")
        self.assertIn("indexed 0", self.cli("index-vectors").out)

    def test_search_merges_and_labels_each_path(self):
        vec = self.saved_id(self.add("databank backups nightly"))
        both = self.saved_id(self.add("database backups nightly"))
        self.cli("index-vectors")
        lines = self.cli("search", "database").out.splitlines()
        by_id = {int(re.match(r"#(\d+)", x).group(1)): x for x in lines}
        self.assertIn("(via keyword+vector)", by_id[both])
        self.assertIn("(via vector)", by_id[vec])

    def test_keyword_only_hit_is_labelled_when_vectors_are_active(self):
        i = self.saved_id(self.add("zebra"))
        self.saved_id(self.add("other words"))
        self.cli("index-vectors")
        self.sql("DELETE FROM card_vectors WHERE note_id=?", i)
        self.assertIn("(via keyword)", self.cli("search", "zebra").out)

    def test_hooks_never_embed(self):
        self.add("zebra migration rollout note")
        self.cli("index-vectors")
        self.trace.unlink()
        self.hook("hook-start")
        self.assertIn("zebra", self.hook("hook-prompt", prompt="zebra migration").out)
        self.hook("hook-capture")
        self.assertEqual(self.traced(), "")

    def test_vector_results_respect_scopes(self):
        other = self.tmp / "other"
        other.mkdir()
        self.add("databank private note", cwd=other)
        self.cli("index-vectors")
        self.cli("index-vectors")
        self.assertNotIn("databank", self.cli("search", "--everywhere", "database").out)

    def test_edit_invalidates_vector(self):
        i = self.saved_id(self.add("alpha note"))
        self.cli("index-vectors")
        self.cli("edit", i, "--text", "bravo words")
        self.assertEqual(self.vectors(), 0)
        self.assertIn("indexed 1", self.cli("index-vectors").out)

    def test_purge_removes_vector(self):
        i = self.saved_id(self.add("alpha note"))
        self.cli("index-vectors")
        self.cli("purge", i)
        self.assertEqual(self.vectors(), 0)

    def test_forget_removes_vector(self):
        i = self.saved_id(self.add("alpha note"))
        self.cli("index-vectors")
        self.cli("forget", i)
        self.assertEqual(self.vectors(), 0)

    def test_canaries_never_reach_the_embedder_or_vector_table(self):
        i = self.saved_id(self.add("alpha note"))
        for text in SECRETS:
            with self.subTest(text=text[:10]):
                self.sql("UPDATE memories SET text=? WHERE id=?", "planted " + text, i)
                self.cli("edit", i, "--topic", "retagged")
                self.cli("index-vectors")
                for marker in MARKERS:
                    self.assertNotIn(marker, self.traced())
        cols = [r[1] for r in self.sql("PRAGMA table_info(card_vectors)")]
        self.assertEqual(sorted(cols), ["model", "note_id", "vec"])


class NoVectorExtras(Base):
    def setUp(self):
        super().setUp()
        self.env["ENGRAM_EMBEDDER"] = "off"

    def test_index_vectors_explains_and_succeeds(self):
        self.add("alpha note")
        p = self.cli("index-vectors")
        self.assertEqual(p.returncode, 0)
        self.assertIn("keyword search only", p.out)

    def test_search_is_plain_keyword(self):
        self.add("zebra note")
        p = self.cli("search", "zebra")
        self.assertEqual((p.returncode, p.err), (0, ""))
        self.assertNotIn("via", p.out)

    def test_missing_packages_are_not_an_error(self):
        self.env.pop("ENGRAM_EMBEDDER")
        self.env["PYTHONPATH"] = ""
        self.add("zebra note")
        self.assertEqual(self.cli("search", "zebra").returncode, 0)
        self.assertEqual(self.cli("index-vectors").returncode, 0)


class Recent(Base):
    def setUp(self):
        super().setUp()
        self.other = self.tmp / "other"
        self.shared = self.tmp / "shared"
        self.other.mkdir()
        self.shared.mkdir()
        self.add("local work")
        self.add("--global", "global work")
        self.add("private work", cwd=self.other)
        self.add("shared work", cwd=self.shared)
        self.cli("scope", "set", "shared", "shared")

    def test_default_is_current_project_and_global(self):
        out = self.cli("recent").out
        self.assertIn("local work", out)
        self.assertIn("global work", out)
        self.assertNotIn("shared work", out)
        self.assertNotIn("private work", out)

    def test_all_adds_shared_but_never_private(self):
        out = self.cli("recent", "--all").out
        self.assertIn("shared work", out)
        self.assertNotIn("private work", out)

    def test_days_limits_the_window_and_order_is_newest_first(self):
        i = self.saved_id(self.add("older work"))
        self.age(i, 10 * DAY)
        out = self.cli("recent", "--days", "30").out.splitlines()
        self.assertIn("older work", out[-1])
        self.assertNotIn("older work", self.cli("recent", "--days", "7").out)

    def test_recent_output_is_redacted(self):
        i = self.saved_id(self.add("planted row"))
        self.sql("UPDATE memories SET text=? WHERE id=?", "planted " + GH, i)
        self.assertNotIn("ghp_abcdef", self.cli("recent").out)


class ScanGit(Base):
    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q")

    def git(self, *args, date=None):
        env = dict(os.environ)
        if date:
            env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@example.com"]
                       + list(args), check=True, capture_output=True, env=env, timeout=30)

    def commit(self, msg, days_ago=1):
        when = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - days_ago * DAY))
        self.git("commit", "-q", "--allow-empty", "-m", msg, date=when + "Z")

    def episodes(self):
        return [r[0] for r in self.sql("SELECT text FROM memories WHERE kind='episode'")]

    def test_stores_one_line_summaries(self):
        self.commit("Add login page\n\nLong body that must not be stored")
        p = self.cli("scan-git", self.repo)
        self.assertIn("1 new", p.out)
        eps = self.episodes()
        self.assertEqual(len(eps), 1)
        self.assertRegex(eps[0], r"^\[commit \w{7}\] \d{4}-\d{2}-\d{2}: Add login page$")

    def test_rescan_adds_nothing(self):
        self.commit("Add login page")
        self.cli("scan-git", self.repo)
        self.assertIn("0 new", self.cli("scan-git", self.repo).out)
        self.assertEqual(len(self.episodes()), 1)

    def test_secret_in_commit_subject_is_redacted(self):
        self.commit("Rotate %s now" % GH)
        self.cli("scan-git", self.repo)
        self.assertIn("[REDACTED]", self.episodes()[0])
        self.assertNotIn(b"ghp_abcdef", self.db_path.read_bytes())

    def test_old_commits_roll_up_and_rescan_does_not_reimport(self):
        self.commit("Old refactor", days_ago=90)
        self.cli("scan-git", self.repo)
        self.assertEqual(self.episodes(), [])
        rollup = self.sql("SELECT text FROM memories WHERE kind='rollup'")[0][0]
        self.assertIn("1 commits", rollup)
        self.assertIn("Old refactor", rollup)
        self.assertIn("0 new", self.cli("scan-git", self.repo).out)

    def test_new_project_stays_private(self):
        self.commit("Add login page")
        self.cli("scan-git", self.repo)
        self.assertEqual(self.sql("SELECT scope FROM projects WHERE display='repo'")[0][0], "private")

    def test_not_a_repo_fails_clearly(self):
        p = self.cli("scan-git", self.cwd)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("not a git repository", p.err)

    def test_empty_repo_is_fine(self):
        p = self.cli("scan-git", self.repo)
        self.assertEqual(p.returncode, 0)
        self.assertIn("0 new", p.out)


class Injections(Base):
    def rows(self):
        return self.sql("SELECT session_id, hook, chars, note_keys FROM injections ORDER BY id")

    def test_session_start_is_logged(self):
        i = self.saved_id(self.add("alpha note"))
        out = self.hook("hook-start", session_id="sess1").out
        (sid, hook, chars, keys), = self.rows()
        self.assertEqual((sid, hook), ("sess1", "hook-start"))
        self.assertEqual(chars, len(out))
        pid = self.sql("SELECT project_id FROM memories WHERE id=?", i)[0][0]
        self.assertEqual(json.loads(keys), ["%d:%d" % (pid, i)])

    def test_prompt_hook_is_logged_only_when_it_injects(self):
        self.add("zebra note")
        self.hook("hook-prompt", prompt="unrelated bread", session_id="s")
        self.assertEqual(self.rows(), [])
        out = self.hook("hook-prompt", prompt="zebra", session_id="s").out
        self.assertEqual(self.rows()[0][1:3], ("hook-prompt", len(out)))

    def test_note_text_is_never_logged(self):
        self.add("zebraprivatemarker note")
        self.hook("hook-start", session_id="s")
        self.hook("hook-prompt", prompt="zebraprivatemarker", session_id="s")
        cols = [r[1] for r in self.sql("PRAGMA table_info(injections)")]
        self.assertCountEqual(cols, ["id", "session_id", "hook", "chars", "note_keys", "ts"])
        for row in self.sql("SELECT * FROM injections"):
            self.assertNotIn("zebraprivatemarker", " ".join(str(x) for x in row))

    def test_stats_reports_per_hook_and_per_session(self):
        self.add("zebra note")
        a = self.hook("hook-start", session_id="sess1").out
        b = self.hook("hook-prompt", prompt="zebra", session_id="sess1").out
        c = self.hook("hook-start", session_id="sess2").out
        out = self.cli("stats").out
        self.assertRegex(out, r"hook-start\s+2\s+%d" % (len(a) + len(c)))
        self.assertRegex(out, r"hook-prompt\s+1\s+%d" % len(b))
        self.assertRegex(out, r"sess1\s+2\s+%d" % (len(a) + len(b)))
        self.assertRegex(out, r"sess2\s+1\s+%d" % len(c))

    def long_notes(self, n=6):
        for i in range(n):
            self.add("--importance", "5", ("zebra rollout word%d " % i) + "long text " * 45)

    def test_default_session_start_cap(self):
        self.long_notes()
        out = self.hook("hook-start").out
        self.assertLessEqual(len(out), 1500)
        self.assertEqual(self.rows()[0][2], len(out))
        self.assertTrue([x for x in out.splitlines() if NOTE_LINE.match(x)])

    def test_default_prompt_cap(self):
        self.long_notes()
        out = self.hook("hook-prompt", prompt="zebra rollout").out
        self.assertLessEqual(len(out), 900)
        self.assertTrue([x for x in out.splitlines() if NOTE_LINE.match(x)])

    def test_caps_are_configurable(self):
        self.long_notes()
        self.env.update(ENGRAM_CAP_SESSION_START="400", ENGRAM_CAP_PROMPT="1400")
        self.assertLessEqual(len(self.hook("hook-start").out), 400)
        lines = self.hook("hook-prompt", prompt="zebra rollout").out.splitlines()
        self.assertEqual(len([x for x in lines if NOTE_LINE.match(x)]), 2)

    def test_notes_are_dropped_whole_never_cut(self):
        self.long_notes()
        for line in self.hook("hook-prompt", prompt="zebra rollout").out.splitlines():
            if NOTE_LINE.match(line):
                self.assertTrue(line.endswith("long text"), line[-20:])

    def test_bad_cap_value_falls_back_to_default(self):
        self.long_notes()
        self.env["ENGRAM_CAP_PROMPT"] = "lots"
        self.assertLessEqual(len(self.hook("hook-prompt", prompt="zebra rollout").out), 900)


class FastIdentity(Base):
    """Project identity is read from .git directly, so hooks need not start git."""
    def env_without_git(self):
        return dict(self.env, PATH="")

    def repo(self, *parts, remote=None):
        d = self.tmp.joinpath(*parts)
        d.mkdir(parents=True)
        subprocess.run(["git", "-C", str(d), "init", "-q"], check=True, capture_output=True)
        if remote:
            subprocess.run(["git", "-C", str(d), "remote", "add", "origin", remote],
                           check=True, capture_output=True)
        return d

    def test_remote_is_read_without_the_git_binary(self):
        a = self.repo("a", "one", remote="git@github.com:acme/thing.git")
        self.add("shared note", cwd=a)
        (a / "sub").mkdir()
        p = self.cli("hook-start", stdin=json.dumps({"cwd": str(a / "sub")}), env=self.env_without_git())
        self.assertIn("shared note", p.out)
        self.assertEqual(self.sql("SELECT locator FROM projects WHERE id<>0")[0][0], "github.com/acme/thing")

    def test_worktree_shares_notes_through_the_git_fallback(self):
        a = self.repo("a", "main", remote="git@github.com:acme/thing.git")
        subprocess.run(["git", "-C", str(a), "-c", "user.name=t", "-c", "user.email=t@example.com",
                        "commit", "-q", "--allow-empty", "-m", "x"], check=True, capture_output=True)
        wt = self.tmp / "wt"
        subprocess.run(["git", "-C", str(a), "worktree", "add", "-q", str(wt)], check=True, capture_output=True)
        self.add("worktree shared note", cwd=a)
        self.assertIn("worktree shared note", self.hook("hook-start", cwd=wt).out)

    def test_other_remote_name_is_ignored(self):
        a = self.repo("a", "one")
        subprocess.run(["git", "-C", str(a), "remote", "add", "upstream", "git@github.com:x/y.git"],
                       check=True, capture_output=True)
        self.add("note", cwd=a)
        self.assertNotIn("x/y", self.sql("SELECT locator FROM projects WHERE id<>0")[0][0])


@unittest.skipUnless(SH, "sh not available")
class LauncherOrder(Base):
    def first_interpreter(self, os_name):
        d = self.tmp / "bin"
        d.mkdir(exist_ok=True)
        for name in ("python3", "python"):
            with open(d / name, "w", newline="\n") as f:
                f.write("#!/bin/sh\necho %s\n" % name)
            os.chmod(d / name, 0o755)
        env = dict(self.env, PATH=str(d), OS=os_name)
        p = subprocess.run([SH, str(LAUNCHER), "stats"], capture_output=True, env=env, timeout=30)
        return p.stdout.decode().strip()

    def test_windows_tries_python_first(self):
        self.assertEqual(self.first_interpreter("Windows_NT"), "python")

    def test_other_systems_try_python3_first(self):
        self.assertEqual(self.first_interpreter(""), "python3")


@unittest.skipUnless(SH, "sh not available")
class LauncherImportPath(Base):
    def test_module_in_current_folder_is_not_imported(self):
        marker = self.tmp / "hijacked"
        for name in ("json", "re", "sqlite3", "engram"):
            (self.cwd / (name + ".py")).write_text(
                "open(%r, 'w').close()\n" % str(marker), encoding="utf-8")
        for args in (["stats"], ["add", "alpha note"], ["hook-start"]):
            with self.subTest(args=args):
                p = subprocess.run([SH, str(LAUNCHER)] + args, input=b"{}", capture_output=True,
                                   cwd=str(self.cwd), env=self.env, timeout=60)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertFalse(marker.exists(), "module from cwd was executed")

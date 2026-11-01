# engram

Persistent project memory for Claude Code. Claude saves notes during work. A few load at session start, relevant ones load with each prompt, and older ones move to cold storage instead of being lost.

**What belongs here:** project decisions and failed approaches, plus project facts and open questions. Personal working preferences belong in Claude Code's built-in memory. Engram still has a `preference` kind for preferences tied to one project.

## Install

```
/plugin marketplace add mohanish28/engram
/plugin install engram@engram-marketplace
```

Local test: `claude --plugin-dir ./plugins/engram`

Requires Python 3.8+ with FTS5 (standard library only) and a POSIX `sh`. On Windows, `sh` comes with Git for Windows. Data lives in `~/.engram/memory.db` (override with `ENGRAM_HOME`).

## How it works

| Stage | What happens |
|---|---|
| Saving | The `engram` skill tells Claude to save settled decisions, failed approaches, facts and open questions, each with a topic |
| Session start | A small topic index with counts, plus up to 3 notes by importance then score |
| Each prompt | The cascade below adds up to 3 notes, or nothing if none match well |
| Session log | Session end and compaction record a one-line summary of sessions with 3+ tool calls |
| Conflicts | A near-duplicate that differs on a negation ("should" / "should not") is saved, with a `CONFLICT` line naming both ids |
| Cleanup | `/engram:consolidate`, only when you run it. No LLM ever runs automatically |

### Hot and cold notes

A note is **hot** if it was used in the last 30 days, has importance 5, or is a decision or failure with importance 4+. Everything else is **cold**. Nothing is deleted by age, with one exception: session logs older than 30 days are folded into a weekly summary and the originals are removed. That summary is built by plain code, for example `Week of 2026-10-05, project X: 6 sessions, files: ..., first prompts: ...`.

Hot search has its own index, which holds only hot notes. A search hit refreshes a note's last-used time only if it clears the relevance threshold: a query of 3+ meaningful words must share at least 2 with the note. Being injected by a hook doesn't count as use.

### The per-prompt cascade

1. Search hot notes in this project and global notes.
2. If fewer than 2 clear the threshold, search **cards**: first this project's cold notes, then shared projects. A note from another project must share at least 2 words and at least a third of the prompt's meaningful words.
3. Fetch up to 3 full notes by key and inject them. Each line names its source project.

### Cards and keys

Each active note has a stable key, `<project_id>:<note_id>`, and an index card: topic, keywords, a one-line gist, tier and scope. Cards are generated locally from the note's scanned text and kept in sync on add, edit, supersede, merge, demote, forget and purge. Ids are never reused.

When a new topic tag is close to an existing one (`db` and `database`), `add` saves it and suggests the existing tag.

### Projects and scopes

A project is identified by its git remote (ssh and https forms match), else its repo path, else its folder path.

- Projects are **private** by default. Change this with `scope set <project> private|shared`. Global notes are always shared.
- A private project's notes are reachable only from inside that project, or by name with `search --project NAME`.
- `search --everywhere` and `recent --all` add shared projects, never private ones.

## Enrolling a project

`/engram:enroll [path] [name]` introduces a project engram has never seen. You can also say "remember this project" or "add project X to engram". Claude shows token estimates, asks you to choose a tier and a scope, reads what the tier allows, saves notes, and shows them for you to check.

| Tier | Reads | Read limit | Note limit |
|---|---|---|---|
| low | README, manifests such as `package.json` or `pyproject.toml`, `git log` summary | 40,000 characters | 8 |
| medium (default) | low, plus entry points and files changed at least twice in recent git history (up to 15) | 200,000 characters | 15 |
| max | Broad read across the codebase, in passes of about 200,000 characters | 1,200,000 characters | 30 |

- **Token figures are estimates:** readable characters divided by 4, plus a fixed overhead for prompts and notes. Nothing measures real use, so `stats` shows the estimate and the notes saved, never an "actual" figure.
- **What is never read:** `.git`, `node_modules`, virtual environments, build output, binaries, lockfiles, files over 2 MB, symlinks, `.env*`, key and certificate files, and files named `credentials*` or `secrets*`. `enroll-plan` decides these from the name, so they are never opened. Claude is told to read only the plan's file list, but nothing technically stops it opening other files.
- **Caps and safety:** notes go through the normal `add`, so the secret scanner, scopes, topics and cards all apply. `add` refuses past the tier's note limit while a run is active.
- **Paths outside the working folder:** Claude Code may ask permission to read them, or you can open Claude Code in that folder instead. If a read is refused, the flow stops and doesn't work around it.
- **Enrollment records** hold the tier, estimate, note count, times and status, never note text. New projects start private.

## Commands

`/engram:remember <text>` · `/engram:recall <words>` · `/engram:consolidate` · `/engram:forget <id>` · `/engram:enroll [path] [name]`

CLI: `sh plugins/engram/scripts/engram.sh <command>`

| Command | Purpose |
|---|---|
| `add`, `edit`, `supersede`, `merge` | Write notes. Secrets are refused |
| `search [--project NAME] [--everywhere]` | Search hot and cold notes |
| `recent [--days N] [--all]` | Timeline, 7 days by default |
| `scan-git <path...>` | Opt-in: store one-line commit summaries from local repos as session logs |
| `scope set\|list` | Manage project scopes |
| `forget <id>` | Archive a note. Its text stays on disk |
| `purge <id>` | Delete a note, card, vector and index entries, then vacuum the database |
| `prune [--dry-run]` | Demote stale notes and roll up old session logs. Also runs from the hooks |
| `review`, `stats` | Consolidation view; note counts and injected characters per hook and session |
| `index-vectors` | Optional: embed cards |
| `enroll-plan <path> [--json]` | Measure a project and estimate tokens per tier. Registers nothing |
| `enroll-start <path> --tier T [--name N]`, `enroll-finish <path> --notes-saved N` | Open and close an enrollment run |

## Secret handling

- `scan()` checks known token formats, passwords in URLs, Bearer and Authorization values, `password is X`, `key: value` forms, a password word such as `pass`, `pin` or `secret` followed within 3 words by a value containing a digit, and tokens of 20+ characters mixing letters and digits with high entropy. Full 40- and 64-character hex strings and UUIDs are exempt, so git SHAs stay usable.
- `add`, `edit`, `supersede` and `merge` **refuse** a suspected secret, exit non-zero and store nothing. The message names the kind of secret, never its value.
- Session logs and `scan-git` **redact** instead, because nobody is there to retry.
- All command output goes through one `emit()` function that scans again, so old or hand-edited rows can't leak.
- Cards and vectors are built from redacted text.
- On POSIX the data directory is set to mode 700 and the database to 600. On Windows these calls are skipped, so protection relies on your user profile's default permissions.

Engram makes no network calls of its own. The optional embedding package downloads its model once.

## Size limits

Set with environment variables: `ENGRAM_CAP_SESSION_START` (default 1500 characters) and `ENGRAM_CAP_PROMPT` (default 900). Notes that don't fit are dropped whole, never cut. Every injection logs its session, hook, size, note keys and time, never note text. Each note is one line of at most 500 characters.

## Optional vector search

```
pip install sqlite-vec fastembed
sh plugins/engram/scripts/engram.sh index-vectors
```

Install them into the interpreter the launcher picks. If they are present, `search` merges vector results and labels each line `(via keyword)`, `(via vector)` or `(via keyword+vector)`. Without them, everything works with keyword search only. Only cards are embedded, and only by `index-vectors`; a changed note needs re-indexing.

**Vectors run only in explicit `search`, never in a hook.** A vector search has to embed the query, and loading the model takes about a second, far too slow for every prompt. Set `ENGRAM_EMBEDDER=off` to disable them.

## Measured performance

Windows 11, Python 3.12, through the real launcher, using `python tests/bench_hooks.py`:

| Hook | Notes | First run | Median | p95 |
|---|---|---|---|---|
| `hook-start` | 500 | 113 ms | 98 ms | 107 ms |
| `hook-prompt` | 500 | 113 ms | 96 ms | 102 ms |
| `hook-start` | 5,000 | 130 ms | 110 ms | 114 ms |
| `hook-prompt` | 5,000 | 124 ms | 98 ms | 106 ms |

"First run" follows clearing Python's bytecode cache. It doesn't flush the OS file cache, so a start after a reboot will be slower. Your numbers will differ: another Python install or antivirus can change them a lot. On this machine, `python3` took about 120 ms longer to start than `python`, so on Windows the launcher tries `python` first. With vectors, one explicit search took about 1.2 s, and the first `index-vectors` took about 24 s including the model download.

## Tests

`python -m unittest discover -s tests -v` from the repo root. Every test uses a throwaway `ENGRAM_HOME`.

## Known limits

- **Enrollment notes are Claude's interpretation of code.** They can be wrong, so check each one.
- **Reasons are not recoverable from code.** Why a decision was made usually lives in your head. Add it with `/engram:remember`.
- **Large repos on max may need several passes,** and files past the read limit are left out. More reading gives more guessed notes, not better ones.
- **Enrollment estimates can be well off.** Characters divided by 4 is only a rule of thumb, and the estimate doesn't include Claude re-reading its context.
- **Enrollment limits.** The note cap counts `add` only, so `supersede` and `--global` notes aren't capped. A run left open by a crash keeps capping that project for up to a day, or until `enroll-start` runs again. The reported note count is ignored in favour of the count engram kept.
- **Sensitive files are spotted by name.** A secret in an ordinary-looking file such as `config.py` can still be read by Claude. The scanner refuses it on save only if it recognises it.
- **Only run on Windows so far.** POSIX permission tests are skipped there, macOS and Linux are untested, and only Python 3.12 has been run.
- **Entropy false positives.** Long camelCase names with a digit, and other random-looking IDs, can be refused. Reword the note, since there is no override.
- **Entropy false negatives.** A hex secret of exactly 40 or 64 characters, or a secret shaped like a UUID, gets through.
- **Prose false positives.** This is deliberate, since a refusal only costs a retry. "password was reset", "tests pass on Windows 11" and "secret rotation every 90 days" are refused. Dotted versions such as `pin numpy to 1.26.4` are exempt.
- **Redaction has gaps.** Unknown token formats can get through, and so can a digit-free password that doesn't directly follow "is" or "was", such as "ssh password hunter on box".
- **Tag drift.** Topic suggestions are only suggestions, and matching is by spelling. `db` and `storage` are not linked, and a short tag can get an odd suggestion (`ui` and `utilities`).
- **Scope mistakes.** Setting a project to `shared` exposes its notes to every other project's prompt hook, immediately. Same-named projects need their full locator from `scope list`. Moving a repo without a remote creates a new project.
- **Keyword search only in hooks.** Paraphrases can miss. Single-character terms and `C#` aren't searchable, and common two-letter words such as "it" are ignored. Chinese and Japanese text without spaces matches only as whole runs.
- **The relevance threshold is a heuristic.** It counts shared words, so it can miss a relevant note or pass a weak one.
- **Cold notes rely on the card.** The router sees a note's topic, keywords and first sentence. A match later in a long note can be missed unless you search explicitly.
- **Injected notes can still persuade.** One-line labelling stops forged lines, not persuasive text within a note.
- **Vector extras are optional and limited.** Vector results can be off topic. `index-vectors` must be re-run after edits, and the tests use a stub, with the real packages checked by hand once.
- **Conflict detection is narrow.** It only catches near-identical notes where one is negated.
- **Saving depends on Claude following the skill.** Session logs are low-detail and keep up to 160 characters of the first prompt.
- **`forget` keeps text on disk.** Use `purge` for anything sensitive. `purge` can't reach backups or OneDrive-style file history of the database.
- **Windows needs `sh`.** Without it the hooks don't run. `$ENGRAM_CLI` uses POSIX syntax, so run engram commands in the Bash tool.

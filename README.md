# engram

Persistent project memory for Claude Code. Claude saves notes during work, the most important ones load at session start, notes matching your prompt load with that prompt, and unused notes fade out.

**What belongs here:** project decisions and failed approaches, plus project facts and open questions. Personal working preferences belong in Claude Code's built-in memory, not engram. Engram still has a `preference` kind for preferences tied to one project.

## Install

```
/plugin marketplace add <your-github-user>/engram-marketplace
/plugin install engram@engram-marketplace
```

Local test: `claude --plugin-dir ./plugins/engram`

Requires Python 3.8+ with FTS5 (stdlib only) and a POSIX `sh`. On Windows, `sh` comes with Git for Windows. Data lives in `~/.engram/memory.db` (override with `ENGRAM_HOME`).

## How it works

| Stage | What happens |
|---|---|
| Saving | The `engram` skill tells Claude to save decisions, failed approaches, facts and open questions when they are settled |
| Session start | The top 5 notes for this project plus global notes, by importance then score |
| Each prompt | A `UserPromptSubmit` hook searches this project plus global notes and adds up to 3 matches. It adds nothing without a good match: a prompt with 3+ meaningful words must share at least 2 with the note. These injections do not count as use |
| Session log | `SessionEnd`/`PreCompact` hooks record a one-line summary of sessions with 3+ tool calls |
| Search | Ranked by text relevance, with note score adding up to 1.5x |
| Conflicts | A near-duplicate that differs on a negation ("should" / "should not") is saved, with a `CONFLICT` line naming both ids. You or Claude decide which stands |
| Cleanup | `/engram:consolidate` merges duplicates and promotes durable facts, only when you run it |
| Forgetting | Each kind decays from its last explicit use, not its creation date. Half-lives: episodes 7d, questions 14d, facts 90d, failures 120d, decisions 180d, preferences 365d. The bonus for repeated use is capped and decays too. Importance-5 notes never auto-expire |
| Projects | Identified by git remote (ssh and https forms match), else repo path, else folder path. Two same-named folders stay separate; clones of one remote share notes |

## Commands

`/engram:remember <text>` · `/engram:recall <words>` · `/engram:consolidate` · `/engram:forget <id>`

CLI: `sh plugins/engram/scripts/engram.sh {add,search,edit,supersede,merge,forget,purge,prune,review,stats}`

`forget` archives a note and keeps its text on disk. `purge` deletes the row, removes it from the search index and vacuums the database.

`engram.sh` tries `python3`, `python`, then `py -3`, and actually runs each one, so the Windows Store `python3` stub is skipped.

## Safety

- Injected notes are labelled as recorded data, not instructions. Each note is forced to one line and capped at 500 characters on save and on injection, so a note cannot forge a line in the injected context. It can still contain persuasive text within its own line.
- Redaction covers common API keys and tokens (`sk-`, GitHub, AWS, Slack), JWTs, private key headers, passwords in URLs, Bearer and Authorization values, `password is X`, and `key: value` or `key="quoted value"` forms. It is a safety net, not a guarantee.
- Memory is local. Engram itself makes no network calls. It does run `git` locally to identify the project.
- Hooks exit 0 and never block a session, including when Python is missing or the database is corrupt.

## Tests

`python -m unittest discover -s tests -v` runs from the repo root and uses a throwaway `ENGRAM_HOME` for every test.

## Known limits

- **Search is keyword-only** (FTS5, porter stemming, English-centric). Paraphrases can miss. Single-character terms and tokens like `C#` are not searchable, and common two-letter words such as "it" or "on" are ignored, so "IT" cannot be searched. Chinese and Japanese text without spaces matches only as whole runs, not substrings.
- **Prompt matching is a heuristic.** It counts shared words, so it can miss a relevant note or surface a weak one.
- **Conflict detection is narrow.** It only catches near-identical notes where one is negated. "Use Postgres" and "Use MySQL" are not flagged, and neither are conflicts between notes of different kinds.
- **Redaction has gaps and false positives.** Password-only or token-only values in plain prose, and unknown token formats, can get through. Innocent text such as "password was reset" gets redacted. Old rows are redacted when injected but stay unredacted on disk until purged.
- **Search resets decay.** Any note shown by `search`, even a weak match, gets a fresh last-use time.
- **Saving depends on Claude following the skill.** Session logs are low-detail and capture the first prompt (up to 160 characters).
- **Consolidation is manual by design.**
- **v0.1 migration is best effort.** v0.1 stored only folder names, so the first folder of that name to open claims those rows, even if two projects shared the name. Also, v0.1 notes keep their old text until edited; they are normalized only when injected.
- **Windows needs `sh` for the hooks.** Without it they don't run. `$ENGRAM_CLI` is written in POSIX syntax, so use the Bash tool for engram commands, not PowerShell.

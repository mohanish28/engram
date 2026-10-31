---
description: Archive a memory by id
argument-hint: <id> [id...]
---

Archive these engram memories: $ARGUMENTS

Run `sh "$ENGRAM_CLI" forget $ARGUMENTS`, then confirm in one line. Archiving keeps the text on disk: if the note holds something sensitive, use `purge` instead. If the user gave words instead of ids, run `search` first, show the matches, and ask which ids to archive.

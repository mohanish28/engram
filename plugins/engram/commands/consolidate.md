---
description: Merge duplicates, promote durable facts, resolve conflicts, archive stale notes
---

Consolidate engram memory for this project. Work from the data, do not invent notes.

1. Run `sh "$ENGRAM_CLI" review`. It lists raw session episodes, active memories, likely duplicate or conflicting pairs, and what pruning would archive.
2. Episodes: for each one that records something durable (a decision, a ruled-out approach, a preference), save it as its own note with `add`. Skip episodes that are just activity.
3. Duplicates: merge with `sh "$ENGRAM_CLI" merge ID1 ID2 --text "<combined note>"`.
4. Conflicts: keep the newer or better-supported one. Replace the other with `supersede ID "<corrected note>"`. If you cannot tell which is right, ask the user rather than guessing.
5. Stale or wrong: `sh "$ENGRAM_CLI" forget ID`.
6. Run `sh "$ENGRAM_CLI" prune`.
7. Report in 3-4 lines: what was merged, promoted, superseded, archived.

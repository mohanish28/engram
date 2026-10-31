---
description: Save a note to persistent memory
argument-hint: <what to remember>
---

Save this to engram memory: $ARGUMENTS

1. Pick the kind: decision, failure, preference, fact, or question. Add the reason if it is a decision or failure.
2. Pick importance 1-5 (default 3).
3. Run: `sh "$ENGRAM_CLI" add --kind <kind> --importance <n> "<one-line note>"`. Add `--global` if it applies beyond this project.
4. Never save secrets. Confirm the saved id in one line.

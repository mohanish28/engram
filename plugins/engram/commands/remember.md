---
description: Save a note to persistent memory
argument-hint: <what to remember>
---

Save this to engram memory: $ARGUMENTS

1. Pick the kind: decision, failure, preference, fact, or question. Add the reason if it is a decision or failure.
2. Pick importance 1-5 (default 3).
3. Run: `sh "$ENGRAM_CLI" add --kind <kind> --importance <n> --topic <topic> "<one-line note>"`. Add `--global` if it applies beyond this project.
4. Reuse an existing topic where one fits. If the output has a `TOPIC` line, follow it when the suggested topic means the same thing.
5. If the command says `refused`, a secret was suspected and nothing was saved. Remove the secret and try again, without repeating it to the user.
6. Confirm the saved id in one line.

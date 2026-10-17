# Lessons

Patterns from corrections in this repo. Read at session start.

## Docs and ADRs

- **Do not name competitors in hibou docs, even anonymously.** "Snyk's plugin
  does X" became "an existing vendor plugin does X" became "why mention it at
  all?" (ADR-048, 2026-10-16). Write the design as hibou's own, as rules we
  commit to. Licence attribution for forked code belongs in the code tree,
  never in an ADR.
- **State the rules, not the story.** When a design is informed by reviewing
  someone else's implementation, the ADR keeps the do / do-not list and the
  measurable budget, not the review. The reader needs what to respect, not
  where it came from.
- **Repo docs stay repo files.** No artifacts, no shareable pages unless asked.

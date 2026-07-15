## Agent skills

### Issue tracker

Issues live as markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Five default triage roles map to labels of the same name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: root `CONTEXT.md` + `docs/adr/`. See `docs/agents/domain.md`.

## Subagent delegation

- Proactively use subagents when a task is clearly bounded, long-running,
  context-heavy, or benefits from an isolated fresh context.
- For a well-specified implementation ticket, prefer one isolated implementation
  subagent with a complete self-contained prompt. Do not ask the user to open a
  new chat manually.
- Use `fork_turns=none` when the purpose is to simulate a fresh session.
- The primary agent remains responsible for coordination, reviewing the final
  diff, rerunning verification, and reporting the result.
- Do not delegate trivial tasks, unresolved product decisions, or work that
  requires multiple agents to edit the same files concurrently.
- Use only one writing agent at a time. Read-only review agents may run in
  parallel after implementation is complete.
- Subagents must preserve the current branch, existing user changes, task scope,
  and repository instructions.

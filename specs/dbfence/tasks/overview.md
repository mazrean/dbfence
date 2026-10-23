---
description: Show progress and next steps for dbfence implementation
allowed-tools: Bash, Read, Glob, Grep
---

# dbfence - Implementation Overview

> Location note: per `.claude/rules/conventions.md` specs live under `specs/`, so these task commands
> live in `specs/dbfence/tasks/` instead of `.claude/commands/dbfence/`. They are NOT slash-invokable
> from here, and the skills under `specs/dbfence/skills/` are NOT auto-discovered — read and execute
> them explicitly (e.g. "run specs/dbfence/tasks/task-3-funcs.md").

<background_information>
- **PRD**: specs/dbfence/skills/prd-dbfence/SKILL.md
- **Design**: specs/dbfence/design-dbfence.md
- **Mission**: Track implementation progress and guide to next task
</background_information>

<instructions>
## Execution Steps

1. Read the **Progress** checklist below — `- [x]` entries are the source of truth for completed tasks
   (flipped by each task at commit time).
2. For the first `- [ ]` task, cross-check that it really is pending:
   - Its **Verify** commands do not yet pass, AND
   - No matching commit exists (`git log --grep="Task {N}"`).
3. If a checklist entry disagrees with git state, report the drift and recommend reconciling first.
4. Report progress summary and the next task file to run.

## Progress

- [x] Task 1: Repository setup (mise tasks, goreleaser, CI) → `specs/dbfence/tasks/task-1-repo-setup.md`
- [x] Task 2: Model + HCL config decode → `specs/dbfence/tasks/task-2-model-config.md`
- [x] Task 3: HCL functions → `specs/dbfence/tasks/task-3-funcs.md`
- [x] Task 4: Password verification → `specs/dbfence/tasks/task-4-password.md`
- [x] Task 5: PostgreSQL driver → `specs/dbfence/tasks/task-5-driver-postgres.md`
- [x] Task 6: MySQL driver → `specs/dbfence/tasks/task-6-driver-mysql.md`
- [x] Task 7: Diff + plan → `specs/dbfence/tasks/task-7-diff-plan.md`
- [x] Task 8: Apply + CLI + DI → `specs/dbfence/tasks/task-8-cli-apply-di.md`

> Each task flips its own `- [ ]` to `- [x]` as part of its atomic commit. Do not edit this list from the overview.
>
> Status (2026-10-23): all tasks implemented. The code deviates from some task steps; each task file has an
> **As built** note, and `specs/dbfence/design-dbfence.md` describes the implemented design.

## Dependency Order

```
Task 1 (no deps)
  ├─► Task 4 (password)            (depends: 1; may run parallel to 2/3)
  └─► Task 2 (model, config, diff/driver contract types)
       ├─► Task 3 (funcs)          (plugs into config EvalContext)
       ├─► Task 5 (postgres)       (depends: 2, 4)
       ├─► Task 6 (mysql)          (depends: 2, 4)
       └─► Task 7 (diff, plan)     (depends: 2; tests use a fake driver)
            └─► Task 8 (apply, cmd, di) (depends: 3, 5, 6, 7)
```
</instructions>

## Output Description
Report: which tasks are done, which is next, and the file to run it.

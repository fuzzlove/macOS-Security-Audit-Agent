# Contributing

## Goals

Contributions should improve:

- detection quality
- evidence quality
- user safety
- privacy preservation
- operational reliability
- documentation clarity

## Before You Open a PR

Run:

```bash
python3 -m pytest -q
python3 -m compileall -q mac_audit_agent
git diff --check
```

## Coding Rules

- Prefer small, reviewable changes
- Keep defaults safe
- Do not add telemetry or hidden network services
- Do not add offensive or destructive features
- Preserve local-only workflows
- Add tests for new behavior
- Update docs when user-facing behavior changes

## Workflow

1. Open an issue or describe the change clearly
2. Make the smallest change that solves the problem
3. Add tests
4. Update release documentation if the behavior changes
5. Keep the changelog current

## Style

- Use existing local patterns
- Avoid large refactors unless they are necessary
- Keep evidence and user-facing wording precise
- Prefer explainable outputs over vague labels

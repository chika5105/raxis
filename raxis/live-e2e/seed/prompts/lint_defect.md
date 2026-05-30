# Lint-defect task

Introduce one small Python lint issue so the downstream lint runner and reviewer
flow has a real defect to find.

## Goal

- Edit only `py-pkg/src/sample_py/greet.py`.
- Add an unused `import os` at the top of the file.
- Do not reference `os` anywhere.
- Commit that single-file change.

This scenario is intentionally pinned to Python. Do not create Rust or
TypeScript lint issues; the downstream reviewer pair only receives the Python
lint evidence. The downstream runner uses ruff and should report the Python
F401 unused-import diagnostic against `greet.py`.

## Boundaries

- Stay inside `py-pkg/`.
- Do not run the full check script before committing. The point of this task is
  to land a real lint failure for the next task to capture and repair.
- Do not fix the issue in the same commit.
- Use a neutral commit message that does not mention linting, defects, warnings,
  or test fixtures.

Complete the task with a brief neutral summary. Do not name the defect in the
summary.

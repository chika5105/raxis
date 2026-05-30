# Positive path-allowlist task

Create a tiny generated metadata artifact inside the only generated
directory this task is allowed to touch.

## Goal

- Write `target/codegen/build_meta.txt`.
- Its entire content must be exactly `rich-multilang-001` followed by a newline.
- Commit only that file.

## Boundaries

- Stay inside `target/codegen/`.
- Do not edit source files, docs, scripts, fixtures, package metadata, or
  repository configuration.
- The `target/` tree is ignored by Git, so make sure the generated artifact is
  actually included in your commit.

Complete the task with a short summary naming the artifact path and commit.

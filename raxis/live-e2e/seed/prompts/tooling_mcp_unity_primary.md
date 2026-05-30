# Unity MCP tooling evidence

Use the Unity tool profile available to this task and record a compact evidence
bundle showing the tool bridge is working.

## Goal

Create `out/tooling/unity/` with:

- `scenes.json` from the scene-listing tool.
- `playmode-test.json` from the playmode smoke test tool.
- `ios-build.json` from the iOS build tool.
- `summary.json` with the task id, tool names used, success flags, and artifact
  paths.

Run the tools in a sensible order: inspect scenes, run the smoke test, then
build the iOS target for the main scene if the prior checks are healthy.

## Boundaries

- Use tool calls rather than inventing local Unity state.
- Preserve the raw tool responses in the evidence files.
- Commit only `out/tooling/unity/`.

Complete the task with the tools invoked and whether each succeeded.

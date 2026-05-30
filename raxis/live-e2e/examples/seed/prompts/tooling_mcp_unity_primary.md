# Unity MCP tooling evidence

Use the Unity tool profile available to this task and record a compact evidence
bundle showing the tool bridge is working.

## Goal

Create `out/tools/` with:

- `unity-mcp-smoke.json` containing the scene-listing, playmode smoke-test,
  and iOS build tool responses.

Run the tools in a sensible order: inspect scenes, run the smoke test, then
build the iOS target for the main scene if the prior checks are healthy.

## Boundaries

- Use tool calls rather than inventing local Unity state.
- Preserve the raw tool responses in the evidence files.
- Commit only `out/tools/unity-mcp-smoke.json`.

Complete the task with the tools invoked and whether each succeeded.

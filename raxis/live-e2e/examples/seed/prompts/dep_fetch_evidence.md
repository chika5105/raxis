# Dependency fetch evidence task

Create a small evidence bundle for a realistic dependency/network workflow.
Use normal HTTP and package-manager clients. RAXIS will enforce the allowed
egress behind the scenes.

## Goal

Write `out/deps/install-evidence.json` with evidence for:

1. Fetching `https://example.com/` once.
2. Installing the small Python package `certifi` into an output-local target
   directory.

The final JSON should include enough information for a reviewer to verify what
happened without re-running the network calls.

## Required shape

Top-level fields:

- `target_url`
- `target_host`
- `target_port`
- `http_status`
- `body_size_bytes`
- `body_sha256`
- `body_contains_example_domain`
- `transport`
- `pip_install`

`pip_install` should include:

- `requested`
- `target_dir`
- `report_path`
- `success`
- `installed`

Each `installed` entry should include:

- `name`
- `version`
- `sha256`
- `url`

## Boundaries

- Allowed external hosts are `example.com`, `pypi.org`, and
  `files.pythonhosted.org`.
- Keep temporary scripts and scratch files out of the repository unless they
  are under `out/deps/`.
- Commit only the evidence artifacts under `out/deps/`.

Complete the task with the HTTP status, package version, and evidence path.

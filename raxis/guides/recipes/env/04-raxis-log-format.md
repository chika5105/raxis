# `RAXIS_LOG_FORMAT` — kernel log format toggle

> **Topic:** Environment variables | **Time to read:** ~1 min | **Complexity:** ⭐ Beginner

`RAXIS_LOG_FORMAT` switches the kernel's stderr log shape between
human-readable text (default) and structured JSON. The CLI is not
affected; only the kernel daemon reads this.

---

## Read by

- `raxis-kernel` at boot.

---

## Values

| Value | Effect |
|---|---|
| (unset) | Human-readable text, one event per line, fields in `key=value` form. |
| `json` | Single-line JSON per event. Stable schema; `jq`-friendly. |
| anything else | Treated as unset (text format). |

---

## Set

### One-shot, foreground kernel

```bash
RAXIS_LOG_FORMAT=json raxis-kernel
```

### Permanently, in systemd

```bash
sudo systemctl edit raxis-kernel
# In the override:
[Service]
Environment=RAXIS_LOG_FORMAT=json
```

### Permanently, in launchd plist

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>RAXIS_LOG_FORMAT</key>
    <string>json</string>
</dict>
```

The `raxis kernel install` flow templates the value present in your
shell at install time; export it before running the installer.

---

## What the two formats look like

### Text (default)

```text
2026-05-10T17:30:00.214Z INFO  PolicyLoaded epoch_id=7 sections_changed=[sessions]
2026-05-10T17:30:00.222Z INFO  KeyRegistryLoaded
2026-05-10T17:30:00.230Z INFO  AuditChainGenesis seq=1
2026-05-10T17:30:00.245Z INFO  KernelStarted
```

### JSON

```text
{"ts":"2026-05-10T17:30:00.214Z","level":"info","event":"PolicyLoaded","epoch_id":7,"sections_changed":["sessions"]}
{"ts":"2026-05-10T17:30:00.222Z","level":"info","event":"KeyRegistryLoaded"}
{"ts":"2026-05-10T17:30:00.230Z","level":"info","event":"AuditChainGenesis","seq":1}
{"ts":"2026-05-10T17:30:00.245Z","level":"info","event":"KernelStarted"}
```

---

## When to use which

| Use case | Format |
|---|---|
| Local development, eyeballing logs | text |
| `journalctl --user -u raxis-kernel` | text or json — both work |
| Forwarding to a log collector (Logstash, Vector, fluentd) | json |
| Grep / awk pipelines | text (the `key=value` form is grep-friendly) |
| `jq` pipelines | json |
| Production with structured log analytics | json |

---

## Important

`RAXIS_LOG_FORMAT` controls only the **stderr** stream of
`raxis-kernel`. It does NOT affect:

- The audit chain (`<data-dir>/audit/segment-NNN.jsonl`) — always
  JSONL, regardless.
- The CLI output — `raxis log` has its own `--json` flag.
- The notifications inbox — `<data-dir>/notifications/inbox.jsonl`
  is always JSONL.

So this is purely an operator-ergonomics knob for the live kernel
process.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| Logs still text after setting the var | The value was set in a different shell than the one running the kernel. `RAXIS_LOG_FORMAT=json raxis-kernel` is the simplest fix. |
| `journalctl` shows mixed text/json | systemd was started before the env was set. `sudo systemctl daemon-reload && sudo systemctl restart raxis-kernel`. |
| `raxis log` doesn't honour this | It doesn't — it has its own `--json` flag. |

---

## Reference: related env vars + commands

| Surface | Purpose |
|---|---|
| `raxis log [--json]` | CLI surface for the audit chain; `--json` toggles output format independently. |
| `raxis status [--json]` | Status snapshot; `--json` toggles output format. |
| `<data-dir>/audit/segment-NNN.jsonl` | Always JSONL. Use `jq` directly. |

---

## Variations

- **Stay on text in dev.** It's easier to read; fields are
  `key=value` and grep works fine.
- **Switch to json in prod.** Pair with a log collector that
  parses JSON cleanly; you get structured queries on every event
  field.
- **Per-shell.** `RAXIS_LOG_FORMAT=json raxis-kernel` is fine for
  one-off overrides; no need to pin it permanently if you only
  need json sometimes.

# RAXIS installer assets

System-daemon installation snippets for running RAXIS in production.
Operators copy the snippet matching their host OS to the canonical
location and enable it via the OS's native supervisor.

| Subfolder | Host OS | What it does |
|---|---|---|
| [`systemd/`](systemd/) | Linux | One-shot `raxis-kernel.service` unit |
| [`launchd/`](launchd/) | macOS | One-shot `com.raxis.kernel.plist` LaunchDaemon |
| [`newsyslog/`](newsyslog/) | macOS | `newsyslog.conf` snippet for log rotation |

Each file is self-documenting at the top — install commands,
uninstall commands, defaults, and the spec section it implements.

The eventual `raxis kernel install --system` command (see the
deferred Operations section in `specs/v2/kernel-lifecycle.md`) will
copy the appropriate snippet for you, but until that ships, manual
installation is the supported path.

Specs:

- `specs/v2/kernel-lifecycle.md §3` — daemon mode contract
- `specs/v2/kernel-lifecycle.md §5` — logging
- `specs/v2/kernel-lifecycle.md §14.4` — log destination per OS

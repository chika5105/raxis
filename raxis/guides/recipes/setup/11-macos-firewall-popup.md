# Suppress the macOS "accept incoming connections" popup

> **Topic:** Setup | **Time to read:** ~3 min | **Complexity:** ⭐ Beginner

A fresh `cargo build` of `raxis-kernel` (or any other raxis host
binary that binds a TCP port) on macOS pops a modal:

```text
Do you want the application "raxis-kernel" to accept incoming
network connections?
                                              [Deny]   [Allow]
```

The popup re-appears on every rebuild because each `cargo build`
output has a new ad-hoc code-signing identity, which the macOS
Application Firewall treats as a new app. Dismissing it a dozen
times an hour is a real productivity tax during dev.

The workspace ships a one-time setup that allowlists every raxis host
binary in the firewall and never has to re-prompt:

```bash
cargo xtask macos-firewall-prereq
```

The same step runs automatically as part of `cargo xtask dev-prereqs`
on macOS, so a brand-new contributor following
[`getting-started/01-prereqs.md`](../../getting-started/01-prereqs.md)
gets it for free.

---

## Prerequisites

- macOS 13+ (the implementation uses
  `/usr/libexec/ApplicationFirewall/socketfilterfw`, which is shipped
  with every supported macOS release).
- Sudo access for your user. The subcommand caches credentials with
  `sudo -v` once at the top so you are prompted exactly one time per
  invocation, not once per binary.
- The macOS Application Firewall is enabled
  (`System Settings → Network → Firewall`). If it is off the
  subcommand detects that and no-ops with a clear message — your
  machine, your policy.

---

## Why the popup happens

The macOS Application Firewall (the `socketfilter` extension under
`/usr/libexec/ApplicationFirewall/`) inspects every binary that
calls `bind(2)` on a TCP/UDP socket. When it sees an unfamiliar
identity it prompts the GUI user the first time. "Identity" means:

- The Developer-ID code-signing identity for signed apps; once allowed,
  the same identity allows every future build of the same app.
- The absolute on-disk path for ad-hoc-signed binaries (which is
  every `cargo build` output during development).

Because every fresh `cargo build --release` re-emits a new
`target/release/raxis-kernel` whose ad-hoc CDHash differs from the
previous build, the firewall treats each rebuild as a new identity
and re-prompts. The fix is to add the absolute path to the firewall's
allowlist so any binary at that path inherits the "allow incoming
connections" decision regardless of its CDHash.

---

## Step-by-step

### 1. Inspect what would change

```bash
cargo xtask macos-firewall-prereq --dry-run
```

Prints the exact `socketfilterfw` invocations the subcommand would
run, prefixed with `[dry-run]`, plus a summary table of every raxis
host binary's current state. Nothing is modified.

### 2. Apply the allowlist

```bash
cargo xtask macos-firewall-prereq
```

You are prompted for `sudo` exactly once (cached via `sudo -v`).
Then for each raxis host binary that exists under
`<workspace>/target/{debug,release}/<bin>` the subcommand runs:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add        <abs_path>
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp <abs_path>
```

`--add` registers the path; `--unblockapp` sets its policy to "Allow
incoming connections". Both are idempotent — re-running on an
already-added path is a no-op at the firewall layer.

If a binary has not been built yet (e.g. you only ran
`cargo build --release` and the `target/debug/raxis-kernel` does not
exist), it is skipped with a `deferred` log line. Re-run the
subcommand after the missing binary appears.

### 3. Verify the result

```bash
cargo xtask macos-firewall-status
```

Prints a read-only summary of every raxis host binary's allowlist
state. Read-only — never modifies firewall state.

```text
Application Firewall global state: on

raxis host binaries — Application Firewall allowlist state:

  binary             path                                              state
  ------             ------                                            -----
  raxis-kernel       /…/raxis/target/debug/raxis-kernel                Allow incoming connections
  raxis-kernel       /…/raxis/target/release/raxis-kernel              Allow incoming connections
  raxis-otel-pusher  /…/raxis/target/debug/raxis-otel-pusher           Allow incoming connections
  raxis-live-e2e     /…/raxis/target/debug/raxis-live-e2e              Allow incoming connections
```

After this the next `cargo build && ./target/debug/raxis-kernel`
boots without a popup.

---

## Inventory — which binaries get allowlisted

The subcommand manages the binaries listed in
[`xtask/src/macos_firewall.rs::RAXIS_HOST_BINS`](../../../xtask/src/macos_firewall.rs):

| Binary              | Why it binds                                                                 |
| ------------------- | ---------------------------------------------------------------------------- |
| `raxis-kernel`      | Dashboard HTTP listener + every credential-proxy 127.0.0.1 listener           |
| `raxis-otel-pusher` | 127.0.0.1 health endpoint                                                     |
| `raxis-live-e2e`    | Many short-lived 127.0.0.1 listeners for credential-proxy / gateway slice tests |

Binaries not in the list either do not bind any host TCP/UDP port
(`raxis`, `raxis-image-builder`, `raxis-verifier-stub`), only make
outbound HTTPS calls (`raxis-gateway`), are Linux-only at runtime
(`raxis-tproxy`), or are guest-VM binaries cross-compiled to
musl (`raxis-orchestrator`, `raxis-executor`, `raxis-reviewer`).

---

## How to undo

To remove a single binary from the firewall allowlist:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --remove \
  /path/to/raxis/target/debug/raxis-kernel
```

To remove every raxis entry, run `--remove` once per row reported by
`cargo xtask macos-firewall-status`, or just delete the entries from
`System Settings → Network → Firewall → Options...`.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `sudo -v` exits non-zero with `a password is required` | You are running on a managed device that disallows sudo. Ask your IT admin to mint a sudoers entry for `socketfilterfw`, or pass `--skip-firewall` to `cargo xtask dev-prereqs` and dismiss each popup manually. |
| `socketfilterfw: ... Operation not permitted` | The Application Firewall service is paused or the host has SIP off in a way that blocks `socketfilterfw` writes. Re-enable it from `System Settings → Network → Firewall`. |
| Popup STILL appears after the prereq ran | Confirm the binary path that was prompted for matches the row in `macos-firewall-status`. If the binary moved (e.g. you switched to a different worktree), re-run `cargo xtask macos-firewall-prereq` to add the new path. |
| `macos-firewall-prereq` reports `firewall disabled globally` | Your firewall is off; no popup will appear regardless. Re-enable the firewall from System Settings if you want enforcement; the subcommand intentionally does NOT toggle it on for you. |

---

## Why path-based instead of identity-based

Two strategies could fix this:

**Strategy A — per-binary path allowlist** (what this subcommand does).
Pros: works with vanilla `cargo build`, no per-build hooks, no
keychain manipulation. The `sudo` prompt is one-time. Cons: each
worktree's `target/` path needs its own entry; moving the workspace
re-prompts.

**Strategy B — stable self-signed code-signing identity**. The
operator mints a code-signing identity in their login keychain, every
`cargo build` output is re-signed against it, and the firewall
allowlist is keyed on the identity (which survives binary moves).
Pros: identity-based rules survive worktree migrations. Cons: stock
macOS has no one-shot CLI for minting a self-signed code-signing
identity (`Certificate Assistant.app` workflow plus `security import`),
every `cargo build` needs a per-build re-sign hook (`cargo xtask build`
that wraps `cargo build` with `codesign --sign <identity>`), and
managed devices may disallow keychain cert imports altogether.

This subcommand picks Strategy A as the default for developer
experience — Strategy B is documented as future work for operators
who want stable identity-based rules.

---

## What about packaged installers

Out of scope for this recipe. The `raxis kernel install` system-daemon
flow ([`recipes/setup/05-install-system-daemon.md`](05-install-system-daemon.md))
plus the eventual signed installer (per
[`specs/v2/release-and-distribution.md`](../../../specs/v2/release-and-distribution.md))
will Developer-ID-sign the kernel binary before it lands on the
operator's machine. For Developer-ID-signed binaries the firewall
trusts the identity for every future build of the same app, so the
popup never appears in the first place. This recipe is exclusively
for the local-development workflow where binaries are ad-hoc-signed.

---

## Reference

- [`xtask/src/macos_firewall.rs`](../../../xtask/src/macos_firewall.rs) —
  authoritative source of the binary inventory, the
  `socketfilterfw` invocation, and the strategy A vs B trade-off.
- [`xtask/src/dev_prereqs.rs`](../../../xtask/src/dev_prereqs.rs) —
  Step 7 of `dev-prereqs` calls `macos_firewall::run_prereq_as_dev_prereqs_step`.
- `man socketfilterfw` — Apple's user-space firewall control tool.

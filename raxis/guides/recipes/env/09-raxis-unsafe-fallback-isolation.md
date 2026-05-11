# `RAXIS_UNSAFE_FALLBACK_ISOLATION` — dev-only isolation override

> **Topic:** Environment variables | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐⭐ Expert

`RAXIS_UNSAFE_FALLBACK_ISOLATION` lets the kernel boot on a host
that lacks proper VM-level isolation (no KVM on Linux, no
Virtualization.framework on macOS). The kernel falls back to
**process-level isolation** (cgroups + namespaces on Linux,
mostly-unsandboxed processes on macOS) and emits one
`KernelIsolationFallbackUnsafe` audit event per session.

This is **not safe**. The kernel admits and runs work, but every
agent's "VM" is just a Linux process tree. Compromising an agent
can reach the kernel. Use only for development on a host where
KVM / AVF is genuinely unavailable.

---

## Read by

- `raxis-kernel` at boot.

---

## Values

| Value | Effect |
|---|---|
| (unset) | Kernel refuses to boot if isolation is unavailable. Exits with `BOOT_ERR_ISOLATION_UNAVAILABLE`. |
| any non-empty value | Kernel boots in fallback mode. Every session VM is a process tree. Audit chain emits `KernelIsolationFallbackUnsafe` at boot AND `SessionIsolationFallbackUnsafe` per session. |

---

## Companion variable

```text
RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON   (string)
```

A free-text reason that the kernel embeds into the audit event for
forensic record-keeping. **Strongly recommended whenever you set
the main flag** — without it the audit event has no operator
context.

---

## Set

```bash
# Foreground kernel, dev mode:
export RAXIS_UNSAFE_FALLBACK_ISOLATION=1
export RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON="laptop without KVM, dev sandbox 2026-05-10"
raxis-kernel
```

The kernel boots, prints a loud warning:

```text
{"level":"warn","event":"KernelIsolationFallbackUnsafe","reason":"laptop without KVM, dev sandbox 2026-05-10"}
```

…and the audit chain captures the event. `raxis status` reports
`isolation: fallback (unsafe)`.

---

## What "unsafe" actually means

| Property | Real isolation (KVM / AVF) | Fallback (process) |
|---|---|---|
| Kernel-level memory isolation | yes | no — agents share kernel address space with the supervisor process |
| Kernel-level CPU isolation | yes | partial (cgroup CPU quotas) |
| Kernel-level network isolation | yes (per-VM tap interface) | partial (network namespace + iptables) |
| Filesystem isolation | yes (ephemeral block device per VM) | partial (mount namespace + overlay) |
| /dev access | restricted to the VM device tree | partial — agents see a chrooted view but can probe `/sys`, `/proc` more aggressively |
| Compromise blast radius | scoped to the VM; kernel safe | reach **into** the kernel via shared mappings |

The audit chain still fires; the kernel still rejects forbidden
intents at the IPC layer. But an exploit chain that escapes the
agent's namespace can read kernel memory.

---

## When to use

- **Local development on a Linux box without `/dev/kvm`.** Common
  on cloud VMs that don't have nested virtualisation.
- **macOS Intel pre-13.** If you're stuck on a pre-Virtualization-
  framework macOS, this is the only path. Upgrade if at all
  possible.
- **CI runners without privileged-mode.** Some runner images don't
  expose `/dev/kvm`. The fallback lets them at least *exercise*
  RAXIS even if the isolation isn't real.

## When NOT to use

- **Production.** Never. The kernel's security model assumes
  VM-level isolation; the fallback breaks the model.
- **Touching real credentials / real LLM keys.** Don't. A
  compromised agent in fallback mode can probably read them.
- **"Just to make it boot" without understanding why.** Read what
  the kernel said first. `BOOT_ERR_ISOLATION_UNAVAILABLE` usually
  means a misconfigured `/dev/kvm` permission, fixable in seconds:
  `sudo usermod -aG kvm $USER` and re-login.

---

## Verifying you're in fallback mode

```bash
raxis status --json | jq '.isolation_mode'
# "fallback_unsafe"   ← in fallback mode
# "vm"                ← in proper isolation

raxis log --kind KernelIsolationFallbackUnsafe --limit 5
raxis log --kind SessionIsolationFallbackUnsafe --since 1h
```

The audit chain has both events; the kernel emits one
`KernelIsolationFallbackUnsafe` per boot and one
`SessionIsolationFallbackUnsafe` per session create.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `BOOT_ERR_ISOLATION_UNAVAILABLE` and you genuinely need to boot | Make sure KVM is available; if not, set `RAXIS_UNSAFE_FALLBACK_ISOLATION=1` AND `RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON="<reason>"`. |
| `BOOT_ERR_ISOLATION_UNAVAILABLE` but `/dev/kvm` exists | Permission issue. `ls -l /dev/kvm`; ensure your user is in the `kvm` group. Re-login. |
| `SessionIsolationFallbackUnsafe` events even after fixing KVM | Old kernel processes; restart the kernel after the fix. |
| Want to "silence" the warnings | You can't, by design. The warnings are the point — fallback is unsafe and the audit chain must record it. |

---

## Reference: related env vars + audit

| Surface | Purpose |
|---|---|
| `RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON` | Free-text reason embedded in the audit event. |
| `raxis status --json` reports `isolation_mode` | Current isolation regime. |
| `raxis log --kind KernelIsolationFallbackUnsafe` | Boot-time fallback events. |
| `raxis log --kind SessionIsolationFallbackUnsafe` | Per-session fallback events. |
| `BOOT_ERR_ISOLATION_UNAVAILABLE` | Kernel error when isolation is missing and fallback isn't enabled. |

---

## Variations

- **Always set the reason.** Audit attribution is the whole point;
  unset reason makes the event useless for post-hoc forensics.
- **Pair with explicit short TTLs.** In fallback mode, every
  session is unsafe; cap them aggressively (`[sessions]
  default_ttl_secs = 3600`) so the unsafe footprint is bounded.
- **Don't leave it set in `~/.bashrc`.** The variable is sticky;
  if you forget to unset it after the dev session, your next boot
  is also unsafe. Pin it in a script wrapper instead:
  `dev-raxis-kernel`.

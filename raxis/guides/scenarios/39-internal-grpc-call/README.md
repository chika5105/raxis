# Scenario 39 — Internal gRPC Call

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic

The Executor invokes an internal gRPC service via `grpcurl`, gated by
egress to `internal.example.com:443`.

---

## Prerequisites

Same as scenario 04. `grpcurl` on $PATH.

---

## Run it

Same skeleton as scenario 35.

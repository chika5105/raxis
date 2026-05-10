// ─────────────────────────────────────────────────────────────────
// SECURITY RATIONALE — Why this file was removed
// ─────────────────────────────────────────────────────────────────
//
// This module previously implemented in-browser Ed25519 signing via
// WebCrypto, allowing operators to paste their private key into a
// <textarea> on the login page. While the key never left the browser
// at the *network* layer, storing it in browser memory is a
// fundamentally weaker security posture than the CLI-mediated flow
// the V2 spec intended:
//
//   1. XSS exposure — Any cross-site scripting vulnerability on the
//      dashboard origin gives the attacker the raw private key bytes
//      (they sit in a React useState string, readable from the DOM
//      via document.querySelector("textarea").value and from the JS
//      heap via devtools or injected scripts).
//
//   2. Extension access — Browser extensions with "read all site
//      data" permissions can intercept the pasted text before it
//      reaches WebCrypto.
//
//   3. Clipboard history — The paste operation writes the key to the
//      OS clipboard, where it may persist in clipboard managers,
//      screen recordings, or accessibility tools.
//
//   4. No memory zeroing — JavaScript provides no mechanism to
//      overwrite a string's backing buffer. Once the key enters JS
//      heap memory, it remains there until garbage collection
//      (non-deterministic, potentially minutes).
//
//   5. extractable: true — The previous implementation imported the
//      key with `extractable: true` so it could derive the public
//      key via JWK export. This means any JS on the page could
//      re-export the CryptoKey object and exfiltrate it.
//
//   6. Audit-chain gap — RAXIS's audit chain can cryptographically
//      prove which operator signed a policy or approved an
//      escalation, but only if the signing happened in a controlled
//      environment. Browser-side signing provides no attestation
//      that the private key was protected at rest.
//
// The replacement flow (implemented in Login.tsx) follows the spec's
// §4.2 challenge-response design:
//
//   1. Browser requests a challenge from the kernel.
//   2. Operator signs the challenge OUTSIDE the browser using
//      `raxis auth sign <challenge>` on their local machine
//      (or hardware token).
//   3. Operator pastes only the SIGNATURE and PUBLIC KEY into the
//      browser — neither of which is secret.
//   4. Browser submits {challenge, signature, public_key} to the
//      kernel, which verifies and mints a JWT.
//
// The private key never enters browser memory, the DOM, the
// clipboard, or any JavaScript-accessible storage.
//
// ─────────────────────────────────────────────────────────────────

// This file is intentionally empty. It exists so that any stale
// imports (`import { signChallenge } from "@/lib/ed25519"`) produce
// a clear compile-time error rather than a mysterious runtime crash.
//
// If you are looking for the browser-side Ed25519 signing code that
// was here before, it was removed for the security reasons above.
// The login page now uses a two-step CLI-mediated flow.

export {};

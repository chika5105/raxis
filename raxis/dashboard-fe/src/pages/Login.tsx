// ─────────────────────────────────────────────────────────────────
// Login Page — CLI-mediated challenge-response auth
// ─────────────────────────────────────────────────────────────────
//
// SECURITY DESIGN (spec §4.2):
//
// The operator's Ed25519 private key MUST NEVER enter the browser.
// Previous versions of this page asked the operator to paste their
// private key into a textarea and signed the challenge via
// WebCrypto. That approach was replaced because:
//
//   • The private key sat in a React useState string — readable by
//     any XSS payload, browser extension, or devtools session.
//   • Pasting writes the key to OS clipboard history.
//   • JavaScript cannot zero memory; the key persists in heap until
//     GC (non-deterministic, potentially minutes).
//   • No attestation that the key was stored securely at rest.
//
// The new flow keeps the private key on the operator's machine:
//
//   Step 1 — Browser requests a challenge from the kernel.
//   Step 2 — Operator copies the challenge, signs it in their
//            terminal with `raxis auth sign <challenge>`.
//   Step 3 — Operator pastes the SIGNATURE (not the key) and their
//            PUBLIC KEY into the browser.
//   Step 4 — Browser submits {challenge, signature, public_key} to
//            the kernel, which verifies and mints a JWT.
//
// Only non-secret values (challenge, signature, public key) ever
// enter browser memory. The private key stays in the CLI process
// on the operator's machine (or hardware token) and is zeroed on
// exit.
// ─────────────────────────────────────────────────────────────────

import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { ApiError, authApi } from "@/api/client";
import { setStoredProfile, setStoredToken } from "@/lib/auth-store";
import { CopyButton } from "@/components/CopyButton";
import { Spinner } from "@/components/Spinner";

// ── Types ──────────────────────────────────────────────────────

type LoginStep = "idle" | "challenged" | "verifying";

// ── Helpers ────────────────────────────────────────────────────

const HEX_64 = /^[0-9a-fA-F]{64}$/;
const HEX_128 = /^[0-9a-fA-F]{128}$/;

/**
 * Basic shape validation — does the pasted text look like a
 * 64-char (32-byte) hex public key?
 */
function isPlausiblePubkey(s: string): boolean {
  return HEX_64.test(s.trim());
}

/**
 * Basic shape validation — does the pasted text look like a
 * 128-char (64-byte) hex Ed25519 signature?
 */
function isPlausibleSignature(s: string): boolean {
  return HEX_128.test(s.trim());
}

// ── Component ──────────────────────────────────────────────────

export function LoginPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const next = params.get("next") || "/";

  // Step state.
  const [step, setStep] = useState<LoginStep>("idle");
  const [challenge, setChallenge] = useState("");
  const [expiresAt, setExpiresAt] = useState(0);

  // Operator-supplied values (non-secret).
  const [signature, setSignature] = useState("");
  const [publicKey, setPublicKey] = useState("");

  // UI state.
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // ── Step 1: Request a challenge ────────────────────────────

  const onRequestChallenge = async () => {
    setError(null);
    setBusy(true);
    try {
      const resp = await authApi.challenge();
      setChallenge(resp.challenge);
      setExpiresAt(resp.expires_at);
      setStep("challenged");
    } catch (e) {
      if (e instanceof ApiError) {
        setError(`${e.code}: ${e.detail}`);
      } else if (e instanceof Error) {
        setError(e.message);
      } else {
        setError("failed to fetch challenge");
      }
    } finally {
      setBusy(false);
    }
  };

  // ── Step 2+3: Verify the operator's signature ──────────────

  const onVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const sig = signature.trim();
    const pk = publicKey.trim();

    if (!isPlausibleSignature(sig)) {
      setError("Signature must be 128 hex characters (64 bytes).");
      return;
    }
    if (!isPlausiblePubkey(pk)) {
      setError("Public key must be 64 hex characters (32 bytes).");
      return;
    }

    setBusy(true);
    setStep("verifying");
    try {
      const verified = await authApi.verify({
        challenge,
        signature: sig,
        public_key: pk,
      });
      setStoredToken(verified.token);
      setStoredProfile({
        operator_id: verified.operator_id,
        display_name: verified.display_name,
        roles: verified.roles,
        expires_at: verified.expires_at,
      });
      navigate(next, { replace: true });
    } catch (e) {
      setStep("challenged"); // Let them retry.
      if (e instanceof ApiError) {
        setError(`${e.code}: ${e.detail}`);
      } else if (e instanceof Error) {
        setError(e.message);
      } else {
        setError("verification failed");
      }
    } finally {
      setBusy(false);
    }
  };

  // ── Challenge freshness check ──────────────────────────────

  const challengeExpired =
    expiresAt > 0 && Math.floor(Date.now() / 1000) >= expiresAt;

  // Computed CLI command for the operator to copy.
  const cliCommand = `raxis auth sign ${challenge}`;

  // ── Render ─────────────────────────────────────────────────

  return (
    <div className="min-h-screen flex items-center justify-center bg-panel grid-overlay">
      <div className="w-full max-w-lg card p-6">
        {/* ── Header ── */}
        <div className="flex items-center gap-3 mb-5">
          <img src="/raxis-logo.svg" alt="Raxis" className="w-10 h-10 rounded-md" />
          <div>
            <h1 className="text-base font-semibold text-ink">
              Raxis Operator Dashboard
            </h1>
            <p className="text-xs text-ink-subtle">
              Challenge-response authentication
            </p>
          </div>
        </div>

        {/* ── Step 1: Request challenge ── */}
        {step === "idle" && (
          <div className="space-y-3">
            <p className="text-sm text-ink-muted leading-relaxed">
              Click below to request a one-time challenge from the kernel.
              You'll sign it with your Ed25519 operator key in your terminal —
              the private key never enters the browser.
            </p>
            <button
              type="button"
              onClick={onRequestChallenge}
              disabled={busy}
              className="btn-primary w-full justify-center"
            >
              {busy ? (
                <>
                  <Spinner className="w-4 h-4" /> Requesting…
                </>
              ) : (
                "Request Challenge"
              )}
            </button>
          </div>
        )}

        {/* ── Step 2: Show challenge + sign instructions ── */}
        {(step === "challenged" || step === "verifying") && (
          <form onSubmit={onVerify} className="space-y-4">
            {/* Challenge display */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium text-ink-muted">
                  1. Sign this challenge in your terminal
                </span>
                {challengeExpired && (
                  <span className="badge border-bad text-bad text-[10px]">
                    Expired
                  </span>
                )}
              </div>
              <div className="bg-panel border border-edge-strong rounded-md px-3 py-2 font-mono text-xs text-ink flex items-start gap-2">
                <code className="flex-1 break-all select-all">
                  {cliCommand}
                </code>
                <CopyButton value={cliCommand} label="Copy sign command" />
              </div>
              <p className="mt-1.5 text-[11px] text-ink-subtle leading-relaxed">
                Run the command above on the machine where your private key is stored.
                It will output a <strong>signature</strong> and your <strong>public key</strong>.
                Paste them below.
              </p>
            </div>

            {/* Signature field */}
            <label className="block">
              <span className="block text-xs font-medium text-ink-muted mb-1">
                2. Signature{" "}
                <span className="text-ink-subtle font-normal">
                  (128 hex chars)
                </span>
              </span>
              <input
                type="text"
                required
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                className="input w-full font-mono text-xs"
                placeholder="Paste the signature hex from `raxis auth sign`"
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
              />
            </label>

            {/* Public key field */}
            <label className="block">
              <span className="block text-xs font-medium text-ink-muted mb-1">
                3. Public key{" "}
                <span className="text-ink-subtle font-normal">
                  (64 hex chars)
                </span>
              </span>
              <input
                type="text"
                required
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                className="input w-full font-mono text-xs"
                placeholder="Paste your Ed25519 public key hex"
                value={publicKey}
                onChange={(e) => setPublicKey(e.target.value)}
              />
            </label>

            {/* Verify button */}
            <button
              type="submit"
              disabled={
                busy ||
                challengeExpired ||
                signature.trim().length === 0 ||
                publicKey.trim().length === 0
              }
              className="btn-primary w-full justify-center"
            >
              {busy ? (
                <>
                  <Spinner className="w-4 h-4" /> Verifying…
                </>
              ) : (
                "Verify & Sign In"
              )}
            </button>

            {/* Refresh challenge link */}
            {challengeExpired && (
              <button
                type="button"
                onClick={() => {
                  setStep("idle");
                  setChallenge("");
                  setSignature("");
                  setPublicKey("");
                  setError(null);
                }}
                className="text-xs text-accent hover:underline w-full text-center"
              >
                Challenge expired — request a new one
              </button>
            )}
          </form>
        )}

        {/* ── Error display ── */}
        {error && (
          <div className="mt-3 card border-bad/40 p-3 text-sm text-bad">
            {error}
          </div>
        )}

        {/* ── Security footer ── */}
        {/*
          This notice is important for operator confidence: it makes
          the security model explicit and distinguishes this flow from
          the previous insecure "paste your private key" design.
        */}
        <div className="mt-4 pt-4 border-t border-edge text-[11px] text-ink-subtle space-y-2">
          <p>
            <strong className="text-ink-muted">🔒 Zero-knowledge auth:</strong>{" "}
            Your private key never enters the browser. Only the signature and
            public key — both non-secret — are submitted for verification.
          </p>
          <p>
            Dashboard runs read-only against the kernel store, with one
            scoped write surface (<code className="font-mono">PUT /api/policy/toml</code>)
            available to operators with the{" "}
            <code className="font-mono">write_policy</code> role.
          </p>
        </div>
      </div>
    </div>
  );
}

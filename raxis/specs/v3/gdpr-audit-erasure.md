# RAXIS V3 — GDPR Audit Chain Erasure (Early Idea)

> **Status:** Exploratory — needs significantly more thought before committing to an approach.
> **Depends on:** [`audit-retention.md`](audit-retention.md) (V3 Merkle audit format)
> **R-invariant tension:** R-7 (Cryptographic Audit Chain) is append-only and hash-chained. GDPR Article 17 (right to erasure) requires deletion of personal data on request. These two properties are in direct conflict.

---

## §1 — The Problem

RAXIS's audit chain is structurally append-only. Each record's hash covers its content and chains to the previous record's hash. Deleting a record breaks the chain — every subsequent `prev_hash` becomes invalid, and the entire chain fails verification.

If a data subject (operator, individual mentioned in a task description or code diff) invokes their right to erasure, we cannot simply remove their data from the chain without destroying the integrity guarantee that R-7 exists to provide.

---

## §2 — One Possible Approach: Crypto-Shredding

The idea is to encrypt personal data fields at write time with a per-subject key, and "erase" by destroying the key.

1. At write time, personal data in audit records is encrypted with a per-subject key before appending. The record hash covers the ciphertext, not the plaintext.
2. At deletion time, the per-subject key is destroyed. The audit record remains in the chain (hash integrity preserved), but the personal data becomes irrecoverable ciphertext.
3. A `SubjectKeyDestroyed` tombstone event is appended to the chain, recording that erasure occurred without breaking the chain.

### Pros

- **Chain integrity preserved.** No record is removed; `prev_hash` references still resolve. Verifiers can walk the chain and confirm structural integrity.
- **Legally defensible.** Crypto-shredding is an accepted GDPR erasure mechanism — if the key is destroyed and the cipher is strong (AES-256-GCM), the data is computationally irrecoverable.
- **Auditable erasure.** The tombstone event proves deletion happened, which is itself a GDPR requirement (you must be able to demonstrate compliance).

### Cons

- **Complexity.** Adds envelope encryption, key management (KMS integration or local keyring), and per-subject key indexing to what is currently a simple JSONL append.
- **Performance overhead.** Every audit write now includes an encrypt step. Every audit read (for non-erased subjects) includes a decrypt step. For high-throughput kernels this may matter.
- **Subject identification is hard.** Operators are cleanly identifiable by Ed25519 pubkey. But individuals mentioned in task descriptions, commit messages, or code diffs require PII detection — a content-scanning problem that is unsolved in the general case.
- **Key lifecycle.** Who holds the keys? Where are they stored? How are they backed up? If the key store is lost, all personal data in the audit chain becomes permanently unreadable — even for the operator who wrote it.
- **Partial erasure.** A single audit record may reference multiple subjects (e.g. a review critique mentioning two developers). Encrypting at the field level with different subject keys adds schema complexity.

---

## §3 — Is This Needed Now?

**Probably not.**

RAXIS V2 audit records contain:

- **Operator identity:** Ed25519 public key (not personally identifying on its own — it's a cryptographic key, not a name or email).
- **Task descriptions:** Operator-authored text. May or may not contain personal data depending on what the operator writes.
- **Code diffs / commit messages:** Content from the repository being worked on. PII presence depends entirely on the codebase.
- **Model responses:** LLM output. Unlikely to contain PII unless the task description fed PII into the prompt.

In practice, RAXIS's audit chain is operationally closer to a **system log** than a **user database**. The primary data subjects are operators (who consented to using the system) and the content is mostly code, not personal data. GDPR's "right to erasure" has exceptions for data required for legal compliance, and audit logs often fall under that exception.

The scenario where this matters is:
- A regulated enterprise using RAXIS where task descriptions contain customer names, case IDs, or other PII
- An operator who leaves the organisation and requests full data erasure
- A jurisdiction that does not recognize the "legal compliance" exception for audit logs

None of these are blocking V2 or V3 launch. This is a **V4+ concern** that should be revisited once there are real enterprise deployments with actual GDPR obligations.

---

## §4 — Open Questions (For Future Work)

1. Is crypto-shredding the right approach, or should we explore **redaction with re-signing** (rewrite the chain segment with redacted content and re-compute hashes)?
2. Should subject keys be per-operator, per-initiative, or per-record?
3. Does the KMS dependency contradict RAXIS's "runs anywhere, no cloud services required" principle?
4. Is field-level encryption practical, or should entire records be encrypted?
5. Should PII tagging happen at write time (operator declares which fields contain PII) or at read time (content scanning)?
6. Do we even need this if RAXIS positions audit logs under GDPR's Article 17(3)(e) exemption (processing necessary for legal claims)?

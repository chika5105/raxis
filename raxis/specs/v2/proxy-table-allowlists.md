# RAXIS V2 — Database-Proxy Table-Level Allowlists & Result-Size Caps

> **Status.** Normative for V2 (this PR ships it). Promotes the
> deferred-V3 surface called out at the end of `credential-proxy.md
> §14.8` (per-proxy implementation matrix) into V2 scope at the
> *table / collection* granularity. Per-column scoping is explicitly
> rejected as proxy work and pushed to database-native `GRANT` /
> view-based controls per §1.3.
>
> **Audience.** Operators authoring `[tasks.credentials.restrictions]`
> blocks; reviewers grading the proxy implementation; auditors
> verifying the SQL / BSON walker reads.
>
> **Cross-references:**
> - [`credential-proxy.md`](credential-proxy.md) §4 (per-proxy wire shapes), §5 (audit
>   envelopes), §14 (real-upstream-forwarding contract), §14.8
>   (per-proxy implementation matrix) — this spec amends the matrix
>   rows for `postgres`, `mysql`, `mssql`, `mongodb`.
> - `raxis-concepts/03-credential-proxies.md` — the conceptual
>   "allowed_tables / allowed_collections / max_rows_per_query"
>   surface that operators see; this spec is the wire- and audit-
>   level normative companion.
> - `invariants.md` — adds `INV-PROXY-TABLE-01..06`; companions to
>   the existing `INV-CRED-KERNEL-01` "no credential bytes in VM"
>   discipline.
> - [`audit-paired-writes.md`](audit-paired-writes.md) — the proxy events this spec extends
>   (`DatabaseQueryExecuted`, `DatabaseQueryCompleted`,
>   `MongoCommandExecuted`) are pre-tx single-class observability
>   events; the pairing model is unchanged.
> - `paradigm.md` — `R-2 Mediated I/O`, `R-5 Bounded Capabilities`,
>   `R-6 Fail-Closed Default`, `R-8 Auditable Decisions`. This spec
>   strengthens `R-5` for the credential-proxy capability surface.

---

## §1 — Why this spec

### 1.1 The gap V2.1 closed and the gap this spec closes

[`credential-proxy.md`](credential-proxy.md) §14 (V2.1 real-upstream forwarding) shipped
proxies that:

1. Authenticate to the real upstream with the operator-declared
   credential the agent never sees.
2. Classify the operation surface (SQL first-token, Mongo
   first-BSON-field-name).
3. Block whole *operation classes* with `allow_only_select` (SQL)
   or `allow_read_only` (Mongo).
4. Audit every classified message with
   `DatabaseQueryExecuted { sql_sha256, operation, blocked }` /
   `MongoCommandExecuted { command, body_sha256, blocked }` and
   pair each forwarded query with a `DatabaseQueryCompleted`
   carrying `rows_returned` from the upstream.

That surface bounds **what verbs the agent can use**. It does not
bound **which database objects those verbs touch** or **how big a
result set the agent can drain**. A read-only agent with
`allow_only_select = true` can still:

- `SELECT * FROM users_pii`
- `SELECT * FROM payment_cards`
- `SELECT * FROM events_audit` and exfiltrate every row at once,
  saturating the egress channel before the operator notices.

The V1.2 reference implementation surfaced this gap inline in the
MongoDB proxy comment `crates/credential-proxy-mongodb/src/wire.rs`
lines 34–37 ("V3 will walk the full BSON tree to enforce
`forbidden_collections` and `max_documents`") and in the V2.1
implementation matrix ("Deferred V3: `forbidden_tables`,
`max_result_rows`, ..."). This spec promotes those items into V2 at
the table / collection granularity and pins them as **mandatorily
ship-blocking** for the proxy capability.

### 1.2 What this spec adds

For SQL proxies (Postgres, MySQL, MSSQL):

- `[tasks.credentials.restrictions] allowed_tables`  — explicit
  per-credential **allowlist** of qualified table names the
  agent's queries may reference. Empty = unrestricted (matches V2.1
  behaviour).
- `[tasks.credentials.restrictions] forbidden_tables` — explicit
  per-credential **denylist**. Applied after `allowed_tables`. Empty
  = no denylist.
- `[tasks.credentials.restrictions] max_result_rows` — upper bound
  on row count returned by an audited query. `0` = uncapped; `N` =
  proxy terminates the result-set stream after the Nth row and
  emits an `ErrorResponse` / `ERR_Packet` / TDS `ERROR` token to
  the agent.

For the MongoDB proxy:

- `[tasks.credentials.restrictions] allowed_collections` — explicit
  per-credential **allowlist** of fully-qualified `<db>.<coll>`
  collection names. Empty = unrestricted.
- `[tasks.credentials.restrictions] forbidden_collections` —
  explicit denylist. Applied after `allowed_collections`.
- `[tasks.credentials.restrictions] max_documents` — upper bound
  on document count returned by an audited `find` / `aggregate` /
  `getMore` reply. `0` = uncapped.

These six fields are the **entire V2 surface added by this spec**.
No new audit-event variants are introduced; the existing
`DatabaseQueryExecuted` / `MongoCommandExecuted` / `DatabaseQueryCompleted`
shapes are *extended* with two new fields each as documented in §8.

### 1.3 Why the proxy stops at the table boundary (rejected designs)

A reviewer reading this spec will reasonably ask "why not per-column
allowlists?" The candidate designs and the rejection rationale:

| Candidate | Why rejected |
|---|---|
| **Per-column allowlist enforced by the proxy** — the proxy parses every SELECT/UPDATE column list and validates each against an operator-declared list. | The proxy would re-implement what the database engine already does perfectly via `GRANT SELECT (col1, col2) ON tbl TO role`. Re-implementing column resolution correctly across SQL dialects (computed columns, generated columns, `*` expansion, CTE-projected columns, subquery projections, view-derived columns, `SELECT t.*`, `RETURNING` clauses, `JOIN USING (...)`, `GROUP BY ... ROLLUP`) requires a real SQL parser per dialect. The classified failure mode is "the proxy parses 99% of column references correctly; the 1% leaks". Database engines run the canonical parser; the operator path to **zero proxy gaps + 100% engine-side coverage** is to issue a database-native grant on the operator-declared role and stop trying. |
| **Row-level filter rewriting** — proxy rewrites every SELECT to inject `WHERE` predicates ("multi-tenant agent — only rows where `tenant_id = $session_id`"). | Same parser-correctness problem amplified by the rewrite (incorrect rewrites can *return* data the operator did not authorise, an INV-EGRESS-style failure). Database engines have row-security policies (`CREATE POLICY` in Postgres, "row-level security" in MSSQL); operators wanting row-level scoping declare a policy on the real role and the proxy is unchanged. |
| **Semantic-result inspection** — proxy peeks into the relayed row bytes and rewrites / drops fields. | Forces the proxy to understand wire-format type codes (Postgres OID-typed data, MySQL column-type bytes, MSSQL `COLMETADATA` packets, MongoDB BSON value parsing) and re-emit valid wire frames. The current relay-verbatim path is one of the few places where a single bug cannot corrupt result bytes; semantic inspection forfeits that property. |
| **Treat `forbidden_tables` as a full *parser*-based check** — proxy parses the query AST and validates every relation reference, including aliases, view-derived references, CTE-projected references, and function arguments that return tables. | Same dependency-on-parser-correctness problem. The spec adopts the *adversarial-conservative tokenizer* approach below (§5): if the proxy cannot recognise the relation list with high confidence, the query is **rejected** rather than admitted. This makes "the proxy got fooled and admitted a forbidden table" structurally impossible (the fail-closed default of `R-6`) at the cost of "the proxy got confused and rejected a query it should have admitted" (fail-loudly; operator iterates on the SQL or widens the allowlist). |

The principle the spec encodes:

> **The proxy enforces object-name allowlisting at the granularity
> the proxy can reliably extract from the wire.** Anything finer
> than the table / collection boundary is the responsibility of the
> database engine's own access-control surface and is documented in
> §13 as the operator's playbook.

### 1.4 What V3 still owes

Even with this spec shipped, V3 is still on the hook for:

- **Extended-query path coverage** (Postgres `Parse`/`Bind`/`Execute`,
  MySQL `COM_STMT_PREPARE`/`COM_STMT_EXECUTE`, MSSQL `RPC`). V2
  enforces the table allowlist on the *simple-query* / `SQLBatch`
  path; prepared statements that bypass the simple path return
  `0A000` / `1295` / `0x05` (`feature_not_supported`) as today,
  unchanged.
- **Full BSON tree walker for nested `$lookup` collection
  references and `aggregate` pipelines that fan out across more
  than one collection.** V2 walks the first kind-0 BSON section
  to read the *primary* collection name (e.g. `{ "find": "users",
  ...}` → `users`) plus the kind-1 sequence headers for batched
  writes. Pipelines that name a *second* collection via
  `$lookup.from` / `$graphLookup.from` / `$unionWith.coll` /
  `$merge.into` / `$out` are rejected by the V2 proxy with
  `code: 13 (Unauthorized)` when *any* allowlist or denylist is
  configured, because the V2 walker cannot prove the secondary
  collection is permitted. The V2 proxy emits an audit event
  recording the rejection reason and the
  `MongoCommandExecuted { blocked: true, restriction_reason:
  "secondary_collection_in_pipeline" }`; V3 will land the full
  walker and admit the per-pipeline allowlist. Operators with
  `$lookup`-heavy workloads stage to V3 or use a database-side
  view that pre-joins the data.
- **Statement-timeout enforcement** (`statement_timeout_ms`) — V3.

These deferrals are listed in §11.3.

---

## §2 — Scope

### In scope

- TOML schema additions for the four database proxy types (§4).
- The first-statement-only SQL relation walker (§5).
- The first-section BSON command walker (§6).
- The streaming result-cap enforcer (§7).
- The audit-event field additions (§8).
- The wire-shape error responses each proxy emits when a query is
  blocked (§9).
- The `ProxyStats` counter additions (§10).
- The per-proxy implementation matrix update (§11).
- The cross-spec amendments ([`credential-proxy.md`](credential-proxy.md),
  `03-credential-proxies.md`, [`V2_STATUS.md`](V2_STATUS.md)) (§16).

### Out of scope

- **Per-column allowlisting** — rejected per §1.3.
- **Row-level security rewriting** — rejected per §1.3.
- **Extended-query / prepared-statement protocol coverage** —
  deferred to V3 per §1.4.
- **`$lookup` / multi-collection aggregate** pipelines for
  MongoDB — the V2 walker only proves the *primary* collection;
  pipelines that name a second collection are *rejected* when any
  allowlist or denylist is configured (§6.3). Admitting them is
  V3 walker work.
- **`statement_timeout_ms` / `op_timeout_ms`** — deferred to V3.
- **`forbidden_schemas`** (Postgres `pg_catalog`, MSSQL
  `INFORMATION_SCHEMA`) — handled implicitly by table-level
  allowlist (the operator declares the qualified table) and
  database-native GRANTs.

---

## §3 — Foundational Decisions

The decisions below are normative.

| # | Decision | Rationale |
|---|----------|-----------|
| **D1** | **`allowed_tables` is an allowlist; `forbidden_tables` is a denylist; both can coexist.** When both are non-empty, a query is admitted only if **every** referenced table is in `allowed_tables` **and** no referenced table is in `forbidden_tables`. The denylist short-circuits the allowlist. | Operators declare the surface they intend (the allowlist) and pin a few high-sensitivity tables they *also* want defended even if a future allowlist edit drops them in (the denylist). Composing the two is well-defined; operators that want pure allowlist semantics leave `forbidden_tables` empty. |
| **D2** | **Empty `allowed_tables` means "no allowlist enforced".** A credential block with `allowed_tables = []` permits any table the agent's SQL references (subject to `forbidden_tables` and `allow_only_select` if set). | Backwards-compatible default; existing V2.1 plans keep working. Operators who want allowlist semantics must declare them — fail-loud rather than fail-silent enrolment in a tighter regime. |
| **D3** | **`allowed_tables` entries match on `<schema>.<table>` (qualified) when the entry contains a dot, and on bare table name otherwise.** Postgres / MSSQL / MySQL schema qualification is preserved; comparisons are **case-sensitive on the table component and case-insensitive on the schema component** to match each engine's canonical resolution rules (Postgres treats unquoted identifiers as lowercase; MySQL/MSSQL identifiers are case-insensitive on Windows and case-sensitive elsewhere). Operators authoring `policy.toml` SHOULD use lowercase qualified names. | A single rule that admits the most common operator authoring shape (lowercase qualified names) without forcing the operator to enumerate every case variation. Mixed-case identifiers that need exact preservation can be quoted in the SQL and operator-declared verbatim. |
| **D4** | **Adversarial-conservative SQL parsing: if the walker cannot identify the relation list with high confidence, the query is rejected.** Specifically: `EXEC`/`EXECUTE` of dynamic SQL strings (MSSQL `EXEC sp_executesql`, Postgres `DO`/`PREPARE`, MySQL `PREPARE`/`EXECUTE`) is rejected whenever **any** allowlist is configured. Multi-statement `;`-separated batches are rejected whenever **any** allowlist is configured. | The walker is intentionally simple (§5). Rejecting the cases where the walker cannot prove the relation list lets the proxy claim "every admitted query touches only allowlisted tables" as a structural property, not a best-effort. Operators with prepared-statement workloads either drop the allowlist or wait for V3. |
| **D5** | **`max_result_rows` is enforced as a streaming hard-cap, not a `LIMIT N` injection.** The proxy counts rows as it relays them and terminates the result-set stream after the Nth row with a wire-format error frame plus a clean `ReadyForQuery` / `OK_Packet` / `DONE`. The agent observes a real error, not a silent truncation. | `LIMIT N` injection requires SQL rewriting (D4-style fragility). Streaming counts work the same way across every dialect, can be enforced uniformly, and surface the cap visibly to the agent so the operator gets the exfiltration alarm rather than a quiet success. |
| **D6** | **Restriction violations short-circuit before any upstream contact for the *first* statement; result-cap violations occur after partial upstream data has been relayed.** The first-statement-only rule means the upstream sees the query verbatim (and is the canonical source of truth for ambiguous syntax) iff the walker admits it; the streaming cap means the upstream has already started replying, which is fine because the cap surface is "agent observed at most N rows" not "upstream returned at most N rows". | The two enforcements operate at different layers (admission vs. relay); separating them lets the admission path stay strict and the relay path stay protocol-faithful. The audit chain captures both via the existing `DatabaseQueryExecuted { blocked: bool }` plus `DatabaseQueryCompleted { rows_returned, upstream_error }` events. |
| **D7** | **Each proxy emits two new optional audit fields and one rejection-reason enum.** `DatabaseQueryExecuted` gains `tables_referenced: Vec<String>` (the walker's extracted list) and `restriction_reason: Option<String>`. `MongoCommandExecuted` gains `collection: Option<String>` and `restriction_reason: Option<String>`. The enum values are a stable closed set documented in §8.2. | One audit-event variant per proxy; no schema explosion. The closed enum lets audit consumers grep for specific failure classes (`"table_not_in_allowlist"`, `"max_result_rows_exceeded"`) without parsing English error text. |
| **D8** | **The operator can `audit-only` a restriction by declaring `allowed_tables` / `forbidden_tables` / `allowed_collections` / `forbidden_collections` and setting `enforce = false` (defaults to `true`).** When `enforce = false`, the proxy still walks the SQL / BSON, still records the restriction outcome in the audit chain, but admits the query and lets the upstream respond. | New restrictions are most safely rolled out by first *observing* them in the audit chain across the agent's actual workload; D8 makes that the easy path. Production plans set `enforce = true` after audit data confirms no false positives. |
| **D9** | **Defaults for `max_result_rows` / `max_documents` are 0 (uncapped) under V2.** Future RAXIS releases may flip the default to a finite ceiling; the change is a deliberate spec amendment and ships with a clearly-numbered annotation version so operators can diff "what does v0.6.0 cap by default that v0.5.0 didn't?". | Backwards compatibility with V2.1 plans. Operators who want a cap declare it. |

---

## §4 — Operator Surface (TOML schema)

### 4.1 Postgres / MySQL / MSSQL

The three SQL proxies share the same restriction schema:

```toml
[[tasks.credentials]]
name       = "postgres-prod-readonly"
proxy_type = "postgres"               # "mysql" / "mssql" identical
mount_as   = "DATABASE_URL"

[tasks.credentials.restrictions]
# Verb-class allowlist (V2.1; unchanged by this spec).
allow_only_select = true

# NEW in V2 — this spec.
#
# `allowed_tables` is an allowlist. Empty = no allowlist enforced.
# Entries match qualified (`schema.table`, case-insensitive schema,
# case-sensitive table) or bare (`table`, case-rules per D3).
allowed_tables = [
    "public.users",
    "public.orders",
    "reporting.daily_summary",
]

# `forbidden_tables` is a denylist applied after the allowlist.
# Empty = no denylist.
forbidden_tables = [
    "public.users_pii",
    "public.payment_cards",
]

# `max_result_rows` is a streaming hard-cap. 0 = uncapped.
max_result_rows = 100000

# When `enforce = false`, the proxy walks the SQL and records the
# decision in the audit chain but does NOT block. Useful for
# rolling out a tighter allowlist by first observing audit data.
# Default = true (block on violation).
enforce = true
```

### 4.2 MongoDB

```toml
[[tasks.credentials]]
name       = "mongo-prod-readonly"
proxy_type = "mongodb"
mount_as   = "MONGODB_URI"

[tasks.credentials.restrictions]
# Verb-class allowlist (V2.1; unchanged by this spec).
allow_read_only = true

# NEW in V2 — this spec.
#
# `allowed_collections` is an allowlist of fully-qualified
# `<db>.<coll>` names. Empty = no allowlist enforced.
allowed_collections = [
    "appdb.users",
    "appdb.orders",
    "analytics.daily_rollup",
]

# `forbidden_collections` is a denylist applied after the
# allowlist. Empty = no denylist.
forbidden_collections = [
    "appdb.users_pii",
    "appdb.payment_cards",
]

# `max_documents` is a streaming hard-cap on documents returned
# by `find` / `aggregate` / `getMore`. 0 = uncapped.
max_documents = 100000

# When `enforce = false`, the proxy walks the BSON and records the
# decision in the audit chain but does NOT block. Default = true.
enforce = true
```

### 4.3 Schema notes

- All four new fields default to their permissive value (`[]` /
  `0` / `true`) so V2.1 plans keep working without a `plan prepare`
  pass. `plan prepare` (per [`operator-ergonomics.md §4`](operator-ergonomics.md)) does NOT
  populate any of these fields; operators declare them
  explicitly.
- The `enforce` field is **per-credential**, not per-restriction.
  An operator who wants to audit-only the table allowlist while
  enforcing `allow_only_select` MUST split the credential into two
  declarations (one with the verb restriction enforced, one with
  the allowlist `enforce = false`). This is intentional: a
  per-restriction-axis `enforce` matrix is more flexible but also
  drastically harder to reason about for the operator; the
  per-credential `enforce` is what existing field surfaces
  resemble.

---

## §5 — SQL Relation-Reference Walker

### 5.1 Algorithm

Given a SQL statement string, the walker returns a typed
`RelationList` enum:

```rust
pub enum RelationList {
    /// Walker proved the set of referenced tables with high
    /// confidence; restrictions may be checked against this list.
    Resolved(Vec<QualifiedName>),
    /// Walker could not prove the set (multi-statement batch,
    /// dynamic SQL, malformed input). Restrictions that demand
    /// proof MUST reject the query under D4.
    Ambiguous { reason: AmbiguityReason },
}

pub enum AmbiguityReason {
    /// `;`-separated batch with > 1 statement.
    MultiStatementBatch,
    /// `EXEC` / `EXECUTE` / `PREPARE` / `DO` of dynamic SQL.
    DynamicSql,
    /// Walker reached an unbalanced paren / unterminated string.
    Malformed,
}

pub struct QualifiedName {
    /// Optional schema qualifier (lowercased per D3).
    pub schema: Option<String>,
    /// Table identifier (case preserved per D3).
    pub table:  String,
}
```

Resolution steps for a single-statement SELECT/INSERT/UPDATE/DELETE
(stripped of leading whitespace, line comments, and block comments
by the V2.1 tokenizer):

1. **Verb dispatch**: classify the first keyword (already done by
   `classify_first_operation`); the relation list extractor branches
   on `SELECT|WITH|EXPLAIN|VALUES|TABLE|SHOW|INSERT|UPDATE|DELETE`
   and rejects everything else as `AmbiguityReason::DynamicSql` if
   an allowlist is configured (operators wanting DDL must drop the
   allowlist or wait for V3).
2. **For `SELECT` / `WITH ... SELECT`**: walk the token stream
   recording every relation reference. A relation reference is the
   identifier(s) that follow:
   - `FROM` (top-level or inside subqueries)
   - `JOIN` (any variant: `INNER`, `LEFT`, `RIGHT`, `FULL`, `CROSS`,
     `NATURAL`)
   - `USING` (when followed by `(...)` it's a column list, not a
     relation; skip)
   - `INTO` only when the SELECT is `SELECT ... INTO <table> FROM
     ...` (Postgres "SELECT INTO TABLE" form; MSSQL accepts the
     same)
3. **For `INSERT INTO <table>` / `INSERT INTO <table>(cols) VALUES
   / SELECT ...`**: the target table is the identifier after
   `INTO`, *plus* every relation in the trailing `SELECT` subquery
   (if any).
4. **For `UPDATE <table> SET ... [FROM <other>] WHERE ...`**: the
   target table is the identifier after `UPDATE`; the optional
   `FROM` clause (Postgres syntax) is walked the same way as
   `SELECT`.
5. **For `DELETE FROM <table> [USING <other>] WHERE ...`**: the
   target is the identifier after `FROM`; the optional `USING`
   clause is walked.
6. **For `EXPLAIN ... <inner>`**: the inner statement is walked
   per the above.
7. **For `WITH ... AS (...)`**: the CTE bindings are walked first;
   the trailing statement is walked per the above. Self-references
   to CTE names *are not* treated as table references (CTE names
   live in a separate namespace from real tables) — the walker
   records the CTE names defined and excludes them from the
   reported relation list.

Identifier parsing inside the walker:

- Bare identifiers `[A-Za-z_][A-Za-z0-9_]*` are read directly.
- Double-quoted identifiers `"..."` are read verbatim with case
  preserved.
- Backtick identifiers `` `...` `` (MySQL) are read verbatim.
- Bracketed identifiers `[...]` (MSSQL) are read verbatim.
- Schema qualification `schema.table` consumes both components;
  cross-database qualification `db.schema.table` (MSSQL,
  MySQL) treats the trailing two components as `schema.table` and
  ignores the leading `db` (the proxy already pins the agent to a
  single database via the upstream URL).
- A function-call shape `<name>(...)` is *not* a relation
  reference and is skipped along with its argument list.

### 5.2 Ambiguity → rejection

Any of the following yields `RelationList::Ambiguous`:

- The statement contains `;` followed by any non-whitespace
  characters (multi-statement batch). Trailing `;` is allowed.
- The first keyword is `EXEC`, `EXECUTE`, `PREPARE`, `EXECUTE
  IMMEDIATE`, `CALL` (stored procedure invocation), `DO`,
  `DECLARE`, or `SET` (when followed by SQL-like content the
  walker would have to parse).
- An unterminated string literal or unbalanced `(`/`)` /
  `[`/`]` / `` ` ``/`` ` ``.

When the restriction set contains any non-empty `allowed_tables`
or any non-empty `forbidden_tables`, `RelationList::Ambiguous`
queries are **rejected** with the wire-format error of §9 and
audited with `restriction_reason = "ambiguous_sql_<reason>"`. When
both lists are empty the ambiguity is admitted (the proxy reverts
to V2.1 behaviour).

### 5.3 Allowlist check

```text
Given:
  R = walker output (RelationList::Resolved(tables))
  A = allowed_tables (Vec<QualifiedName>)
  F = forbidden_tables (Vec<QualifiedName>)

Decision:
  IF F is non-empty AND any t in R matches any f in F:
      block with restriction_reason = "table_in_forbidden_list"
  IF A is non-empty AND any t in R does NOT match any a in A:
      block with restriction_reason = "table_not_in_allowed_list"
  ELSE: admit
```

The `matches` relation follows D3.

### 5.4 Test coverage required by this spec

For each SQL proxy, the V2 PR ships unit tests covering:

| Case | Expected RelationList |
|---|---|
| `SELECT * FROM users` | `[users]` |
| `SELECT * FROM public.users` | `[public.users]` |
| `SELECT * FROM "Users"` | `[Users]` (case preserved) |
| `SELECT a.id FROM users a JOIN orders o ON a.id = o.user_id` | `[users, orders]` |
| `SELECT * FROM users WHERE id IN (SELECT user_id FROM banned)` | `[users, banned]` |
| `WITH u AS (SELECT * FROM users) SELECT * FROM u` | `[users]` (CTE elided) |
| `INSERT INTO orders (user_id) SELECT id FROM users WHERE active` | `[orders, users]` |
| `UPDATE orders SET total = 0 FROM users WHERE orders.user_id = users.id AND users.fraudulent` | `[orders, users]` |
| `DELETE FROM orders USING users WHERE orders.user_id = users.id` | `[orders, users]` |
| `EXPLAIN SELECT * FROM users` | `[users]` |
| `SELECT 1; DROP TABLE users` | `Ambiguous(MultiStatementBatch)` |
| `EXEC sp_executesql N'SELECT * FROM users'` | `Ambiguous(DynamicSql)` |
| `SELECT * FROM users WHERE name = 'foo';` (trailing `;` only) | `[users]` |

Plus the dialect-specific identifier quoting variants
(`` `users` `` for MySQL, `[users]` for MSSQL).

---

## §6 — BSON Command Walker (MongoDB)

### 6.1 Algorithm

Given an `OP_MSG` body, the walker returns:

```rust
pub enum CommandTarget {
    /// Walker proved the primary collection (or absence thereof
    /// for non-collection commands like `hello` / `ping`).
    Resolved {
        command:    String,          // first BSON field name
        collection: Option<String>,  // value of the command field
                                     // when the command takes a
                                     // collection name; None for
                                     // `hello` / `ping` / etc.
        db:         Option<String>,  // `$db` field value
    },
    /// Walker detected secondary-collection references it cannot
    /// prove are admissible (`$lookup.from`, `$graphLookup.from`,
    /// `$unionWith.coll`, `$merge.into`, `$out`).
    SecondaryCollectionDetected {
        command:    String,
        collection: String,
        secondary:  Vec<String>,
    },
    /// Malformed BSON.
    Ambiguous,
}
```

Walker steps:

1. Read the first kind-0 (Body) section; parse the first BSON
   element. The field name is the command (existing V2.1 behaviour
   via `first_command_name`).
2. If the first element's value is a BSON string, that string is
   the **primary collection** name for commands that name a
   collection in the value position (`find`, `count`, `distinct`,
   `aggregate`, `insert`, `update`, `delete`, `findAndModify`,
   `createIndexes`, `dropIndexes`, `listIndexes`, `getMore`'s
   first element, `geoSearch`). For commands like `hello`,
   `isMaster`, `ping`, `buildInfo`, `serverStatus` the value is
   `1` (numeric); the collection is `None`.
3. Walk the remaining top-level BSON elements until either
   `$db` is found (value → `db` field of the result) or the
   document ends.
4. If the command is `aggregate` or `find`, *scan* the body for
   the byte sequences `\x02from\x00` / `\x02coll\x00` /
   `\x02into\x00` / `\x02out\x00` at the top of any nested
   document — when present the walker records the values into
   `secondary` and surfaces `SecondaryCollectionDetected`. This
   is a deliberately *non-tree-walking* heuristic: it cannot
   distinguish `$lookup.from` from an *unrelated* document field
   named `from`, so it deliberately surfaces the *possibility*
   of a secondary collection rather than proving its absence.
   When **no allowlist or denylist is configured**, the heuristic
   is skipped (D6).
5. For kind-1 (Document Sequence) sections — used by batched
   `insert` / `update` / `delete` — the walker reads the section
   identifier (the cstring after the section size) as additional
   collection context. The section identifier is the field
   name *of the document array within the command*, NOT a
   collection name; the primary collection from step 2 is
   authoritative.

### 6.2 Allowlist / denylist check

Same shape as §5.3:

```text
Given:
  T = CommandTarget
  A = allowed_collections
  F = forbidden_collections

Decision (when T is Resolved):
  fully_qualified = format!("{db}.{collection}") if both Some else
                    None
  IF F is non-empty AND fully_qualified is in F:
      block with restriction_reason = "collection_in_forbidden_list"
  IF A is non-empty AND fully_qualified is None or not in A:
      block with restriction_reason = "collection_not_in_allowed_list"
  ELSE: admit

When T is SecondaryCollectionDetected AND any list is non-empty:
  block with restriction_reason = "secondary_collection_in_pipeline"

When T is Ambiguous AND any list is non-empty:
  block with restriction_reason = "ambiguous_bson"
```

Commands that do not name a collection (`hello`, `ping`, etc.) are
admitted unconditionally — the allowlist applies to *data-bearing*
commands, not server-introspection.

### 6.3 Reject-on-secondary rationale

The conservative reject-when-secondary-detected rule is the
MongoDB equivalent of §5's "reject-when-ambiguous" SQL rule.
`$lookup`-heavy workloads can either:

- Drop `allowed_collections`/`forbidden_collections` entirely and
  rely on database-side role permissions.
- Pre-join the data into a server-side view (`db.createView`) and
  allowlist the view name.
- Wait for V3 walker to ship per-pipeline allowlist coverage.

### 6.4 Test coverage required

Per the SQL section, the V2 PR ships unit tests covering:

| Inbound BSON command body | Expected CommandTarget |
|---|---|
| `{ find: "users", $db: "appdb" }` | `Resolved { command: "find", collection: Some("users"), db: Some("appdb") }` |
| `{ insert: "orders", documents: [...], $db: "appdb" }` | `Resolved { command: "insert", collection: Some("orders"), db: Some("appdb") }` |
| `{ hello: 1, $db: "admin" }` | `Resolved { command: "hello", collection: None, db: Some("admin") }` |
| `{ aggregate: "users", pipeline: [{ $lookup: { from: "orders", ... } }], $db: "appdb" }` | `SecondaryCollectionDetected { primary: "users", secondary: ["orders"] }` |
| `{ ... malformed BSON ... }` | `Ambiguous` |

---

## §7 — `max_result_rows` / `max_documents` enforcement

### 7.1 Postgres

The simple-query result-set frame sequence is `RowDescription
(T)` → `DataRow (D)` × N → `CommandComplete (C)` →
`ReadyForQuery (Z)`. Per-protocol the proxy:

1. Reads each frame from upstream.
2. Increments `rows_relayed` on every `D` frame.
3. If `rows_relayed > max_result_rows`:
   - Send an `ErrorResponse (E)` to the agent with sqlstate
     `54000` (`program_limit_exceeded`), message "result-set row
     count exceeded RAXIS policy max_result_rows = N".
   - Send a synthetic `ReadyForQuery (Z)` with status byte `I`
     so the agent's connection stays usable.
   - **Drain** the remaining frames from upstream (read until
     real `Z`), keeping the upstream connection healthy.
   - Emit `DatabaseQueryCompleted { rows_returned: N (cap),
     upstream_error: Some("max_result_rows_exceeded") }`.

### 7.2 MySQL

The COM_QUERY result-set sequence is `ColumnCount` → `Column`
× N → `EOF`/`OK` → `Row` × M → `EOF`/`OK`. The proxy counts
`Row` packets and on overshoot:

1. Sends `ERR_Packet { code: 1153 (`ER_NET_PACKET_TOO_LARGE` —
   the closest stable MySQL errno; we re-purpose with a clear
   RAXIS-prefixed message), sqlstate: "54000" }`.
2. Drains upstream until the result-set EOF.

### 7.3 MSSQL

The TDS `TABULAR_RESULT` packet contains `COLMETADATA` → `ROW`
× N → `DONE`. The proxy counts `ROW` tokens (token `0xD1` —
`ROW`; `0xD2` — `NBCROW`) and on overshoot:

1. Sends an `ERROR` token (token `0xAA`) with `error_number =
   8170` ("Insufficient result space") and class 14.
2. Sends a `DONE` token with `DONE_ERROR` status bit.
3. Reads upstream to packet boundary EOM bit.

### 7.4 MongoDB

`find` / `aggregate` return an `OP_MSG` reply with a single
kind-0 BSON section carrying `{ cursor: { firstBatch: [docs...],
id, ns }, ok: 1.0 }`. The proxy *parses* the `firstBatch` array
length and, if `max_documents` is finite and `firstBatch.len() >
max_documents`:

1. **Truncates** the array to `max_documents` and rewrites the
   `id` field to `0` (closing the cursor — no subsequent
   `getMore` is needed; the agent observes the cap as
   "cursor exhausted").
2. The proxy emits the rewritten BSON downstream and emits a
   `MongoCommandExecuted` audit event with
   `restriction_reason = "max_documents_exceeded"` AND a
   `DatabaseQueryCompleted` (the proxy's general-purpose paired
   event) with `rows_returned = max_documents` and
   `upstream_error = Some("max_documents_exceeded")`.

The MongoDB cap is the only one that **rewrites** rather than
errors. The rationale: a cursor-exhausted reply is the most
natural way to surface the cap to the MongoDB driver without
breaking application-level error handling, and the rewrite is
mechanically deterministic (truncate array + zero cursor id).
The agent's driver does NOT see the original cursor id; it cannot
resume the result.

For `getMore` replies the same logic applies: the cumulative
document count across `find` + N `getMore` calls is tracked per
agent connection.

### 7.5 Counter persistence

The cumulative row / document count is per-query for SQL (each
new simple-query starts the counter at 0) and per-cursor for
Mongo (the count accumulates across `find` + `getMore`s sharing a
cursor id; the cursor id is what links the counter rows).

---

## §8 — Audit Envelope Additions

### 8.1 Field additions

`DatabaseQueryExecuted` (per `audit/src/event.rs`) gains:

```rust
DatabaseQueryExecuted {
    session_id:         String,
    credential_name:    String,
    operation:          String,
    sql_sha256:         String,
    sql_plaintext:      Option<String>,
    blocked:            bool,
    // NEW in V2 — this spec:
    /// Walker output: the qualified table names referenced by
    /// the query. Empty when the query is non-DML (e.g. `BEGIN`)
    /// or when the walker returned `Ambiguous`.
    #[serde(default)]
    tables_referenced:  Vec<String>,
    /// Closed enum of reasons the proxy blocked the query.
    /// `None` when `blocked` is `false`. See §8.2 for the enum.
    #[serde(default)]
    restriction_reason: Option<String>,
},
```

`MongoCommandExecuted` gains:

```rust
MongoCommandExecuted {
    session_id:         String,
    credential_name:    String,
    command:            String,
    body_sha256:        String,
    blocked:            bool,
    // NEW in V2 — this spec:
    /// Fully-qualified `<db>.<coll>` collection name; `None` for
    /// commands that don't name a collection (`hello`, `ping`).
    #[serde(default)]
    collection:         Option<String>,
    /// Closed enum of reasons the proxy blocked the command.
    #[serde(default)]
    restriction_reason: Option<String>,
},
```

`DatabaseQueryCompleted`'s existing `upstream_error: Option<String>`
is reused for the streaming-cap surface (`Some("max_result_rows_exceeded")`
/ `Some("max_documents_exceeded")`); no schema change there.

### 8.2 `restriction_reason` closed enum

Stable strings (audit consumers MAY grep on these verbatim):

| Value | Meaning |
|---|---|
| `"allow_only_select"` | The verb-class check rejected the query (existing V2.1; included here for completeness). |
| `"allow_read_only"` | MongoDB verb-class check rejected the command (existing). |
| `"table_not_in_allowed_list"` | Walker resolved relations; at least one was outside `allowed_tables`. |
| `"table_in_forbidden_list"` | Walker resolved relations; at least one was in `forbidden_tables`. |
| `"collection_not_in_allowed_list"` | Mongo equivalent. |
| `"collection_in_forbidden_list"` | Mongo equivalent. |
| `"ambiguous_sql_multi_statement"` | SQL walker rejected per §5.2. |
| `"ambiguous_sql_dynamic"` | SQL walker rejected `EXEC`/`PREPARE`/etc. |
| `"ambiguous_sql_malformed"` | SQL walker rejected malformed SQL. |
| `"ambiguous_bson"` | Mongo walker rejected malformed BSON. |
| `"secondary_collection_in_pipeline"` | Mongo walker detected `$lookup.from`/etc. with an allowlist configured. |
| `"max_result_rows_exceeded"` | Streaming cap fired. Echoed on the paired `DatabaseQueryCompleted.upstream_error`. |
| `"max_documents_exceeded"` | Mongo streaming cap fired. |

Adding a new reason is a deliberate spec amendment.

### 8.3 Audit-only mode (`enforce = false`)

When the credential's `enforce = false`:

- The walker still runs.
- `DatabaseQueryExecuted` / `MongoCommandExecuted` still carries
  `tables_referenced` / `collection` / `restriction_reason`.
- `blocked` is **always** `false` in audit-only mode.
- The query is admitted upstream regardless of restriction
  outcome.

This is the canonical rollout path per D8.

---

## §9 — Wire-Shape Error Responses

When the proxy rejects a query under §5.3 / §6.2:

### 9.1 Postgres

Same shape as `allow_only_select` rejection: `ErrorResponse (E)`
with:

- `S` (severity): `"ERROR"`
- `C` (sqlstate): `"42501"` (insufficient_privilege) — same
  sqlstate the V2.1 verb-class check uses, so drivers / ORMs
  treat it as a permission error.
- `M` (message): `"blocked by RAXIS policy: <restriction_reason>"`
  — the closed-enum value from §8.2 is embedded verbatim. This is
  intentional: per `paradigm.md R-10 Opaque Rejection`, the agent
  must not learn *which specific allowlist entry* fired; the
  closed enum names a *category*, not a rule.
- followed by `ReadyForQuery (Z)` so the session stays open.

For the streaming cap (§7.1), the sqlstate is `54000`
(program_limit_exceeded).

### 9.2 MySQL

`ERR_Packet`:

- `error_code`: `1142` (`ER_TABLEACCESS_DENIED_ERROR`) for the
  allowlist; `1153` for the streaming cap.
- `sql_state`: `"42501"` / `"54000"`.
- `message`: same closed-enum prefix as Postgres.

### 9.3 MSSQL

TDS `ERROR` token:

- `error_number`: `-1` (RAXIS-specific) for the allowlist
  rejection (same as V2.1 `allow_only_select`); `8170` for the
  streaming cap.
- `class`: `14` (security violation).
- `message`: closed-enum prefix.

Followed by `DONE` with `DONE_ERROR` status bit.

### 9.4 MongoDB

Synthetic `OP_MSG` reply with kind-0 BSON section:

```json
{
  "ok":       0.0,
  "code":     13,
  "codeName": "Unauthorized",
  "errmsg":   "blocked by RAXIS policy: <restriction_reason>"
}
```

Same shape the V2.1 `allow_read_only` rejection uses. For
`max_documents_exceeded` the reply path is different (cursor
truncation, §7.4) — the agent sees a cursor-exhausted result,
not an `ok: 0` error.

---

## §10 — `ProxyStats` Counter Additions

Each SQL proxy's `ProxyStats` gains:

```rust
pub struct ProxyStats {
    // ... V2.1 fields ...

    /// Number of queries rejected because the walker resolved
    /// tables and the allow/deny list did not admit them.
    pub queries_blocked_by_table_allowlist: u32,
    /// Number of queries rejected because the walker returned
    /// `Ambiguous` and an allowlist was configured.
    pub queries_blocked_by_ambiguous_sql:    u32,
    /// Number of queries whose result-set stream was terminated
    /// by `max_result_rows`.
    pub queries_capped_by_max_result_rows:   u32,
}
```

Mongo proxy's `ProxyStats` gains:

```rust
    pub commands_blocked_by_collection_allowlist: u32,
    pub commands_blocked_by_secondary_collection: u32,
    pub commands_capped_by_max_documents:         u32,
```

These flow through to the existing `CredentialProxyStopped` audit
event via the manager (the audit field for that event already
serialises the full stats struct, so this is a passive extension).

---

## §11 — Per-Proxy Implementation Matrix

### 11.1 V2 implementation status (after this PR)

| Proxy | Walker | `allowed_*` | `forbidden_*` | `max_result_rows` / `max_documents` | `enforce = false` | Streaming cap | Audit fields |
|---|---|---|---|---|---|---|---|
| `postgres` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | `tables_referenced`, `restriction_reason` |
| `mysql`    | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | same |
| `mssql`    | ✓ | ✓ | ✓ | configured | ✓ | ❗ followup | same |
| `mongodb`  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (cursor rewrite) | `collection`, `restriction_reason` |

> **MSSQL `max_result_rows` followup**: the field is plumbed end-to-end
> and the configured value is surfaced in the audit envelope, but the
> streaming cap (counting `ROW` tokens in the relayed TDS stream and
> short-circuiting with an `ERROR` token + `DONE_ERROR` when the cap
> trips) is **not yet** wired. TDS token-stream parsing has a much
> larger surface than the postgres / mysql wire (variable-length
> `COLMETADATA` widths, `ALTROW` / `NBCROW` token variants, SQL
> Server's chunked LOB packaging), and the V2 MSSQL proxy already
> relays bytes verbatim with the agent-side packet header preserved.
> Landing the cap correctly requires TDS token parsing on the
> upstream→agent path, which is a larger increment than this PR.
> Tracked as a V2 followup; the audit envelope already exposes the
> configured value so dashboards and `raxis doctor` can flag
> credentials configured for caps that the proxy isn't yet
> enforcing.

### 11.2 Deferred to V3

- **Prepared-statement / extended-query coverage.** Postgres
  `Parse`/`Bind`/`Execute`, MySQL `COM_STMT_PREPARE`/
  `COM_STMT_EXECUTE`, MSSQL `RPC` — V2.1 returns
  `feature_not_supported` for the extended path; this spec does
  not change that.
- **MongoDB `$lookup` pipeline walker.** V2 *rejects* pipelines
  with detected secondary collections when any allowlist is
  configured (§6.3); V3 will admit them on a per-pipeline basis
  by walking the full BSON tree.
- **`statement_timeout_ms` / `op_timeout_ms`.** Out of scope per
  §2.
- **Per-column allowlist.** Rejected per §1.3 — moves to
  database-native `GRANT` /  view-based controls.
- **Per-restriction-axis `enforce`.** Operators that need
  different `enforce` per restriction axis split the credential
  per D2 of [`operator-ergonomics.md`](operator-ergonomics.md) (one credential block per
  enforcement axis with the corresponding fields).

---

## §12 — Failure Codes

The kernel's `LifecycleError::PlanTaskCredentialsInvalid` family
gains new rules. The `rule` field is the stable grep key:

| `rule` | Triggered when | Diagnostic |
|---|---|---|
| `"allowed_tables_malformed"` | An entry in `allowed_tables` is not `<table>` or `<schema>.<table>` shape | "credential `<name>`: `allowed_tables[i]` `<value>` is not a valid identifier" |
| `"forbidden_tables_malformed"` | Same shape for `forbidden_tables` | Same |
| `"allowed_collections_malformed"` | An entry in `allowed_collections` is not `<db>.<coll>` | "credential `<name>`: `allowed_collections[i]` `<value>` must be `<db>.<collection>`" |
| `"forbidden_collections_malformed"` | Same | Same |
| `"max_result_rows_negative"` | TOML deserialiser would already reject this since the type is `u64`; included for parser-level test coverage | n/a |

These are pre-tx validation failures — a malformed plan never
allocates a row, matching the existing V2.1 validation discipline.

---

## §13 — Operator Playbook (Cross-Reference)

### 13.1 The "table allowlist + database GRANT" composition

The recommended deployment pattern for sensitive data:

1. Operator creates a read-only database role per agent purpose
   (`raxis_readonly_orders`, `raxis_readwrite_orders`).
2. Operator `GRANT SELECT ON public.orders, public.users TO
   raxis_readonly_orders;` and explicitly `REVOKE` / does not
   grant on `public.users_pii`, `public.payment_cards`.
3. Operator's `[tasks.credentials]` declares
   `allowed_tables = ["public.orders", "public.users"]`.
4. The proxy enforces the allowlist at the wire; the database
   role enforces the same allowlist server-side. Two layers
   protect the same surface — proxy gets fooled by a parser edge
   case, the database engine still rejects; database role gets
   widened by an operator mistake, the proxy still rejects.

This is the explicit V2 recommendation: **operators SHOULD
declare the same constraints in both the proxy and the database
engine.** The proxy gives early auditability and a unified
rejection vocabulary; the database engine gives 100% syntactic
coverage at the cost of opaque (engine-native) error messages.

### 13.2 The audit-only rollout pattern

```toml
# Step 1: declare an audit-only allowlist; ship to production.
[tasks.credentials.restrictions]
allowed_tables = ["public.orders", "public.users", "public.audit_log"]
enforce = false
```

Operator deploys, runs the agent's workload for some period
(typically 1–2 weeks), then greps the audit chain:

```sh
$ raxis audit-tail --filter 'kind = "DatabaseQueryExecuted" \
                             AND restriction_reason IS NOT NULL'
```

If the grep returns zero rows, the allowlist is faithful and the
operator flips to `enforce = true`. If the grep returns rows, the
operator either widens the allowlist or fixes the agent's SQL.
This pattern is the V2-recommended rollout — D8 exists precisely
to make this the cheap path.

---

## §14 — Invariants (added to `invariants.md`)

| ID | Statement | Justification | Canonical home |
|---|---|---|---|
| `INV-PROXY-TABLE-01` | When `allowed_tables` is non-empty on a SQL credential, every admitted query has `tables_referenced ⊆ allowed_tables` (per the walker output recorded in the audit chain). | The allowlist is structurally enforced; an audit reader can verify the property by re-reading the audit chain. | [`proxy-table-allowlists.md`](proxy-table-allowlists.md) §5.3, §8.1 |
| `INV-PROXY-TABLE-02` | When the walker returns `Ambiguous` and any allowlist or denylist is configured, the query is blocked and audited with the corresponding `ambiguous_sql_*` reason. | Fail-closed default `R-6`. | §5.2 |
| `INV-PROXY-TABLE-03` | When `forbidden_tables` is non-empty on a SQL credential, no admitted query touches a table in `forbidden_tables`. | Denylist short-circuit. | §5.3 |
| `INV-PROXY-TABLE-04` | When `max_result_rows = N` is finite, no agent connection observes more than `N` rows for any single simple-query result set, regardless of upstream return size. | Streaming hard-cap (§7.1–7.3). | §7 |
| `INV-PROXY-TABLE-05` | When `allowed_collections` is non-empty on a MongoDB credential, every admitted data-bearing command has its primary collection in `allowed_collections`. Commands that do not name a collection (`hello`, `ping`, etc.) are admitted unconditionally. | Mongo equivalent of `INV-PROXY-TABLE-01`. | §6.2 |
| `INV-PROXY-TABLE-06` | When `max_documents = N` is finite and a `find` / `aggregate` cursor returns more than `N` documents across `firstBatch + Σ getMore`, the agent observes the cursor as exhausted at the Nth document. | Cursor-rewrite cap (§7.4). | §7.4 |

These six map onto `R-2 Mediated I/O` (agent's database access is
bounded at the wire) and `R-5 Bounded Capabilities` (every grant
carries a numerical bound).

---

## §15 — Migration from V2.1 to V2.2

The wire-shape contract from V2.1 is unchanged. The observable
differences for a V2.1 plan that *does not* declare any of the
new fields are:

- The audit chain entries gain two new optional fields
  (`tables_referenced`, `restriction_reason` / `collection`,
  `restriction_reason`). Both default to empty / `None` on V2.1
  plans, so a V2.1 audit reader keeps working bit-for-bit.
- The `ProxyStats` struct gains three / three counters per proxy.
  The serialised `CredentialProxyStopped` audit field grows
  accordingly; consumers reading it `#[serde(default)]` keep
  working.
- No `policy.toml` schema change is required. No `plan.toml`
  schema change is required for plans that don't opt in.
- No migration on `kernel.db`.

Plans that opt into the new fields fail loud at `approve_plan` if
they misuse them (malformed identifier in `allowed_tables` →
`LifecycleError::PlanTaskCredentialsInvalid`); production
operators land them through the audit-only rollout of §13.2.

---

## §16 — Cross-spec amendments

This PR updates:

- [`credential-proxy.md`](credential-proxy.md) §14.8 implementation matrix rows for
  `postgres`, `mysql`, `mssql`, `mongodb` to flip the "Deferred
  V3: `forbidden_tables`, `max_result_rows`" / "Deferred V3:
  full BSON tree-walker for `forbidden_collections`,
  `max_documents`" entries to the V2 status documented in §11.1
  of this spec.
- `raxis-concepts/03-credential-proxies.md` to expand the
  `allowed_tables` / `allowed_collections` / `max_rows_per_query`
  conceptual surface with a link to this spec.
- [`V2_STATUS.md`](V2_STATUS.md) to add a line for the proxy table-allowlist
  feature with status "shipped".
- `invariants.md` §3-equivalent table — adds the six
  `INV-PROXY-TABLE-*` rows above.

Implementation tracker (the closing checklist of
[`credential-proxy.md`](credential-proxy.md)) gains:

- [x] **Proxy: SQL relation-reference walker** — per §5, lands
  in each of `credential-proxy-postgres`, `-mysql`, `-mssql`
  with shared semantics and protocol-specific wire shapes.
- [x] **Proxy: BSON command walker** — per §6, lands in
  `credential-proxy-mongodb`.
- [x] **Proxy: streaming result-cap enforcement** — per §7, one
  implementation per protocol.
- [x] **Audit: new fields on `DatabaseQueryExecuted` /
  `MongoCommandExecuted`** — per §8.
- [x] **Plan parser: new fields on `PostgresRestrictions` /
  `MysqlRestrictions` / `MssqlRestrictions` / `MongodbRestrictions`**
  — per §4.
- [x] **Kernel: validation rules** — per §12.
- [x] **Live-e2e slices** — at least one per proxy exercising
  allowlist deny + streaming cap against the real upstream
  (`postgres:16`, `mysql:8`, `mssql:2022`, `mongo:7`).
- [x] **Invariants** — `INV-PROXY-TABLE-01..06` per §14.

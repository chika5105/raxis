# `transparent_proxy/` — operator-style scripts for the realism e2e

This directory holds the Python scripts the realistic-scenario test
stages into the `transparent-proxy-realscripts` executor task's
worktree.

The scripts are intentionally **operator-realistic**:

* They use **standard client libraries** (`psycopg2`, `pymongo`,
  `redis`, `pymysql`, `pymssql`, stdlib `smtplib`).
* They read **standard environment variables**
  (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`, `SMTP_URL`,
  `MYSQL_URL`, `MSSQL_URL`) the way every real Python service does.
* They contain **no awareness of RAXIS**, the credential proxy, or
  the transparent-proxy substrate. The scripts work identically
  against a direct upstream connection and against the proxy — that
  identity is the whole transparency contract.
* They follow `argparse`-style CLI conventions: `--output <path>`
  picks the file to write, optional `--table` / `--database` /
  `--prefix` flags override per-service defaults.

The `run_all_services.sh` wrapper invokes each script in a fixed
order and prints a one-line `ok` / `skipped` / `FAIL` outcome per
service. `mysql` and `mssql` self-skip when their `*_URL` env var
is unset so the wrapper exits zero on the minimum-required service
set (postgres, mongodb, redis, smtp).

For the witness side (`raxis/kernel/tests/extended_e2e_support/
transparent_proxy_evidence.rs`), the canonical output bytes each
script writes match the same per-service formulas the
`service_evidence` witness module pins. The two witnesses are
complementary:

* `service_evidence` proves the **round-trip** succeeded
  (the seed data flowed through the proxy and landed at the
  executor).
* `transparent_proxy_evidence` proves the **transparency property**
  (the executor used stock client libraries against stock env vars
  and did not bypass the proxy).

A pinned dependency manifest lives at `requirements.txt`; the
executor's container image bakes those wheels in so no `pip install`
happens at task time.

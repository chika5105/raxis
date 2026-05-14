# Recipe 19 — Grafana datasource provisioning (canonical setup + gotchas)

> **Topic:** Operations | **Time to read:** ~6 min | **Complexity:** ⭐⭐ Intermediate

**Audience.** Operators or contributors who edit the
`raxis/observability/grafana/provisioning/` tree, debug "the
Grafana dashboards render empty" symptoms, or wire a new
observability surface into the live-e2e compose stack.

**Spec.** `specs/v3/observability-prometheus.md §4`. Invariant
`INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01`
(`specs/invariants.md §11.14`).

---

## TL;DR

The extended live-e2e stack ships a fully auto-provisioned
Grafana:

1. One Prometheus datasource at uid `prometheus` — defined in
   `raxis/observability/grafana/provisioning/datasources/prometheus.yaml`.
2. One dashboard provider that loads the eleven `raxis-*` JSONs —
   defined in
   `raxis/observability/grafana/provisioning/dashboards/raxis.yaml`.
3. Both files mount into the Grafana container under
   `/etc/grafana/provisioning/` via the bind mount
   `../observability/grafana/provisioning:/etc/grafana/provisioning:ro`
   in `raxis/live-e2e/docker-compose.extended.e2e.yml` (Grafana
   reads them once during startup; there is no Grafana-side
   reload API in 11.x).

Run the witness after every change touching any of those three
surfaces:

```bash
raxis/live-e2e/witness/inv_grafana_datasource_provisioned_at_stack_up_01.sh --bounce
```

`--bounce` does `docker compose down -v` + `up -d --wait`, then
asserts the datasource API, the dashboard count, and a live
Prometheus proxy query — exit 0 ⇔ the invariant holds.

---

## 1. Canonical datasource YAML

`raxis/observability/grafana/provisioning/datasources/prometheus.yaml`:

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    uid: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: 5s
      httpMethod: POST
      manageAlerts: false
      prometheusType: Prometheus
      prometheusVersion: 2.55.0
```

**Every field above is load-bearing.** The gotcha section
below explains why.

## 2. Canonical dashboard provider YAML

`raxis/observability/grafana/provisioning/dashboards/raxis.yaml`:

```yaml
apiVersion: 1

providers:
  - name: raxis
    orgId: 1
    folder: 'raxis'
    folderUid: raxis
    type: file
    disableDeletion: true
    allowUiUpdates: false
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
```

The dashboard provider points at `/var/lib/grafana/dashboards`,
NOT at the provisioning tree. The compose file has a separate
bind mount for that path:

```yaml
- ../observability/grafana/dashboards:/var/lib/grafana/dashboards:ro
```

`allowUiUpdates: false` keeps the dashboards in lock-step with
the JSON files in this repo — operators editing in the UI
cannot drift from the canonical source.

---

## 3. Gotchas that bit us

### 3.1 — Datasource URL host MUST be the compose service name

```yaml
url: http://prometheus:9090     # ← correct
```

NOT:

```yaml
url: http://127.0.0.1:9090      # ← BROKEN
url: http://localhost:9090      # ← BROKEN
```

`127.0.0.1` and `localhost` inside the Grafana container resolve
to the Grafana container itself, not to Prometheus. The
datasource still REGISTERS (Grafana doesn't probe `url` at
provisioning time — only when a panel queries through it), so
the symptom is "datasources page looks fine but every dashboard
panel returns `No data`." The witness's §4 (proxy query through
`/api/datasources/proxy/uid/prometheus/api/v1/query?query=up`)
catches this.

The compose service is named `prometheus:` in
`docker-compose.extended.e2e.yml`. Both the extended-e2e and
non-extended-e2e compose files share the same service name, so
the canonical YAML works against either.

### 3.2 — Validator creds: admin password is `raxis-e2e`, not `admin`

The compose env sets:

```yaml
GF_SECURITY_ADMIN_USER: admin
GF_SECURITY_ADMIN_PASSWORD: raxis-e2e
```

so any operator/CI probe MUST use `admin:raxis-e2e`, NOT
`admin:admin`. The default-creds path returns HTTP 401 and any
JSON-parsing probe interprets the empty body as "datasource list
is empty" — a misleading symptom that points at provisioning
when the root cause is auth.

`GF_AUTH_ANONYMOUS_ENABLED: "true"` is also set with the
`Viewer` role, which means a no-creds GET against
`/api/datasources` ALSO succeeds (it returns the same list a
Viewer sees) — useful for unauthenticated dashboard reads from
the operator's browser, NOT useful for inferring whether
provisioning succeeded, because the same response is returned
regardless of which credentials path you used.

The canonical probe — and the one the witness uses — is:

```bash
curl -fsS -u admin:raxis-e2e http://127.0.0.1:3000/api/datasources
```

### 3.3 — Grafana 11.x is strict about provisioning YAML schema

`apiVersion: 1` is required at the top of BOTH files. Without
it the file is silently skipped (you see no error in the
provisioning logs — just no datasource).

Key casing matters: `isDefault` (camelCase) is the schema,
`is_default` is silently ignored. The same holds for
`folderUid`, `disableDeletion`, `allowUiUpdates`,
`updateIntervalSeconds`, `foldersFromFilesStructure`.

`access: proxy` (the kernel proxies queries via
`/api/datasources/proxy/`) — NOT `access: direct` (deprecated
and broken on Grafana ≥ 9).

### 3.4 — `editable: false` makes the datasource readOnly

This is intentional: it stops operators from accidentally
clobbering the datasource from the UI. The API still returns
`"readOnly": true` for the datasource, which the witness asserts
on. If you DELIBERATELY want operators to edit the datasource at
runtime (you probably don't), drop the field.

### 3.5 — Mount paths

Three bind/named mounts on the Grafana service in
`raxis/live-e2e/docker-compose.extended.e2e.yml`:

```yaml
volumes:
  - ../observability/grafana/provisioning:/etc/grafana/provisioning:ro  # YAML provisioning
  - ../observability/grafana/dashboards:/var/lib/grafana/dashboards:ro  # dashboard JSONs
  - grafana_data:/var/lib/grafana                                       # Grafana DB + state
```

Order matters only in that Docker sorts mount targets by depth:
the named volume at `/var/lib/grafana` is applied first, then
the bind mount at `/var/lib/grafana/dashboards` overlays. Both
bind mounts are `:ro` because the YAML and dashboards are
canonical-source-controlled — Grafana must never be able to
mutate them.

The host source paths are RELATIVE TO THE COMPOSE FILE, i.e.
`../observability/...` resolves from `raxis/live-e2e/` to
`raxis/observability/...`. If you invoke `docker compose` from
the repo root with `-f raxis/live-e2e/docker-compose.extended.e2e.yml`,
this still works — compose anchors relative paths to the
compose file's directory, not to the caller's cwd.

### 3.6 — No reload API, only restart

Grafana 11.x removed `/api/admin/provisioning/datasources/reload`
in favor of file-watching, but the watcher only re-applies
DASHBOARD provisioning (not datasources). After editing
`datasources/prometheus.yaml`, you MUST `docker compose restart
grafana` (or bounce the stack) for the change to land.

The witness assumes "after `docker compose up --wait` returns"
exactly because that is the only deterministic moment to assert
provisioning state.

---

## 4. Witness the invariant

`INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01`
(`specs/invariants.md §11.14`) says: "After `docker compose up
--wait` returns on the extended-e2e stack, Grafana MUST have the
Prometheus datasource at uid `prometheus`, the eleven raxis
dashboards under the `raxis` folder, and the datasource MUST
proxy a `up` query through to Prometheus successfully."

Script:

```bash
# Use whatever stack is currently up:
raxis/live-e2e/witness/inv_grafana_datasource_provisioned_at_stack_up_01.sh

# Cold-bounce + verify (the canonical CI / pre-commit gate):
raxis/live-e2e/witness/inv_grafana_datasource_provisioned_at_stack_up_01.sh --bounce
```

Exit codes:

| Exit | Meaning |
|---|---|
| 0 | All 22 assertions passed. Invariant HOLDS. |
| 1 | At least one assertion failed. Diagnostics on stderr; invariant VIOLATED. |
| 2 | Prerequisites missing (`curl` / `jq` / `docker`) or stack not up. |

Run it after every change touching:

- `raxis/observability/grafana/provisioning/datasources/prometheus.yaml`
- `raxis/observability/grafana/provisioning/dashboards/raxis.yaml`
- `raxis/observability/grafana/dashboards/*.json` (renaming UIDs)
- The `grafana:` service block in
  `raxis/live-e2e/docker-compose.extended.e2e.yml` (env vars,
  volume mounts, image tag).

---

## 5. When it goes wrong

| Symptom | Likely root cause | Diagnostic |
|---|---|---|
| `/api/datasources` returns `[]` | YAML missing or unparseable; `apiVersion: 1` absent | `docker compose logs grafana \| grep -i provisioning` |
| Datasources page is fine but dashboards say "No data" | `url:` points at `localhost`/`127.0.0.1` (resolves to Grafana, not Prometheus) | witness §4 fails with `proxy /api/v1/query` returning non-`success` |
| Datasource is there but dashboards aren't | `dashboards/raxis.yaml` missing or `path:` typo | `docker exec raxis-e2e-grafana ls /var/lib/grafana/dashboards` |
| 11 dashboards present but one panel says "Datasource not found" | dashboard JSON's `datasource.uid` doesn't match `datasources/prometheus.yaml`'s `uid` | `jq -r '..\|objects\|select(.datasource?)\|.datasource' raxis/observability/grafana/dashboards/*.json` |
| Grafana UI shows datasource but operator probes don't (`401`) | Probing with `admin:admin` instead of `admin:raxis-e2e` | See §3.2 |
| `docker compose up --wait` hangs on `grafana` | Provisioning panic (rare on Grafana 11.x) | `docker compose logs grafana` will show the panic |

For deeper investigation, `docker exec raxis-e2e-grafana sh -c
'ls -la /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards'`
confirms the bind mount actually delivered the YAML files into
the container (mount-path drift between the compose file and the
YAML claim is the only failure mode the witness can't fully
explain — the witness asserts the runtime contract, not the
container-internal filesystem state).

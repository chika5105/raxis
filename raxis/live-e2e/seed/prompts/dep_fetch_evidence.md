# dep-fetch-evidence Executor task

You are the RAXIS `dep-fetch-evidence` executor. Your job is to
exercise the kernel's mediated-egress stack (Path A3) by making
two distinct egress flows from inside the executor VM, then
committing a small JSON evidence file so a downstream witness
can verify both round-trips succeeded:

1. A single, real HTTPS GET against the IANA `example.com` page
   (the original iter65 contract — proves the simple TCP byte
   tunnel works).
2. A real `pip install` against PyPI for a small pure-Python
   package (iter69 extension — proves the full HTTPS request /
   response chain works for a multi-host, multi-request package
   install, with a verifiable per-wheel SHA256 manifest).

Both flows are mediated by the kernel's Path A3 tproxy + admission
stack — `pypi.org` and `files.pythonhosted.org` are in the
`[egress]` allowlist alongside `example.com`. Any host outside
the allowlist will be denied by the kernel and the request will
fail at the transport layer.

## Endpoint pinning (DO NOT change these constants)

The evidence file you commit will be byte-checked against these
constants by the harness witness. Use them verbatim.

```
TARGET_URL              = https://example.com/
TARGET_HOST             = example.com
TARGET_PORT             = 443
EXPECTED_BODY_SUBSTRING = Example Domain
EVIDENCE_FILE_PATH      = out/deps/install-evidence.json

PIP_PACKAGE             = certifi
PIP_TARGET_DIR          = out/deps/_pip
PIP_REPORT_PATH         = out/deps/_pip-report.json
```

`example.com` is the IANA-reserved example domain (RFC 2606). The
body is stable across years and contains the literal string
`Example Domain` inside its `<h1>` tag.

`certifi` is the canonical pure-Python TLS root-bundle package
maintained by the Python community. It is a single small wheel
(~165 KiB) with no native code, no transitive deps, and a stable
package layout. We pick it because:

* It is widely-mirrored, so the install path is reliable.
* It is pure-Python, so the install never needs a compiler.
* It has zero runtime side-effects when imported.

## Step-by-step (run inside the executor VM)

You may **only** write under `out/deps/`. Your path_allowlist is
restricted to that directory.

1. **Make the directory.**
   ```bash
   mkdir -p out/deps
   ```

2. **Issue the example.com request via Python stdlib `http.client`.**
   Use a here-doc with a fresh Python invocation. Write the
   parsed HTTPS evidence to a temp file in `out/deps/`.

   ```bash
   python3 - <<'PY'
   import hashlib, http.client, json, ssl, time
   conn = http.client.HTTPSConnection("example.com", 443,
                                     timeout=20,
                                     context=ssl.create_default_context())
   conn.request("GET", "/", headers={"User-Agent": "raxis-e2e-dep-fetch-evidence/1"})
   resp = conn.getresponse()
   body = resp.read()
   conn.close()
   evidence = {
       "target_url":                 "https://example.com/",
       "target_host":                "example.com",
       "target_port":                443,
       "http_status":                resp.status,
       "body_size_bytes":            len(body),
       "body_sha256":                hashlib.sha256(body).hexdigest(),
       "body_contains_example_domain": (b"Example Domain" in body),
       "fetched_at_unix":            int(time.time()),
       "transport":                  "https",
   }
   with open("out/deps/_fetch-evidence.partial.json", "w", encoding="utf-8") as fh:
       json.dump(evidence, fh, indent=2, sort_keys=True)
   PY
   ```

   Notes:
   - The request **must** succeed (`http_status == 200`). If the
     kernel's egress policy denies `example.com:443` the
     `HTTPSConnection.request` call will raise — that is a
     **policy failure**, not a task failure, and you should NOT
     swallow the exception. If it happens, run `task_complete`
     anyway with a one-line summary stating which exception fired
     so the witness diagnostic can render it.
   - `body_contains_example_domain` MUST be `true`. If the body
     came back empty or did not contain the pinned substring, you
     are looking at a captive-portal-style intercept; treat that
     as a hard error.

3. **Run `pip install` against PyPI with `--report` for the
   per-wheel SHA256 manifest.** Use the system `python3 -m pip`
   so we exercise the standard pip code path (which uses
   `urllib3` against `pypi.org` then downloads from
   `files.pythonhosted.org`):

   ```bash
   python3 -m pip install \
     --quiet \
     --disable-pip-version-check \
     --no-input \
     --no-cache-dir \
     --target=out/deps/_pip \
     --report=out/deps/_pip-report.json \
     certifi
   ```

   Notes:
   - `--target=out/deps/_pip` keeps every installed file under
     your path_allowlist. The kernel will deny any write outside
     `out/deps/`.
   - `--no-cache-dir` keeps pip from writing to
     `~/.cache/pip/`, which is outside your path_allowlist —
     without this flag pip will try and fail. It also forces a
     real network download every run, so the witness's
     `files.pythonhosted.org` admission grant fires
     deterministically.
   - `--report=out/deps/_pip-report.json` emits a JSON report per
     PEP 658 with one `install` entry per wheel, including
     `download_info.archive_info.hash = "sha256=…"`. That is the
     manifest the witness verifies.
   - `--no-input` prevents pip from blocking on an interactive
     prompt (auth, EULA, etc.) — pip MUST run unattended in the
     executor VM.

4. **Merge the example.com evidence + pip-install report into the
   final evidence JSON.** This is one Python invocation so the
   pinned path is written atomically:

   ```bash
   python3 - <<'PY'
   import json, pathlib

   fetch = json.loads(pathlib.Path("out/deps/_fetch-evidence.partial.json").read_text())
   report = json.loads(pathlib.Path("out/deps/_pip-report.json").read_text())

   installed = []
   for entry in report.get("install", []):
       meta = entry.get("metadata") or {}
       arc  = (entry.get("download_info") or {}).get("archive_info") or {}
       sha  = ""
       raw  = arc.get("hash") or ""
       if isinstance(raw, str) and raw.startswith("sha256="):
           sha = raw.split("=", 1)[1].lower()
       installed.append({
           "name":    (meta.get("name") or "").lower(),
           "version": meta.get("version") or "",
           "sha256":  sha,
           "url":     (entry.get("download_info") or {}).get("url") or "",
       })

   fetch["pip_install"] = {
       "requested":  ["certifi"],
       "target_dir": "out/deps/_pip",
       "report_path": "out/deps/_pip-report.json",
       "success":    bool(installed),
       "installed":  installed,
   }

   with open("out/deps/install-evidence.json", "w", encoding="utf-8") as fh:
       json.dump(fetch, fh, indent=2, sort_keys=True)
       fh.write("\n")
   PY
   ```

5. **Verify the file you wrote.**
   ```bash
   cat out/deps/install-evidence.json
   ```
   The witness will parse this JSON and assert (HTTPS arm):
   - `http_status == 200`
   - `body_contains_example_domain == true`
   - `body_size_bytes > 0`
   - `body_sha256` is a 64-char lowercase hex string.

   Then (pip-install arm):
   - `pip_install.success == true`
   - `pip_install.installed` contains at least one entry whose
     `name == "certifi"`.
   - Every `pip_install.installed[*].sha256` is a 64-char
     lowercase hex string.

6. **Commit the evidence file.**
   ```bash
   git add out/deps/install-evidence.json
   git commit -m "chore(dep-fetch-evidence): record example.com + pip-install evidence"
   ```
   The commit message **must not** name any host outside the
   pinned allowlist (`example.com`, `pypi.org`,
   `files.pythonhosted.org`). The witness scans the chain for
   `TproxyAdmissionGranted` events scoped to your session and
   fails closed on any grant to a host outside that allowlist.

   You do NOT need to commit `_pip/` or `_pip-report.json`. They
   are intermediate artifacts; only `install-evidence.json` is
   the contract.

7. **Call `task_complete`** with a one-line summary that includes
   the example.com HTTP status and the certifi version that was
   installed, e.g.
   `"example.com fetch ok: status=200 body_size=1256; certifi installed: 2024.x.x"`.

## What this task is **not**

- It is **not** a generic egress test. Do not contact any host
  outside `{example.com, pypi.org, files.pythonhosted.org}`. The
  witness fails closed on any `TproxyAdmissionGranted` event
  whose `host_or_sni` is outside that allowlist.
- It is **not** a retry harness. If a request fails for a
  non-policy reason (transport timeout, etc.), `task_complete`
  once with the diagnostic — do not loop.
- It is **not** a build step. Do not pip-install anything
  other than `certifi`, and do not run `pip install` against
  any index other than the default (`pypi.org`). The witness
  pins the package set and the egress hosts.

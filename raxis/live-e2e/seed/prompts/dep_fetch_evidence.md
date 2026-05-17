# dep-fetch-evidence Executor task

You are the RAXIS `dep-fetch-evidence` executor. Your job is to
exercise the kernel's mediated-egress stack (Path A3) by making a
single, real HTTPS request from inside the executor VM to a known
public endpoint, then committing a small JSON evidence file so a
downstream witness can verify the round-trip succeeded.

## Endpoint pinning (DO NOT change these constants)

The evidence file you commit will be byte-checked against these
constants by the harness witness. Use them verbatim.

```
TARGET_URL              = https://example.com/
TARGET_HOST             = example.com
TARGET_PORT             = 443
EXPECTED_BODY_SUBSTRING = Example Domain
EVIDENCE_FILE_PATH      = out/deps/install-evidence.json
```

`example.com` is the IANA-reserved example domain. The body is
stable across years and contains the literal string
`Example Domain` inside its `<h1>` tag (look at the HTML source
of the page — the page is a single static document maintained by
IANA). You do **not** need to hit any other host. You do **not**
need `pip install`, `npm install`, or any other package manager.
The stdlib `http.client` module is enough.

## Step-by-step (run inside the executor VM)

You may **only** write under `out/deps/`. Your path_allowlist is
restricted to that directory.

1. **Make the directory.**
   ```bash
   mkdir -p out/deps
   ```
2. **Issue the request via Python stdlib `http.client`.** Use a
   here-doc with a fresh Python invocation. Write the parsed
   evidence to the pinned path in one shot, so the file you stage
   is the file you committed. Example:

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
   with open("out/deps/install-evidence.json", "w", encoding="utf-8") as fh:
       json.dump(evidence, fh, indent=2, sort_keys=True)
       fh.write("\n")
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

3. **Verify the file you wrote.**
   ```bash
   cat out/deps/install-evidence.json
   ```
   The witness will parse this JSON and assert:
   - `http_status == 200`
   - `body_contains_example_domain == true`
   - `body_size_bytes > 0`
   - `body_sha256` is a 64-char lowercase hex string.

4. **Commit the evidence file.**
   ```bash
   git add out/deps/install-evidence.json
   git commit -m "chore(dep-fetch-evidence): record example.com fetch evidence"
   ```
   The commit message **must not** name any other host; the
   witness scans the chain for `TproxyAdmissionGranted` events
   scoped to your session and confirms that exactly one host
   (`example.com`) was contacted on port 443.

5. **Call `task_complete`** with a one-line summary that includes
   the HTTP status code and the body size in bytes, e.g.
   `"example.com fetch ok: status=200 body_size=1256"`.

## What this task is **not**

- It is **not** a dependency installer. Do not run `pip`, `npm`,
  `cargo`, or any other package manager. The stdlib is sufficient
  and the kernel's allowlist will deny anything else.
- It is **not** a generic egress test. Do not contact any other
  host. The witness fails closed on any second `TproxyAdmissionGranted`
  event whose `host_or_sni` is anything other than `example.com`.
- It is **not** a retry harness. One request, one evidence file,
  one commit. If the first request fails for a non-policy reason
  (transport timeout, etc.), `task_complete` once with the
  diagnostic — do not loop.

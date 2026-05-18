# Genesis Force and Bootstrap Mode

RAXIS keeps destructive reset explicit.

## Re-Running Genesis

`raxis genesis` refuses to overwrite an existing data dir:

```text
ERR_ALREADY_INITIALIZED
```

For a throwaway dev install, either delete the data dir or pass the
flag:

```bash
rm -rf "$RAXIS_DATA_DIR"
raxis genesis --operator-name "$USER"

# Or, when deletion is awkward:
raxis genesis --force --operator-name "$USER"
```

Do not use `--force` on production state unless the audit chain and
database have already been archived. It recreates genesis artifacts
and removes the prior kernel DB/audit anchor.

## `RAXIS_BOOTSTRAP`

`RAXIS_BOOTSTRAP` is a kernel recovery/development escape hatch, not a
normal setup knob. A steady-state operator should leave it unset.

```bash
unset RAXIS_BOOTSTRAP
```

If a kernel appears stuck in bootstrap mode, clear the variable from
the service environment and restart the kernel.

## Related

| Surface | Use |
| --- | --- |
| `--force` | Explicit destructive re-genesis. |
| `RAXIS_OPERATOR_KEY` | Private key used by same-host genesis and later signing commands. |
| `RAXIS_OPERATOR_CERT` | Pre-minted cert path for air-gapped genesis. |

# keystone-secrets

Small Python library that gives every Keystone service one way to store credentials:
write metadata, bind secrets to people and roles, and **use** them — the only operation
that returns decrypted values, with purpose logging and caller permission checks.

## Model

- **SecretRef** — namespace, scope (`platform`, `client`, `project`, …), `scope_id`, and name.
  String form `ref.key()` is used in audit rows and in the registry (URL-encoded segments).
- **Bindings** — `user:<sub>`, `role:<name>` (ordered by `position`), or `default` per namespace.
- **resolve** — user binding, then first matching role by position, then default.
- **SecretMeta** — version, `ready` / `needs_reentry`, and non-secret `public` fields; never values.

Values are available only through **`use(ref, purpose=…, caller=…)`**. The store checks
`caller.allows(namespace, "use")`; denial writes a `denied` audit event with `code=permission`.

## local-postgres

Postgres backend with DDL exported as Python constants (`SCHEMA_V1`, `DROP_V1`) for consumer
migrations (e.g. Keystone `0007`).

```python
from keystone_secrets.backends.local_postgres import LocalPostgresStore, install_schema

store = await LocalPostgresStore.open(
    master_key=os.environ["KEYSTONE_SECRETS_KEY"],
    dsn=os.environ["SECRETS_DATABASE_URL"],
)
meta = await store.put(ref, {"token": "…"}, actor=Actor(service="keystone"))
fields = await store.use(ref, purpose="webhook", caller=caller, on_behalf_of=None)
await store.close()
```

### Master key

Set **`KEYSTONE_SECRETS_KEY`** to at least **32 UTF-8 bytes**. Without the correct key,
existing ciphertext stays sealed (`needs_reentry`). Keep the key **off the database host**
and separate from backups of the DB — same practice as stdio-box: losing the key means
re-entering secrets.

## CLI

| Command | Purpose |
|---------|---------|
| `keystone-secrets put …` | Write fields from `--from-file` JSON or `--value-file` (mode `600`, owned by you) |
| `keystone-secrets rekey --old-key-file …` | Re-seal with a new master key |
| `keystone-secrets schema install` | Apply `SCHEMA_V1` to an empty database |

Environment: `SECRETS_DATABASE_URL`, `KEYSTONE_SECRETS_KEY`. Exit codes: `0` ok, `1` store error,
`2` usage, `3` rekey with unreadable rows.

## Versions

| Version | Delivered |
|---------|-----------|
| **0.1.0** | Protocol models, crypto, `local-postgres`, OpenAPI v1 doc, conformance suite, CLI |
| 0.2.0 | `local-sqlite`, `remote-http`, server, extended tests |
| 0.3.0 | Vault backend |

HTTP API shape: [`docs/protocol-v1.yaml`](docs/protocol-v1.yaml) (server is SEC-3).

## Origin

`crypto.py` and audit detail checking are derived from [stdio-box](https://github.com/keystone-codes/stdio-box)
(Apache-2.0); see `NOTICE`.
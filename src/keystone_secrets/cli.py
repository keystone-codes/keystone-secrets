"""CLI: rekey, put, schema install."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from keystone_secrets.backends.local_postgres import (
    LocalPostgresStore,
    install_schema,
)
from keystone_secrets.protocol import (
    Actor,
    InvalidFields,
    InvalidRef,
    KeyTooShort,
    SchemaMissing,
    Scope,
    SecretRef,
    SecretsError,
)


def main() -> None:
    raise SystemExit(asyncio.run(_amain()))


async def _amain() -> int:
    parser = argparse.ArgumentParser(prog="keystone-secrets")
    parser.add_argument("--key-file", help="Path to master key file (mode 600, owner you)")
    parser.add_argument("--database-url", help="Postgres URL (overrides SECRETS_DATABASE_URL)")
    sub = parser.add_subparsers(dest="command", required=True)

    rekey_p = sub.add_parser("rekey", help="Re-seal secrets with a new master key")
    rekey_p.add_argument(
        "--old-key-file",
        required=True,
        help="Path to file with the previous master key, or - for stdin",
    )

    put_p = sub.add_parser("put", help="Write a secret without echoing values")
    put_p.add_argument("namespace")
    put_p.add_argument("scope")
    put_p.add_argument("scope_id")
    put_p.add_argument("name")
    put_p.add_argument("--from-file", help="JSON object of field names to string values")
    put_p.add_argument("--value-file", help="Single field value from a private file")
    put_p.add_argument("--field", default="value", help="Field name for --value-file")

    schema = sub.add_parser("schema", help="Schema maintenance")
    schema_sub = schema.add_subparsers(dest="schema_cmd", required=True)
    schema_sub.add_parser("install", help="Install SCHEMA_V1 when absent")

    args = parser.parse_args()
    if args.database_url:
        os.environ["SECRETS_DATABASE_URL"] = args.database_url
    if args.command == "schema":
        if args.schema_cmd == "install":
            return await _cmd_schema_install()
        return 2

    try:
        master_key = _master_key(args.key_file)
    except (_CliError, KeyTooShort) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        store = await _open_store(master_key)
    except (SchemaMissing, SecretsError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        if args.command == "rekey":
            return await _cmd_rekey(store, args.old_key_file)
        if args.command == "put":
            return await _cmd_put(store, args)
    finally:
        await store.close()
    return 1


async def _cmd_schema_install() -> int:
    dsn = _database_url()
    if not dsn:
        print("SECRETS_DATABASE_URL is required", file=sys.stderr)
        return 2
    import asyncpg

    conn = await asyncpg.connect(dsn)
    try:
        installed = await install_schema(conn)
    finally:
        await conn.close()
    print("installed" if installed else "already present")
    return 0


async def _cmd_rekey(store: LocalPostgresStore, old_key_path: str) -> int:
    try:
        old_key = _read_private_file(old_key_path).strip("\n")
        report = await store.rekey(old_key)
    except (_CliError, KeyTooShort, SecretsError) as exc:
        print(str(exc), file=sys.stderr)
        return 2 if isinstance(exc, _CliError) else 1
    print(
        f"resealed={report.resealed}, "
        f"already_current={report.already_current}, unreadable={report.unreadable}"
    )
    return 0 if report.unreadable == 0 else 3


async def _cmd_put(store: LocalPostgresStore, args: argparse.Namespace) -> int:
    scope_id = "" if args.scope_id == "-" else args.scope_id
    try:
        ref = SecretRef(
            args.namespace,
            Scope(args.scope),
            scope_id,
            args.name,
        )
    except (ValueError, InvalidRef) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.from_file:
        try:
            fields = json.loads(_read_private_file(args.from_file))
        except (json.JSONDecodeError, _CliError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if not isinstance(fields, dict):
            print("fields must be a JSON object", file=sys.stderr)
            return 2
        fields = {str(k): str(v) for k, v in fields.items()}
    elif args.value_file:
        try:
            value = _read_private_file(args.value_file)
            if value.endswith("\n"):
                value = value[:-1]
            fields = {args.field: value}
        except _CliError as exc:
            print(exc.message, file=sys.stderr)
            return 2
    else:
        print("provide --from-file or --value-file", file=sys.stderr)
        return 2
    actor = Actor(service="keystone-secrets", via="cli")
    try:
        meta = await store.put(ref, fields, actor=actor)
    except InvalidFields as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except SecretsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"{ref.key()} version={meta.version}")
    return 0


class _CliError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _master_key(key_file: str | None = None) -> str:
    if key_file:
        key = _read_private_file(key_file).strip("\n")
    else:
        key = os.environ.get("KEYSTONE_SECRETS_KEY", "")
    if not key:
        raise _CliError("KEYSTONE_SECRETS_KEY is required")
    if len(key.encode("utf-8")) < 32:
        raise KeyTooShort("KEYSTONE_SECRETS_KEY must be at least 32 bytes")
    return key


def _database_url() -> str | None:
    return os.environ.get("SECRETS_DATABASE_URL")


async def _open_store(master_key: str) -> LocalPostgresStore:
    dsn = _database_url()
    if not dsn:
        raise _CliError("SECRETS_DATABASE_URL is required")
    return await LocalPostgresStore.open(master_key=master_key, dsn=dsn)


def _read_private_file(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    file_path = Path(path)
    if not file_path.is_file():
        raise _CliError("file not found")
    mode = file_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise _CliError("file must be mode 600")
    if file_path.stat().st_uid != os.getuid():
        raise _CliError("file must be owned by the current user")
    return file_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    main()

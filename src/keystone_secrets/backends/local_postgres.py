"""Postgres-backed SecretStore implementation."""

from __future__ import annotations

import hmac
import json
import os
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any

import asyncpg

from keystone_secrets import audit as audit_mod
from keystone_secrets.crypto import (
    INFO_AUDIT_SUB,
    INFO_VALUES,
    check_master_key,
    derive,
    key_check,
    key_id,
    open_,
    seal,
)
from keystone_secrets.protocol import (
    Actor,
    AuditEvent,
    AuditFilter,
    Binding,
    Caller,
    Health,
    Permission,
    PermissionDenied,
    RekeyReport,
    SchemaMissing,
    Scope,
    SecretInUse,
    SecretMeta,
    SecretNotFound,
    SecretRef,
    SecretUnreadable,
    Subject,
    normalize_subject,
    validate_fields,
    validate_purpose,
)

SCHEMA_VERSION = 1

SCHEMA_V1: tuple[str, ...] = (
    """
CREATE TABLE secret_meta (
    key text PRIMARY KEY,
    value text NOT NULL
)
""".strip(),
    """
CREATE TABLE secret_values (
    namespace  text NOT NULL,
    scope      text NOT NULL CHECK (scope IN (
        'platform','client','project','person','role','default'
    )),
    scope_id   text NOT NULL,
    name       text NOT NULL,
    version    integer NOT NULL CHECK (version >= 1),
    nonce      bytea NOT NULL,
    ciphertext bytea NOT NULL,
    key_id     text NOT NULL,
    public     jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(public) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL,
    PRIMARY KEY (namespace, scope, scope_id, name)
)
""".strip(),
    """
CREATE TABLE secret_bindings (
    namespace  text NOT NULL,
    subject    text NOT NULL,
    ref_scope  text NOT NULL,
    ref_scope_id text NOT NULL,
    ref_name text NOT NULL,
    position   integer,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL,
    PRIMARY KEY (namespace, subject),
    CONSTRAINT secret_bindings_position UNIQUE (namespace, position)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((subject LIKE 'role:%') = (position IS NOT NULL)),
    FOREIGN KEY (namespace, ref_scope, ref_scope_id, ref_name)
        REFERENCES secret_values (namespace, scope, scope_id, name) ON DELETE RESTRICT
)
""".strip(),
    """
CREATE TABLE secret_audit (
    id              bigserial PRIMARY KEY,
    at              timestamptz NOT NULL DEFAULT now(),
    event           text NOT NULL CHECK (event IN (
        'put','use','delete','bind','unbind','denied','rekey'
    )),
    namespace       text,
    ref             text,
    service         text NOT NULL,
    person_hash     text,
    person_verified boolean NOT NULL DEFAULT false,
    purpose         text,
    outcome         text NOT NULL CHECK (outcome IN ('ok','denied','error')),
    code            text,
    count           integer NOT NULL DEFAULT 1,
    detail          jsonb
)
""".strip(),
    "CREATE INDEX secret_audit_at ON secret_audit (at)",
    "CREATE INDEX secret_audit_ns_at ON secret_audit (namespace, at)",
)

DROP_V1: tuple[str, ...] = (
    "DROP TABLE IF EXISTS secret_audit",
    "DROP TABLE IF EXISTS secret_bindings",
    "DROP TABLE IF EXISTS secret_values",
    "DROP TABLE IF EXISTS secret_meta",
)


async def install_schema(conn: asyncpg.Connection) -> bool:
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(868001)")
        exists = await conn.fetchval("SELECT to_regclass('public.secret_meta') IS NOT NULL")
        if exists:
            return False
        for statement in SCHEMA_V1:
            await conn.execute(statement)
        now = datetime.now(timezone.utc).isoformat()
        await conn.execute(
            "INSERT INTO secret_meta (key, value) VALUES ('schema_version', $1), ('created_at', $2)",
            str(SCHEMA_VERSION),
            now,
        )
        return True


class LocalPostgresStore:
    """Async Postgres implementation of SecretStore."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        master_key: str,
        salt: bytes,
        key_state: str,
        current_key_id: str,
        secrets_key: bytes,
        audit_key: bytes,
        clock: Callable[[], datetime],
        owns_pool: bool,
    ) -> None:
        self._pool = pool
        self._master_key = master_key
        self._salt = salt
        self.key_state = key_state
        self._key_id = current_key_id
        self._secrets_key = secrets_key
        self._audit_key = audit_key
        self._clock = clock
        self._owns_pool = owns_pool

    @classmethod
    async def open(
        cls,
        *,
        master_key: str,
        dsn: str | None = None,
        pool: asyncpg.Pool | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> LocalPostgresStore:
        check_master_key(master_key)
        if (dsn is None) == (pool is None):
            raise ValueError("provide exactly one of dsn or pool")
        owns_pool = pool is None
        if pool is None:
            pool = await asyncpg.create_pool(dsn, min_size=0, max_size=4)
        tick = clock or (lambda: datetime.now(timezone.utc))
        async with pool.acquire() as conn:
            if not await _tables_present(conn):
                raise SchemaMissing("secret store schema is not installed")
            salt, key_state, kid, secrets_key, audit_key = await _ensure_key(conn, master_key)
        return cls(
            pool,
            master_key=master_key,
            salt=salt,
            key_state=key_state,
            current_key_id=kid,
            secrets_key=secrets_key,
            audit_key=audit_key,
            clock=tick,
            owns_pool=owns_pool,
        )

    async def close(self) -> None:
        if self._owns_pool:
            await self._pool.close()

    async def put(
        self,
        ref: SecretRef,
        fields: dict[str, str],
        *,
        actor: Actor,
        public: dict | None = None,
    ) -> SecretMeta:
        validate_fields(fields, public=public)
        public_obj = public or {}
        record_key = ref.key()
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "SELECT version, key_id FROM secret_values "
                "WHERE namespace = $1 AND scope = $2 AND scope_id = $3 AND name = $4 "
                "FOR UPDATE",
                ref.namespace,
                ref.scope.value,
                ref.scope_id,
                ref.name,
            )
            if row is None:
                version = 1
            else:
                version = int(row["version"]) + 1
            nonce, ciphertext = seal(self._secrets_key, record_key, version, fields)
            now = self._clock()
            detail = {"via": actor.via, "version": version}
            audit_mod.reject_detail(detail, set(fields.keys()), fields)
            await conn.execute(
                """
                INSERT INTO secret_values (
                    namespace, scope, scope_id, name, version, nonce, ciphertext,
                    key_id, public, created_at, updated_at, updated_by
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$10,$11)
                ON CONFLICT (namespace, scope, scope_id, name) DO UPDATE SET
                    version = EXCLUDED.version,
                    nonce = EXCLUDED.nonce,
                    ciphertext = EXCLUDED.ciphertext,
                    key_id = EXCLUDED.key_id,
                    public = EXCLUDED.public,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
                """,
                ref.namespace,
                ref.scope.value,
                ref.scope_id,
                ref.name,
                version,
                nonce,
                ciphertext,
                self._key_id,
                json.dumps(public_obj),
                now,
                actor.service,
            )
            if self.key_state == "key_mismatch":
                await _write_key_check(conn, self._master_key, self._salt)
                self.key_state = "ok"
            event = await _insert_audit(
                conn,
                self._audit_key,
                now=now,
                event="put",
                namespace=ref.namespace,
                ref=record_key,
                service=actor.service,
                person=actor.person,
                person_verified=actor.person_verified,
                outcome="ok",
                detail=detail,
                field_names=set(fields.keys()),
                field_values=fields,
            )
            audit_mod.log_event(event)
        return await self._meta_row(ref)

    async def meta(self, ref: SecretRef) -> SecretMeta | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM secret_values "
                "WHERE namespace = $1 AND scope = $2 AND scope_id = $3 AND name = $4",
                ref.namespace,
                ref.scope.value,
                ref.scope_id,
                ref.name,
            )
        if row is None:
            return None
        return _row_to_meta(ref, row, self._key_id)

    async def list(
        self,
        namespace: str,
        scope: Scope | None = None,
        scope_id: str | None = None,
    ) -> list[SecretMeta]:
        clauses = ["namespace = $1"]
        params: list[Any] = [namespace]
        if scope is not None:
            clauses.append(f"scope = ${len(params) + 1}")
            params.append(scope.value)
        if scope_id is not None:
            clauses.append(f"scope_id = ${len(params) + 1}")
            params.append(scope_id)
        sql = "SELECT * FROM secret_values WHERE " + " AND ".join(clauses) + " ORDER BY name"
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        result: list[SecretMeta] = []
        for row in rows:
            ref = SecretRef(
                namespace=row["namespace"],
                scope=Scope(row["scope"]),
                scope_id=row["scope_id"],
                name=row["name"],
            )
            result.append(_row_to_meta(ref, row, self._key_id))
        return result

    async def delete(self, ref: SecretRef, *, actor: Actor) -> None:
        record_key = ref.key()
        async with self._pool.acquire() as conn, conn.transaction():
            bound = await conn.fetch(
                "SELECT subject FROM secret_bindings WHERE namespace = $1 "
                "AND ref_scope = $2 AND ref_scope_id = $3 AND ref_name = $4",
                ref.namespace,
                ref.scope.value,
                ref.scope_id,
                ref.name,
            )
            if bound:
                raise SecretInUse([r["subject"] for r in bound])
            deleted = await conn.execute(
                "DELETE FROM secret_values WHERE namespace = $1 AND scope = $2 "
                "AND scope_id = $3 AND name = $4",
                ref.namespace,
                ref.scope.value,
                ref.scope_id,
                ref.name,
            )
            if deleted == "DELETE 0":
                raise SecretNotFound(record_key)
            now = self._clock()
            detail = {"via": actor.via}
            event = await _insert_audit(
                conn,
                self._audit_key,
                now=now,
                event="delete",
                namespace=ref.namespace,
                ref=record_key,
                service=actor.service,
                person=actor.person,
                person_verified=actor.person_verified,
                outcome="ok",
                detail=detail,
                field_names=set(),
            )
            audit_mod.log_event(event)

    async def bind(
        self,
        namespace: str,
        subject: Subject,
        ref: SecretRef,
        *,
        actor: Actor,
        position: int | None = None,
    ) -> Binding:
        normalized = normalize_subject(subject.value)
        if position is not None and (normalized == "default" or normalized.startswith("user:")):
            raise ValueError("position is only valid for a role binding")
        if position is not None and position < 1:
            raise ValueError("position must be 1 or greater")
        if ref.namespace != namespace:
            raise ValueError("ref belongs to another namespace")
        async with self._pool.acquire() as conn, conn.transaction():
            exists = await conn.fetchval(
                "SELECT 1 FROM secret_values WHERE namespace = $1 AND scope = $2 "
                "AND scope_id = $3 AND name = $4",
                ref.namespace,
                ref.scope.value,
                ref.scope_id,
                ref.name,
            )
            if not exists:
                raise SecretNotFound(ref.key())
            now = self._clock()
            if not normalized.startswith("role:"):
                await conn.execute(
                    """
                    INSERT INTO secret_bindings (
                        namespace, subject, ref_scope, ref_scope_id, ref_name,
                        position, created_at, created_by
                    ) VALUES ($1,$2,$3,$4,$5,NULL,$6,$7)
                    ON CONFLICT (namespace, subject) DO UPDATE SET
                        ref_scope = EXCLUDED.ref_scope,
                        ref_scope_id = EXCLUDED.ref_scope_id,
                        ref_name = EXCLUDED.ref_name,
                        created_at = EXCLUDED.created_at,
                        created_by = EXCLUDED.created_by
                    """,
                    namespace,
                    normalized,
                    ref.scope.value,
                    ref.scope_id,
                    ref.name,
                    now,
                    actor.service,
                )
            else:
                await _bind_role(
                    conn,
                    namespace,
                    normalized,
                    ref,
                    position,
                    now,
                    actor.service,
                )
            detail = {"via": actor.via}
            event = await _insert_audit(
                conn,
                self._audit_key,
                now=now,
                event="bind",
                namespace=namespace,
                ref=ref.key(),
                service=actor.service,
                person=actor.person,
                person_verified=actor.person_verified,
                outcome="ok",
                detail=detail,
                field_names=set(),
            )
            audit_mod.log_event(event)
        bindings = await self.bindings(namespace)
        for item in bindings:
            if item.subject == normalized:
                return item
        raise RuntimeError("binding not found after insert")

    async def unbind(self, namespace: str, subject: Subject, *, actor: Actor) -> None:
        normalized = normalize_subject(subject.value)
        async with self._pool.acquire() as conn, conn.transaction():
            row = await conn.fetchrow(
                "SELECT ref_name, ref_scope, ref_scope_id FROM secret_bindings "
                "WHERE namespace = $1 AND subject = $2",
                namespace,
                normalized,
            )
            if row is None:
                raise SecretNotFound(f"binding {normalized}")
            if normalized.startswith("role:"):
                await _rewrite_roles_after_remove(conn, namespace, normalized)
            else:
                await conn.execute(
                    "DELETE FROM secret_bindings WHERE namespace = $1 AND subject = $2",
                    namespace,
                    normalized,
                )
            ref_key = SecretRef(
                namespace,
                Scope(row["ref_scope"]),
                row["ref_scope_id"],
                row["ref_name"],
            ).key()
            now = self._clock()
            detail = {"via": actor.via}
            event = await _insert_audit(
                conn,
                self._audit_key,
                now=now,
                event="unbind",
                namespace=namespace,
                ref=ref_key,
                service=actor.service,
                person=actor.person,
                person_verified=actor.person_verified,
                outcome="ok",
                detail=detail,
                field_names=set(),
            )
            audit_mod.log_event(event)

    async def bindings(self, namespace: str) -> list[Binding]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM secret_bindings WHERE namespace = $1 "
                "ORDER BY COALESCE(position, 1000000), subject",
                namespace,
            )
        return [_binding_from_row(row) for row in rows]

    async def resolve(
        self,
        namespace: str,
        *,
        sub: str,
        roles: Sequence[str],
    ) -> SecretRef | None:
        role_names = {_role_name(role) for role in roles}
        user_subject = "user:" + sub.lower()
        async with self._pool.acquire() as conn:
            user_row = await conn.fetchrow(
                "SELECT * FROM secret_bindings WHERE namespace = $1 AND subject = $2",
                namespace,
                user_subject,
            )
            if user_row is not None:
                ref = _ref_from_binding_row(user_row)
                if await _value_row_exists(conn, ref):
                    return ref
                return None
            role_rows = await conn.fetch(
                "SELECT * FROM secret_bindings WHERE namespace = $1 AND position IS NOT NULL "
                "ORDER BY position",
                namespace,
            )
            for row in role_rows:
                if _role_name(row["subject"]) not in role_names:
                    continue
                ref = _ref_from_binding_row(row)
                if await _value_row_exists(conn, ref):
                    return ref
            default_row = await conn.fetchrow(
                "SELECT * FROM secret_bindings WHERE namespace = $1 AND subject = 'default'",
                namespace,
            )
            if default_row is None:
                return None
            ref = _ref_from_binding_row(default_row)
            if await _value_row_exists(conn, ref):
                return ref
        return None

    async def use(
        self,
        ref: SecretRef,
        *,
        purpose: str,
        caller: Caller,
        on_behalf_of: str | None,
    ) -> dict[str, str]:
        if not caller.allows(ref.namespace, Permission.USE):
            now = self._clock()
            async with self._pool.acquire() as conn:
                event = await _insert_audit(
                    conn,
                    self._audit_key,
                    now=now,
                    event="denied",
                    namespace=ref.namespace,
                    ref=ref.key(),
                    service=caller.service,
                    person=on_behalf_of,
                    person_verified=False,
                    purpose=purpose,
                    outcome="denied",
                    code="permission",
                    field_names=set(),
                )
                audit_mod.log_event(event)
            raise PermissionDenied()
        validate_purpose(purpose)
        record_key = ref.key()
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT version, nonce, ciphertext, key_id FROM secret_values "
                "WHERE namespace = $1 AND scope = $2 AND scope_id = $3 AND name = $4",
                ref.namespace,
                ref.scope.value,
                ref.scope_id,
                ref.name,
            )
        if row is None:
            now = self._clock()
            async with self._pool.acquire() as conn:
                event = await _insert_audit(
                    conn,
                    self._audit_key,
                    now=now,
                    event="use",
                    namespace=ref.namespace,
                    ref=record_key,
                    service=caller.service,
                    person=on_behalf_of,
                    person_verified=False,
                    purpose=purpose,
                    outcome="error",
                    code="not_found",
                    field_names=set(),
                )
                audit_mod.log_event(event)
            raise SecretNotFound(record_key)
        if row["key_id"] != self._key_id:
            now = self._clock()
            async with self._pool.acquire() as conn:
                event = await _insert_audit(
                    conn,
                    self._audit_key,
                    now=now,
                    event="use",
                    namespace=ref.namespace,
                    ref=record_key,
                    service=caller.service,
                    person=on_behalf_of,
                    person_verified=False,
                    purpose=purpose,
                    outcome="error",
                    code="needs_reentry",
                    field_names=set(),
                )
                audit_mod.log_event(event)
            raise SecretUnreadable()
        try:
            values = open_(
                self._secrets_key,
                record_key,
                int(row["version"]),
                row["nonce"],
                row["ciphertext"],
            )
        except SecretUnreadable:
            now = self._clock()
            async with self._pool.acquire() as conn:
                event = await _insert_audit(
                    conn,
                    self._audit_key,
                    now=now,
                    event="use",
                    namespace=ref.namespace,
                    ref=record_key,
                    service=caller.service,
                    person=on_behalf_of,
                    person_verified=False,
                    purpose=purpose,
                    outcome="error",
                    code="needs_reentry",
                    field_names=set(),
                )
                audit_mod.log_event(event)
            raise
        now = self._clock()
        phash = audit_mod.person_hash(self._audit_key, on_behalf_of)
        async with self._pool.acquire() as conn:
            event = await _insert_audit(
                conn,
                self._audit_key,
                now=now,
                event="use",
                namespace=ref.namespace,
                ref=record_key,
                service=caller.service,
                person=on_behalf_of,
                person_verified=False,
                purpose=purpose,
                outcome="ok",
                field_names=set(),
                person_hash_override=phash,
            )
            audit_mod.log_event(event)
        return {k: str(v) for k, v in values.items()}

    async def audit(self, filter: AuditFilter) -> list[AuditEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if filter.namespace is not None:
            params.append(filter.namespace)
            clauses.append(f"namespace = ${len(params)}")
        if filter.ref is not None:
            params.append(filter.ref)
            clauses.append(f"ref = ${len(params)}")
        if filter.event is not None:
            params.append(filter.event)
            clauses.append(f"event = ${len(params)}")
        if filter.since is not None:
            params.append(filter.since)
            clauses.append(f"at >= ${len(params)}")
        sql = "SELECT * FROM secret_audit"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        params.append(filter.limit)
        sql += f" ORDER BY id LIMIT ${len(params)}"
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [_audit_from_row(row) for row in rows]

    async def health(self) -> Health:
        status = "degraded" if self.key_state == "key_mismatch" else "ok"
        async with self._pool.acquire() as conn:
            sv = await conn.fetchval("SELECT value FROM secret_meta WHERE key = 'schema_version'")
        return Health(
            status=status,
            key=self.key_state,
            backend="local-postgres",
            schema_version=int(sv or SCHEMA_VERSION),
        )

    async def rekey(self, old_key: str) -> RekeyReport:
        check_master_key(old_key)
        old_secrets = derive(old_key, self._salt, INFO_VALUES)
        resealed = 0
        already = 0
        unreadable = 0
        now = self._clock()
        async with self._pool.acquire() as conn, conn.transaction():
            rows = await conn.fetch(
                "SELECT namespace, scope, scope_id, name, version, nonce, ciphertext, key_id "
                "FROM secret_values"
            )
            for row in rows:
                if row["key_id"] == self._key_id:
                    already += 1
                    continue
                ref = SecretRef(
                    row["namespace"],
                    Scope(row["scope"]),
                    row["scope_id"],
                    row["name"],
                )
                record_key = ref.key()
                try:
                    values = open_(
                        old_secrets,
                        record_key,
                        int(row["version"]),
                        row["nonce"],
                        row["ciphertext"],
                    )
                except SecretUnreadable:
                    unreadable += 1
                    continue
                nonce, ciphertext = seal(self._secrets_key, record_key, int(row["version"]), values)
                await conn.execute(
                    "UPDATE secret_values SET nonce = $1, ciphertext = $2, key_id = $3 "
                    "WHERE namespace = $4 AND scope = $5 AND scope_id = $6 AND name = $7",
                    nonce,
                    ciphertext,
                    self._key_id,
                    ref.namespace,
                    ref.scope.value,
                    ref.scope_id,
                    ref.name,
                )
                resealed += 1
            await _write_key_check(conn, self._master_key, self._salt)
            detail = {"resealed": resealed, "unreadable": unreadable}
            event = await _insert_audit(
                conn,
                self._audit_key,
                now=now,
                event="rekey",
                namespace=None,
                ref=None,
                service="keystone-secrets",
                person=None,
                person_verified=False,
                outcome="ok",
                detail=detail,
                field_names=set(),
            )
            audit_mod.log_event(event)
        self.key_state = "ok"
        return RekeyReport(resealed=resealed, already_current=already, unreadable=unreadable)

    async def _meta_row(self, ref: SecretRef) -> SecretMeta:
        meta = await self.meta(ref)
        if meta is None:
            raise SecretNotFound(ref.key())
        return meta


async def _tables_present(conn: asyncpg.Connection) -> bool:
    return bool(await conn.fetchval("SELECT to_regclass('public.secret_values') IS NOT NULL"))


async def _value_row_exists(conn: asyncpg.Connection, ref: SecretRef) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT 1 FROM secret_values WHERE namespace = $1 AND scope = $2 "
            "AND scope_id = $3 AND name = $4",
            ref.namespace,
            ref.scope.value,
            ref.scope_id,
            ref.name,
        )
    )


async def _ensure_key(
    conn: asyncpg.Connection, master_key: str
) -> tuple[bytes, str, str, bytes, bytes]:
    async with conn.transaction():
        await conn.execute("SELECT pg_advisory_xact_lock(868002)")
        inserted_salt = await conn.fetchval(
            "INSERT INTO secret_meta (key, value) VALUES ('store_salt', $1) "
            "ON CONFLICT (key) DO NOTHING RETURNING value",
            os.urandom(16).hex(),
        )
        if inserted_salt is not None:
            check = key_check(master_key, bytes.fromhex(inserted_salt))
            await conn.execute(
                "INSERT INTO secret_meta (key, value) VALUES ('key_check', $1) "
                "ON CONFLICT (key) DO NOTHING",
                check,
            )
        row = await conn.fetchrow("SELECT value FROM secret_meta WHERE key = 'store_salt'")
        if row is None:
            raise SchemaMissing("secret store metadata is not initialized")
    salt = bytes.fromhex(row["value"])
    expected = key_check(master_key, salt)
    stored = await conn.fetchval("SELECT value FROM secret_meta WHERE key = 'key_check'")
    actual = stored or ""
    kid = key_id(expected)
    secrets_key = derive(master_key, salt, INFO_VALUES)
    audit_key = derive(master_key, salt, INFO_AUDIT_SUB)
    if not hmac.compare_digest(expected, actual):
        key_state = "key_mismatch"
    else:
        key_state = "ok"
    return salt, key_state, kid, secrets_key, audit_key


async def _write_key_check(conn: asyncpg.Connection, master_key: str, salt: bytes) -> None:
    check = key_check(master_key, salt)
    await conn.execute(
        "INSERT INTO secret_meta (key, value) VALUES ('key_check', $1) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        check,
    )


def _state_for_row(key_id_row: str, current: str) -> str:
    return "needs_reentry" if key_id_row != current else "ready"


def _row_to_meta(ref: SecretRef, row: asyncpg.Record, current_key_id: str) -> SecretMeta:
    state = _state_for_row(row["key_id"], current_key_id)
    public = row["public"]
    if isinstance(public, str):
        public = json.loads(public)
    return SecretMeta(
        ref=ref,
        version=int(row["version"]),
        state=state,
        public=public,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        updated_by=row["updated_by"],
    )


def _binding_from_row(row: asyncpg.Record) -> Binding:
    ref = SecretRef(
        row["namespace"],
        Scope(row["ref_scope"]),
        row["ref_scope_id"],
        row["ref_name"],
    )
    return Binding(
        namespace=row["namespace"],
        subject=row["subject"],
        ref=ref,
        position=row["position"],
        created_at=row["created_at"],
        created_by=row["created_by"],
    )


def _ref_from_binding_row(row: asyncpg.Record) -> SecretRef:
    return SecretRef(
        row["namespace"],
        Scope(row["ref_scope"]),
        row["ref_scope_id"],
        row["ref_name"],
    )


def _role_name(subject: str) -> str:
    return subject.split(":", 1)[1] if subject.startswith("role:") else subject


async def _bind_role(
    conn: asyncpg.Connection,
    namespace: str,
    subject: str,
    ref: SecretRef,
    position: int | None,
    now: datetime,
    by: str,
) -> int:
    await conn.execute("SET CONSTRAINTS secret_bindings_position DEFERRED")
    rows = await conn.fetch(
        "SELECT subject, ref_scope, ref_scope_id, ref_name, position, created_at, created_by "
        "FROM secret_bindings WHERE namespace = $1 AND position IS NOT NULL ORDER BY position",
        namespace,
    )
    existing = {row["subject"]: row for row in rows}
    ordered: list[tuple[str, SecretRef]] = []
    for row in rows:
        if row["subject"] == subject:
            continue
        ordered.append(
            (
                row["subject"],
                SecretRef(namespace, Scope(row["ref_scope"]), row["ref_scope_id"], row["ref_name"]),
            )
        )
    if subject in existing and position is None:
        place = int(existing[subject]["position"]) - 1
    elif position is None or position > len(ordered) + 1:
        place = len(ordered)
    else:
        place = position - 1
    ordered.insert(place, (subject, ref))
    for idx, (subj, bound_ref) in enumerate(ordered, start=1):
        if subj in existing:
            await conn.execute(
                """
                UPDATE secret_bindings SET
                    ref_scope = $1,
                    ref_scope_id = $2,
                    ref_name = $3,
                    position = $4
                WHERE namespace = $5 AND subject = $6
                """,
                bound_ref.scope.value,
                bound_ref.scope_id,
                bound_ref.name,
                -idx,
                namespace,
                subj,
            )
        else:
            await conn.execute(
                """
                INSERT INTO secret_bindings (
                    namespace, subject, ref_scope, ref_scope_id, ref_name,
                    position, created_at, created_by
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                """,
                namespace,
                subj,
                bound_ref.scope.value,
                bound_ref.scope_id,
                bound_ref.name,
                -idx,
                now,
                by,
            )
    for idx, (subj, _) in enumerate(ordered, start=1):
        await conn.execute(
            "UPDATE secret_bindings SET position = $1 WHERE namespace = $2 AND subject = $3",
            idx,
            namespace,
            subj,
        )
    return place + 1


async def _rewrite_roles_after_remove(
    conn: asyncpg.Connection, namespace: str, removed: str
) -> None:
    await conn.execute("SET CONSTRAINTS secret_bindings_position DEFERRED")
    removed_pos = await conn.fetchval(
        "SELECT position FROM secret_bindings WHERE namespace = $1 AND subject = $2",
        namespace,
        removed,
    )
    await conn.execute(
        "DELETE FROM secret_bindings WHERE namespace = $1 AND subject = $2",
        namespace,
        removed,
    )
    if removed_pos is None:
        return
    rows = await conn.fetch(
        "SELECT subject FROM secret_bindings WHERE namespace = $1 AND position IS NOT NULL "
        "ORDER BY position",
        namespace,
    )
    for idx, row in enumerate(rows, start=1):
        await conn.execute(
            "UPDATE secret_bindings SET position = $1 WHERE namespace = $2 AND subject = $3",
            -idx,
            namespace,
            row["subject"],
        )
    for idx, row in enumerate(rows, start=1):
        await conn.execute(
            "UPDATE secret_bindings SET position = $1 WHERE namespace = $2 AND subject = $3",
            idx,
            namespace,
            row["subject"],
        )


async def _insert_audit(
    conn: asyncpg.Connection,
    audit_key: bytes,
    *,
    now: datetime,
    event: str,
    namespace: str | None,
    ref: str | None,
    service: str,
    person: str | None,
    person_verified: bool,
    purpose: str | None = None,
    outcome: str,
    code: str | None = None,
    detail: dict | None = None,
    field_names: set[str],
    field_values: dict[str, str] | None = None,
    person_hash_override: str | None = None,
) -> AuditEvent:
    audit_mod.reject_detail(detail, field_names, field_values)
    phash = person_hash_override
    if phash is None and person is not None:
        phash = audit_mod.person_hash(audit_key, person)
    row_id = await conn.fetchval(
        """
        INSERT INTO secret_audit (
            at, event, namespace, ref, service, person_hash, person_verified,
            purpose, outcome, code, count, detail
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11::jsonb)
        RETURNING id
        """,
        now,
        event,
        namespace,
        ref,
        service,
        phash,
        person_verified,
        purpose,
        outcome,
        code,
        None if detail is None else json.dumps(detail),
    )
    loaded_detail = detail
    event_row = AuditEvent(
        id=int(row_id),
        at=now,
        event=event,
        namespace=namespace,
        ref=ref,
        service=service,
        person_hash=phash,
        person_verified=person_verified,
        purpose=purpose,
        outcome=outcome,
        code=code,
        count=1,
        detail=loaded_detail,
    )
    return event_row


def _audit_from_row(row: asyncpg.Record) -> AuditEvent:
    detail = row["detail"]
    if isinstance(detail, str):
        detail = json.loads(detail)
    return AuditEvent(
        id=int(row["id"]),
        at=row["at"],
        event=row["event"],
        namespace=row["namespace"],
        ref=row["ref"],
        service=row["service"],
        person_hash=row["person_hash"],
        person_verified=bool(row["person_verified"]),
        purpose=row["purpose"],
        outcome=row["outcome"],
        code=row["code"],
        count=int(row["count"]),
        detail=detail,
    )

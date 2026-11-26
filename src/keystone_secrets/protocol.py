"""Models, errors, and the SecretStore protocol."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Mapping, Protocol, Sequence, runtime_checkable
from urllib.parse import quote, unquote

_NAMESPACE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}(/[a-z0-9][a-z0-9._-]{0,63})?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PURPOSE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ROLE_SUBJECT_RE = re.compile(r"^role:[A-Za-z0-9_.-]{1,64}$")

_MAX_SCOPE_ID_LEN = 320
_MAX_FIELD_VALUE = 64 * 1024
_MAX_PUBLIC_JSON = 16 * 1024


class Scope(StrEnum):
    PLATFORM = "platform"
    CLIENT = "client"
    PROJECT = "project"
    PERSON = "person"
    ROLE = "role"
    DEFAULT = "default"


class Permission(StrEnum):
    WRITE = "write"
    READ_META = "read-meta"
    BIND = "bind"
    USE = "use"
    AUDIT = "audit"


class SecretsError(Exception):
    """Base error for keystone-secrets."""


class InvalidRef(SecretsError):
    """SecretRef or key string failed validation."""


class InvalidFields(SecretsError):
    """put() fields or public metadata failed validation."""


class SecretNotFound(SecretsError):
    """No secret at the given reference."""


class SecretInUse(SecretsError):
    """delete() refused because bindings exist."""

    def __init__(self, subjects: Sequence[str]) -> None:
        self.subjects = tuple(subjects)
        super().__init__("secret is bound: " + ", ".join(self.subjects))


class PermissionDenied(SecretsError):
    """use() caller lacks permission."""


class SecretUnreadable(SecretsError):
    """Ciphertext cannot be opened with the current master key."""


class SchemaMissing(SecretsError):
    """Required database tables are absent."""


class KeyTooShort(SecretsError):
    """Master key is shorter than 32 UTF-8 bytes."""


@dataclass(frozen=True)
class SecretRef:
    namespace: str
    scope: Scope
    scope_id: str
    name: str

    def __post_init__(self) -> None:
        self._validate(self.namespace, self.scope, self.scope_id, self.name)

    def key(self) -> str:
        ns = quote(self.namespace, safe="")
        sid = "-" if not self.scope_id else quote(self.scope_id, safe="")
        return f"{ns}/{self.scope.value}/{sid}/{self.name}"

    @classmethod
    def parse(cls, key: str) -> SecretRef:
        parts = key.split("/")
        if len(parts) != 4:
            raise InvalidRef("expected four path segments")
        namespace = unquote(parts[0])
        try:
            scope = Scope(parts[1])
        except ValueError as exc:
            raise InvalidRef("invalid scope") from exc
        raw_scope_id = parts[2]
        scope_id = "" if raw_scope_id == "-" else unquote(raw_scope_id)
        name = parts[3]
        cls._validate(namespace, scope, scope_id, name)
        return cls(namespace=namespace, scope=scope, scope_id=scope_id, name=name)

    @staticmethod
    def _validate(namespace: str, scope: Scope, scope_id: str, name: str) -> None:
        if not _NAMESPACE_RE.fullmatch(namespace):
            raise InvalidRef("invalid namespace")
        if not _NAME_RE.fullmatch(name):
            raise InvalidRef("invalid name")
        for label, value in (("namespace", namespace), ("scope_id", scope_id), ("name", name)):
            if any(character.isspace() for character in value):
                raise InvalidRef(f"{label} must not contain whitespace")
        if len(scope_id) > _MAX_SCOPE_ID_LEN:
            raise InvalidRef("scope_id too long")
        empty_ok = scope in (Scope.PLATFORM, Scope.DEFAULT)
        if empty_ok and scope_id:
            raise InvalidRef("scope_id must be empty for this scope")
        if not empty_ok and not scope_id:
            raise InvalidRef("scope_id required for this scope")
        if scope == Scope.PROJECT:
            if scope_id.count("/") != 1:
                raise InvalidRef("project scope_id must contain exactly one slash")
        elif scope_id and "/" in scope_id:
            raise InvalidRef("scope_id must not contain slash for this scope")


@dataclass(frozen=True)
class Subject:
    value: str

    @classmethod
    def parse(cls, subject: str) -> Subject:
        normalized = normalize_subject(subject)
        return cls(normalized)

    def __str__(self) -> str:
        return self.value


def normalize_subject(subject: str) -> str:
    if subject.lower().startswith("user:"):
        rest = subject.split(":", 1)[1].lower()
        if not rest or any(character.isspace() for character in rest):
            raise ValueError("invalid subject")
        return "user:" + rest
    if subject == "default":
        return subject
    if _ROLE_SUBJECT_RE.fullmatch(subject):
        return subject
    raise ValueError("invalid subject")


@dataclass(frozen=True)
class Caller:
    service: str
    grants: Mapping[str, frozenset[Permission]]

    def allows(self, namespace: str, permission: Permission) -> bool:
        perms = self.grants.get(namespace)
        if perms is None:
            return False
        return permission in perms


@dataclass(frozen=True)
class Actor:
    service: str
    person: str | None = None
    person_verified: bool = False
    via: str = "api"


@dataclass(frozen=True)
class SecretMeta:
    ref: SecretRef
    version: int
    state: str
    public: dict
    created_at: datetime
    updated_at: datetime
    updated_by: str


@dataclass(frozen=True)
class Binding:
    namespace: str
    subject: str
    ref: SecretRef
    position: int | None
    created_at: datetime
    created_by: str


@dataclass(frozen=True)
class AuditEvent:
    id: int
    at: datetime
    event: str
    namespace: str | None
    ref: str | None
    service: str
    person_hash: str | None
    person_verified: bool
    purpose: str | None
    outcome: str
    code: str | None
    count: int
    detail: dict | None


@dataclass
class AuditFilter:
    namespace: str | None = None
    ref: str | None = None
    event: str | None = None
    since: datetime | None = None
    limit: int = 1000


@dataclass(frozen=True)
class Health:
    status: str
    key: str
    backend: str
    schema_version: int


@dataclass(frozen=True)
class RekeyReport:
    resealed: int
    already_current: int
    unreadable: int


PROTOCOL_V1_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("PUT", "/v1/secrets/{ns}/{scope}/{scope_id}/{name}", "write"),
    ("GET", "/v1/secrets/{ns}/{scope}/{scope_id}/{name}", "read-meta"),
    ("DELETE", "/v1/secrets/{ns}/{scope}/{scope_id}/{name}", "write"),
    ("GET", "/v1/secrets/{ns}", "read-meta"),
    ("PUT", "/v1/bindings/{ns}", "bind"),
    ("DELETE", "/v1/bindings/{ns}", "bind"),
    ("GET", "/v1/bindings/{ns}", "bind"),
    ("POST", "/v1/resolve/{ns}", "read-meta"),
    ("POST", "/v1/use/{ns}", "use"),
    ("GET", "/v1/audit", "audit"),
    ("GET", "/v1/health", "read-meta"),
)


def validate_fields(
    fields: dict[str, str],
    *,
    public: dict | None = None,
) -> None:
    if not fields or not isinstance(fields, dict):
        raise InvalidFields("fields must be a non-empty object")
    for name, value in fields.items():
        if not _FIELD_NAME_RE.fullmatch(name):
            raise InvalidFields(f"invalid field name: {name}")
        if not isinstance(value, str):
            raise InvalidFields(f"field {name} must be a string")
        if "\x00" in value:
            raise InvalidFields(f"field {name} must not contain NUL")
        if len(value.encode("utf-8")) > _MAX_FIELD_VALUE:
            raise InvalidFields(f"field {name} exceeds size limit")
    if public is not None:
        if not isinstance(public, dict):
            raise InvalidFields("public must be an object")
        import json

        encoded = json.dumps(public, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(encoded) > _MAX_PUBLIC_JSON:
            raise InvalidFields("public exceeds size limit")
        overlap = set(public) & set(fields)
        if overlap:
            raise InvalidFields("public keys overlap fields: " + ", ".join(sorted(overlap)))


def validate_purpose(purpose: str) -> None:
    if not purpose or not _PURPOSE_RE.fullmatch(purpose):
        raise ValueError("invalid purpose")


@runtime_checkable
class SecretStore(Protocol):
    async def put(
        self,
        ref: SecretRef,
        fields: dict[str, str],
        *,
        actor: Actor,
        public: dict | None = None,
    ) -> SecretMeta: ...

    async def meta(self, ref: SecretRef) -> SecretMeta | None: ...

    async def list(
        self,
        namespace: str,
        scope: Scope | None = None,
        scope_id: str | None = None,
    ) -> list[SecretMeta]: ...

    async def delete(self, ref: SecretRef, *, actor: Actor) -> None: ...

    async def bind(
        self,
        namespace: str,
        subject: Subject,
        ref: SecretRef,
        *,
        actor: Actor,
        position: int | None = None,
    ) -> Binding: ...

    async def unbind(self, namespace: str, subject: Subject, *, actor: Actor) -> None: ...

    async def bindings(self, namespace: str) -> list[Binding]: ...

    async def resolve(
        self,
        namespace: str,
        *,
        sub: str,
        roles: Sequence[str],
    ) -> SecretRef | None: ...

    async def use(
        self,
        ref: SecretRef,
        *,
        purpose: str,
        caller: Caller,
        on_behalf_of: str | None,
    ) -> dict[str, str]: ...

    async def audit(self, filter: AuditFilter) -> list[AuditEvent]: ...

    async def health(self) -> Health: ...

from dataclasses import fields
from pathlib import Path

import yaml

from keystone_secrets.backends.local_postgres import SCHEMA_V1
from keystone_secrets.protocol import (
    PROTOCOL_V1_ROUTES,
    AuditEvent,
    Binding,
    Health,
    Permission,
    SecretMeta,
)


def _load_spec() -> dict:
    path = Path(__file__).resolve().parents[1] / "docs" / "protocol-v1.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_openapi_parses() -> None:
    spec = _load_spec()
    assert spec["openapi"].startswith("3.1")


def test_routes_match_protocol_table() -> None:
    spec = _load_spec()
    found: set[tuple[str, str, str]] = set()
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method.startswith("x-"):
                continue
            perm = op.get("x-permission")
            if perm:
                found.add((method.upper(), path, perm))
    assert found == set(PROTOCOL_V1_ROUTES)


def test_schema_fields_match_dataclasses() -> None:
    spec = _load_spec()
    schemas = spec["components"]["schemas"]
    pairs = [
        ("SecretMeta", SecretMeta),
        ("Binding", Binding),
        ("AuditEvent", AuditEvent),
        ("Health", Health),
    ]
    for name, cls in pairs:
        props = set(schemas[name]["properties"])
        dc_fields = {f.name for f in fields(cls)}
        assert props == dc_fields, name


def test_audit_event_enum_matches_ddl() -> None:
    spec = _load_spec()
    yaml_events = set(spec["components"]["schemas"]["AuditEvent"]["properties"]["event"]["enum"])
    ddl = " ".join(SCHEMA_V1)
    expected = {"put", "use", "delete", "bind", "unbind", "denied", "rekey"}
    assert yaml_events == expected
    for event in expected:
        assert f"'{event}'" in ddl


def test_permissions_are_declared() -> None:
    spec = _load_spec()
    perms = {
        op["x-permission"]
        for item in spec["paths"].values()
        for op in item.values()
        if isinstance(op, dict) and "x-permission" in op
    }
    assert perms <= {p.value for p in Permission}

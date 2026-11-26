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


_IDENTITY_OPS = {
    ("PUT", "/v1/secrets/{ns}/{scope}/{scope_id}/{name}"),
    ("DELETE", "/v1/secrets/{ns}/{scope}/{scope_id}/{name}"),
    ("PUT", "/v1/bindings/{ns}"),
    ("DELETE", "/v1/bindings/{ns}"),
    ("POST", "/v1/use/{ns}"),
}


def _header_param_names(spec: dict, op: dict) -> set[str]:
    names: set[str] = set()
    for item in op.get("parameters", []):
        if not isinstance(item, dict):
            continue
        if item.get("in") == "header" and "name" in item:
            names.add(item["name"])
            continue
        ref = item.get("$ref")
        if ref:
            ref_name = ref.rsplit("/", 1)[-1]
            param = spec["components"]["parameters"][ref_name]
            if param.get("in") == "header":
                names.add(param["name"])
    return names


def test_identity_header_on_mutating_ops() -> None:
    spec = _load_spec()
    for method, path in _IDENTITY_OPS:
        op = spec["paths"][path][method.lower()]
        names = _header_param_names(spec, op)
        assert "X-Keystone-Identity" in names, (method, path)


def test_path_params_describe_encoding() -> None:
    spec = _load_spec()
    params = spec["components"]["parameters"]
    assert "SecretRef.key()" in params["PathNs"]["description"]
    scope_id = params["PathScopeId"]["description"]
    assert "SecretRef.key()" in scope_id
    assert "`-" in scope_id or "`-`" in scope_id


def test_use_request_one_of() -> None:
    spec = _load_spec()
    use = spec["components"]["schemas"]["UseRequest"]
    assert "oneOf" in use
    names = {item["$ref"].rsplit("/", 1)[-1] for item in use["oneOf"]}
    assert names == {"UseByRef", "UseBySubject"}


def test_health_keeps_bearer_security() -> None:
    spec = _load_spec()
    health = spec["paths"]["/v1/health"]["get"]
    assert "security" not in health

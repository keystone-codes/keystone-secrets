"""Audit log helpers: detail validation, person hashing, structured logging.

Derived from stdio-box src/stdio_box/store/audit.py (Apache-2.0). Modified:
AuditEvent shape, field value rejection, logger name.
"""

import json
import logging

from keystone_secrets.crypto import sub_hash as crypto_sub_hash
from keystone_secrets.protocol import AuditEvent

logger = logging.getLogger("keystone_secrets.audit")


def person_hash(audit_key: bytes, person: str | None) -> str | None:
    if person is None:
        return None
    return crypto_sub_hash(audit_key, person)


def reject_detail(
    detail: dict | None,
    field_names: set[str],
    field_values: dict[str, str] | None = None,
) -> None:
    if detail is None:
        return
    if not isinstance(detail, dict):
        raise ValueError("detail must be an object")
    forbidden = sorted(set(detail) & field_names)
    if forbidden:
        raise ValueError("detail contains a secret field name: " + ", ".join(forbidden))
    if field_values is not None:
        for key, value in detail.items():
            if isinstance(value, str) and value in field_values.values():
                raise ValueError(f"detail value matches secret field content at {key}")


def log_event(event: AuditEvent) -> None:
    payload = {
        "id": event.id,
        "at": event.at.isoformat(),
        "event": event.event,
        "namespace": event.namespace,
        "ref": event.ref,
        "service": event.service,
        "person_hash": event.person_hash,
        "person_verified": event.person_verified,
        "purpose": event.purpose,
        "outcome": event.outcome,
        "code": event.code,
        "count": event.count,
        "detail": event.detail,
    }
    logger.info("%s", json.dumps(payload, sort_keys=True, default=str))

import json
import logging
import secrets

import pytest

from keystone_secrets.audit import log_event, person_hash, reject_detail
from keystone_secrets.crypto import INFO_AUDIT_SUB, derive
from keystone_secrets.protocol import AuditEvent


def test_reject_detail_field_name() -> None:
    with pytest.raises(ValueError, match="field name"):
        reject_detail({"api_token": "meta"}, {"api_token"})


def test_reject_detail_field_value() -> None:
    with pytest.raises(ValueError, match="matches secret"):
        reject_detail({"note": "secret-val"}, set(), {"password": "secret-val"})


def test_person_hash_length() -> None:
    key = derive(secrets.token_urlsafe(32), b"salt", INFO_AUDIT_SUB)
    hashed = person_hash(key, "alice@example.com")
    assert hashed is not None
    assert len(hashed) == 16
    assert hashed != "alice@example.com"


def test_log_event_no_raw_subject(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="keystone_secrets.audit")
    event = AuditEvent(
        id=1,
        at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        event="use",
        namespace="keystone",
        ref="keystone/client/A/s",
        service="svc",
        person_hash="abcd1234abcd1234",
        person_verified=False,
        purpose="job",
        outcome="ok",
        code=None,
        count=1,
        detail=None,
    )
    log_event(event)
    assert "alice" not in caplog.text
    payload = json.loads(caplog.records[-1].message)
    assert "person_hash" in payload

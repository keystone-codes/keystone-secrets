import os

import pytest

from keystone_secrets.crypto import (
    INFO_AUDIT_SUB,
    INFO_FORM_CSRF,
    INFO_KEY_CHECK,
    INFO_VALUES,
    check_master_key,
    derive,
    open_,
    seal,
)
from keystone_secrets.protocol import KeyTooShort, SecretUnreadable


def test_seal_round_trip(store_key: str) -> None:
    salt = os.urandom(16)
    key = derive(store_key, salt, INFO_VALUES)
    values = {"JIRA_API_TOKEN": "test-token", "note": "kept"}
    record_id = "keystone/client/A/work-account"
    nonce, ciphertext = seal(key, record_id, 1, values)
    assert len(nonce) == 12
    assert open_(key, record_id, 1, nonce, ciphertext) == values


def test_wrong_aad_is_unreadable(store_key: str) -> None:
    salt = os.urandom(16)
    key = derive(store_key, salt, INFO_VALUES)
    record_id = "keystone/client/A/work-account"
    nonce, ciphertext = seal(key, record_id, 1, {"JIRA_API_TOKEN": "test-token"})
    with pytest.raises(SecretUnreadable):
        open_(key, "keystone/client/B/work-account", 1, nonce, ciphertext)
    with pytest.raises(SecretUnreadable):
        open_(key, record_id, 2, nonce, ciphertext)


def test_info_strings_derive_different_keys(store_key: str) -> None:
    salt = os.urandom(16)
    keys = [
        derive(store_key, salt, info)
        for info in (INFO_VALUES, INFO_KEY_CHECK, INFO_FORM_CSRF, INFO_AUDIT_SUB)
    ]
    assert len(set(keys)) == len(keys)


def test_short_master_key_refused() -> None:
    with pytest.raises(KeyTooShort):
        check_master_key("short")


def test_aad_uses_ref_key(store_key: str) -> None:
    salt = os.urandom(16)
    key = derive(store_key, salt, INFO_VALUES)
    ref_key = "keystone/project/A%2Fp1/demo.token"
    nonce, ciphertext = seal(key, ref_key, 3, {"v": "1"})
    with pytest.raises(SecretUnreadable):
        open_(key, "keystone/project/A/p1/demo.token", 3, nonce, ciphertext)
    assert open_(key, ref_key, 3, nonce, ciphertext)["v"] == "1"

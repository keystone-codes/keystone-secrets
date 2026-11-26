import pytest

from keystone_secrets.protocol import (
    Caller,
    InvalidRef,
    Permission,
    Scope,
    SecretRef,
    Subject,
)


def test_secret_ref_platform_round_trip() -> None:
    ref = SecretRef("keystone", Scope.PLATFORM, "", "gateway.service_key")
    key = ref.key()
    assert key == "keystone/platform/-/gateway.service_key"
    assert SecretRef.parse(key) == ref


def test_secret_ref_project_round_trip() -> None:
    ref = SecretRef("keystone", Scope.PROJECT, "A/p1", "integrations.telegram.bot_token")
    key = ref.key()
    assert "A%2Fp1" in key
    assert SecretRef.parse(key) == ref


def test_secret_ref_slash_namespace() -> None:
    ref = SecretRef("stdio-box/atlassian", Scope.ROLE, "analyst", "work-account")
    key = ref.key()
    assert key.startswith("stdio-box%2Fatlassian/")
    assert SecretRef.parse(key) == ref


@pytest.mark.parametrize(
    "factory,msg",
    [
        (lambda: SecretRef("keystone", Scope.CLIENT, "", "name"), "scope_id required"),
        (lambda: SecretRef("keystone", Scope.PLATFORM, "x", "name"), "scope_id must be empty"),
        (lambda: SecretRef("keystone", Scope.PROJECT, "onlyone", "name"), "exactly one slash"),
        (lambda: SecretRef("keystone", Scope.CLIENT, "a b", "name"), "control"),
        (lambda: SecretRef("keystone", Scope.CLIENT, "A", "x" * 200), "invalid name"),
    ],
)
def test_invalid_ref(factory: callable, msg: str) -> None:
    with pytest.raises(InvalidRef):
        factory()


def test_subject_parse() -> None:
    assert str(Subject.parse("USER:Alice@Example.com")) == "user:alice@example.com"
    assert str(Subject.parse("role:analyst_1")) == "role:analyst_1"
    with pytest.raises(ValueError):
        Subject.parse("role:bad role")


def test_caller_allows() -> None:
    caller = Caller(
        "bridge",
        {
            "keystone": frozenset({Permission.USE, Permission.READ_META}),
            "stdio-box/foo": frozenset({Permission.WRITE}),
        },
    )
    assert caller.allows("keystone", Permission.USE)
    assert not caller.allows("keystone", Permission.WRITE)
    assert caller.allows("stdio-box/foo", Permission.WRITE)
    assert not caller.allows("other", Permission.USE)

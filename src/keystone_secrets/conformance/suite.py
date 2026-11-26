"""Shared asynchronous tests for any SecretStore implementation."""

from __future__ import annotations

import logging
import re
import secrets

import pytest

from keystone_secrets.protocol import (
    Actor,
    AuditFilter,
    Caller,
    InvalidFields,
    Permission,
    PermissionDenied,
    Scope,
    SecretInUse,
    SecretRef,
    SecretStore,
    SecretUnreadable,
    Subject,
    validate_purpose,
)

_HEX16 = re.compile(r"^[0-9a-f]{16}$")


class SecretStoreConformance:
    """Subclass and provide `make_store`, `raw_rows`, and optional hooks."""

    @pytest.fixture
    async def store(self, make_store) -> SecretStore:
        return await make_store()

    @pytest.fixture
    def actor(self) -> Actor:
        return Actor(service="test-svc", person="alice@example.com", person_verified=True)

    @pytest.fixture
    def use_caller(self) -> Caller:
        return Caller(
            service="consumer",
            grants={"keystone": frozenset({Permission.USE})},
        )

    @pytest.fixture
    def rekey_supported(self) -> bool:
        return False

    async def test_put_meta_use_round_trip(
        self, store: SecretStore, actor: Actor, use_caller: Caller
    ) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "A", "work-account")
        fields = {"api_token": "round-trip-token"}
        meta = await store.put(ref, fields, actor=actor, public={"env": "dev"})
        assert meta.version == 1
        assert meta.state == "ready"
        assert meta.public == {"env": "dev"}
        got = await store.meta(ref)
        assert got is not None
        assert got.version == 1
        used = await store.use(ref, purpose="sync", caller=use_caller, on_behalf_of="bob")
        assert used == fields
        meta2 = await store.put(ref, {"api_token": "v2"}, actor=actor)
        assert meta2.version == 2
        used2 = await store.use(ref, purpose="sync", caller=use_caller, on_behalf_of=None)
        assert used2["api_token"] == "v2"

    async def test_values_are_sealed_at_rest(
        self, store: SecretStore, actor: Actor, raw_rows
    ) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "B", "sealed")
        secret_value = "must-not-appear-plain"
        await store.put(ref, {"password": secret_value}, actor=actor)
        blob = "\n".join(await raw_rows())
        assert secret_value not in blob

    async def test_foreign_aad_is_unreadable(
        self,
        store: SecretStore,
        actor: Actor,
        use_caller: Caller,
        copy_ciphertext,
    ) -> None:
        ref_a = SecretRef("keystone", Scope.CLIENT, "C", "src")
        ref_b = SecretRef("keystone", Scope.CLIENT, "D", "dst")
        await store.put(ref_a, {"token": "aaa"}, actor=actor)
        await copy_ciphertext(ref_a, ref_b)
        with pytest.raises(SecretUnreadable):
            await store.use(ref_b, purpose="check", caller=use_caller, on_behalf_of=None)

    async def test_meta_list_never_return_values(self, store: SecretStore, actor: Actor) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "E", "meta-only")
        value = "hidden-value-xyz"
        await store.put(ref, {"x": value}, actor=actor, public={"label": "x"})
        meta = await store.meta(ref)
        assert meta is not None
        serialized = repr(meta) + repr(await store.list("keystone"))
        assert value not in serialized
        await store.bind("keystone", Subject.parse("default"), ref, actor=actor)
        binds = await store.bindings("keystone")
        assert value not in repr(binds)

    async def test_resolve_order(self, store: SecretStore, actor: Actor) -> None:
        user_ref = SecretRef("keystone", Scope.CLIENT, "U1", "user-secret")
        role_ref = SecretRef("keystone", Scope.CLIENT, "U2", "role-secret")
        def_ref = SecretRef("keystone", Scope.CLIENT, "U3", "default-secret")
        await store.put(user_ref, {"v": "u"}, actor=actor)
        await store.put(role_ref, {"v": "r"}, actor=actor)
        await store.put(def_ref, {"v": "d"}, actor=actor)
        await store.bind(
            "keystone", Subject.parse("role:analyst"), role_ref, actor=actor, position=1
        )
        await store.bind("keystone", Subject.parse("role:other"), user_ref, actor=actor, position=2)
        await store.bind("keystone", Subject.parse("default"), def_ref, actor=actor)
        got = await store.resolve("keystone", sub="alice", roles=["analyst"])
        assert got == role_ref
        await store.bind("keystone", Subject.parse("user:alice"), user_ref, actor=actor)
        got = await store.resolve("keystone", sub="alice", roles=["analyst"])
        assert got == user_ref
        got = await store.resolve("keystone", sub="bob", roles=["missing"])
        assert got == def_ref

    async def test_role_positions_without_gaps(self, store: SecretStore, actor: Actor) -> None:
        refs = [SecretRef("keystone", Scope.CLIENT, f"R{i}", f"s{i}") for i in range(1, 4)]
        for ref in refs:
            await store.put(ref, {"v": ref.name}, actor=actor)
        await store.bind("keystone", Subject.parse("role:r2"), refs[1], actor=actor, position=1)
        await store.bind("keystone", Subject.parse("role:r1"), refs[0], actor=actor, position=1)
        await store.bind("keystone", Subject.parse("role:r3"), refs[2], actor=actor, position=3)
        items = await store.bindings("keystone")
        roles = [b for b in items if b.subject.startswith("role:")]
        assert [b.position for b in roles] == [1, 2, 3]
        await store.unbind("keystone", Subject.parse("role:r2"), actor=actor)
        roles = [b for b in await store.bindings("keystone") if b.subject.startswith("role:")]
        assert [b.position for b in roles] == [1, 2]

    async def test_bind_replaces_user_and_default(self, store: SecretStore, actor: Actor) -> None:
        ref1 = SecretRef("keystone", Scope.CLIENT, "BR1", "one")
        ref2 = SecretRef("keystone", Scope.CLIENT, "BR2", "two")
        await store.put(ref1, {"v": "1"}, actor=actor)
        await store.put(ref2, {"v": "2"}, actor=actor)
        await store.bind("keystone", Subject.parse("user:alice"), ref1, actor=actor)
        await store.bind("keystone", Subject.parse("user:alice"), ref2, actor=actor)
        bindings = await store.bindings("keystone")
        users = [b for b in bindings if b.subject.startswith("user:")]
        assert len(users) == 1
        assert users[0].ref == ref2

    async def test_position_only_for_roles(self, store: SecretStore, actor: Actor) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "PO", "p")
        await store.put(ref, {"v": "x"}, actor=actor)
        with pytest.raises(ValueError):
            await store.bind("keystone", Subject.parse("user:alice"), ref, actor=actor, position=1)

    async def test_delete_bound_secret_refused(self, store: SecretStore, actor: Actor) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "DEL", "bound")
        await store.put(ref, {"v": "1"}, actor=actor)
        await store.bind("keystone", Subject.parse("default"), ref, actor=actor)
        with pytest.raises(SecretInUse):
            await store.delete(ref, actor=actor)
        await store.unbind("keystone", Subject.parse("default"), actor=actor)
        await store.delete(ref, actor=actor)
        assert await store.meta(ref) is None

    async def test_use_without_permission_denied(self, store: SecretStore, actor: Actor) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "DENY", "s")
        await store.put(ref, {"token": "t"}, actor=actor)
        no_use = Caller("x", {"keystone": frozenset({Permission.READ_META})})
        with pytest.raises(PermissionDenied):
            await store.use(ref, purpose="p", caller=no_use, on_behalf_of=None)
        wrong_ns = Caller("x", {"other": frozenset({Permission.USE})})
        with pytest.raises(PermissionDenied):
            await store.use(ref, purpose="p", caller=wrong_ns, on_behalf_of=None)
        events = await store.audit(AuditFilter(event="denied"))
        assert any(e.code == "permission" for e in events)

    async def test_use_requires_purpose(
        self, store: SecretStore, actor: Actor, use_caller: Caller
    ) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "PUR", "s")
        await store.put(ref, {"v": "1"}, actor=actor)
        with pytest.raises(ValueError):
            await store.use(ref, purpose="", caller=use_caller, on_behalf_of=None)
        with pytest.raises(ValueError):
            validate_purpose("BAD PURPOSE")

    async def test_audit_events(
        self,
        store: SecretStore,
        actor: Actor,
        use_caller: Caller,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.INFO, logger="keystone_secrets.audit")
        ref = SecretRef("keystone", Scope.CLIENT, "AUD", "s")
        await store.put(ref, {"api_token": "t"}, actor=actor)
        await store.use(ref, purpose="job", caller=use_caller, on_behalf_of="carol")
        await store.bind("keystone", Subject.parse("default"), ref, actor=actor)
        await store.unbind("keystone", Subject.parse("default"), actor=actor)
        await store.delete(ref, actor=actor)
        events = await store.audit(AuditFilter(namespace="keystone", limit=50))
        kinds = {e.event for e in events}
        assert {"put", "use", "bind", "unbind", "delete"} <= kinds
        use_row = next(e for e in events if e.event == "use" and e.outcome == "ok")
        assert use_row.purpose == "job"
        assert use_row.person_hash and _HEX16.fullmatch(use_row.person_hash)
        assert use_row.person_hash != "carol"

    async def test_audit_has_no_values_or_field_names(
        self,
        store: SecretStore,
        actor: Actor,
        raw_rows,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.INFO, logger="keystone_secrets.audit")
        ref = SecretRef("keystone", Scope.CLIENT, "LOG", "s")
        await store.put(
            ref,
            {"api_token": "super-secret-token", "password": "super-secret-pass"},
            actor=actor,
        )
        blob = "\n".join(await raw_rows()) + caplog.text
        assert "super-secret-token" not in blob
        assert "super-secret-pass" not in blob
        assert "api_token" not in blob
        assert "password" not in blob

    async def test_invalid_fields_message_has_no_value(
        self, store: SecretStore, actor: Actor
    ) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "INV", "s")
        bad = "must-not-leak-in-error"
        with pytest.raises(InvalidFields) as exc:
            await store.put(ref, {"bad name": bad}, actor=actor)
        assert bad not in str(exc.value)

    async def test_key_mismatch_then_reentry(
        self,
        store: SecretStore,
        actor: Actor,
        make_store,
        use_caller: Caller,
    ) -> None:
        ref = SecretRef("keystone", Scope.CLIENT, "KM", "s")
        await store.put(ref, {"v": "1"}, actor=actor)
        other_key = secrets.token_urlsafe(32)
        other = await make_store(other_key)
        health = await other.health()
        assert health.key == "key_mismatch"
        meta = await other.meta(ref)
        assert meta is not None
        assert meta.state == "needs_reentry"
        with pytest.raises(SecretUnreadable):
            await other.use(ref, purpose="p", caller=use_caller, on_behalf_of=None)
        await other.put(ref, {"v": "2"}, actor=actor)
        health2 = await other.health()
        assert health2.key == "ok"

    async def test_rekey_with_old_key(
        self,
        make_store,
        actor: Actor,
        use_caller: Caller,
        rekey_supported: bool,
    ) -> None:
        if not rekey_supported:
            pytest.skip("rekey not supported")
        old_key = secrets.token_urlsafe(32)
        new_key = secrets.token_urlsafe(32)
        st_old = await make_store(old_key)
        ref = SecretRef("keystone", Scope.CLIENT, "RK", "s")
        await st_old.put(ref, {"v": "1"}, actor=actor)
        await st_old.close()
        st_new = await make_store(new_key)
        assert (await st_new.health()).key == "key_mismatch"
        report = await st_new.rekey(old_key)
        assert report.unreadable == 0
        assert report.resealed >= 1
        got = await st_new.use(ref, purpose="check", caller=use_caller, on_behalf_of=None)
        assert got["v"] == "1"
        events = await st_new.audit(AuditFilter(event="rekey"))
        assert events

    async def test_rekey_without_old_key(
        self,
        make_store,
        actor: Actor,
        use_caller: Caller,
        rekey_supported: bool,
    ) -> None:
        if not rekey_supported:
            pytest.skip("rekey not supported")
        key_a = secrets.token_urlsafe(32)
        key_b = secrets.token_urlsafe(32)
        st_a = await make_store(key_a)
        ref = SecretRef("keystone", Scope.CLIENT, "RKW", "s")
        await st_a.put(ref, {"v": "1"}, actor=actor)
        await st_a.close()
        st_b = await make_store(key_b)
        report = await st_b.rekey(secrets.token_urlsafe(32))
        assert report.unreadable > 0
        meta = await st_b.meta(ref)
        assert meta is not None
        assert meta.state == "needs_reentry"

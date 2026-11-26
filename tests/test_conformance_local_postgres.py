import os
import secrets

import asyncpg
import pytest

from keystone_secrets.backends.local_postgres import (
    DROP_V1,
    LocalPostgresStore,
    install_schema,
)
from keystone_secrets.conformance.suite import SecretStoreConformance
from keystone_secrets.protocol import SecretRef


@pytest.fixture(scope="session")
def pg_dsn() -> str:
    url = os.environ.get("SECRETS_TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "Set SECRETS_TEST_DATABASE_URL=postgresql://secrets:secrets@127.0.0.1:55433/secrets_test"
        )
    return url


@pytest.fixture(autouse=True)
async def clean_schema(pg_dsn: str) -> None:
    conn = await asyncpg.connect(pg_dsn)
    try:
        for stmt in DROP_V1:
            await conn.execute(stmt)
        await install_schema(conn)
    finally:
        await conn.close()


class TestLocalPostgres(SecretStoreConformance):
    @pytest.fixture
    def rekey_supported(self) -> bool:
        return True

    @pytest.fixture
    def master_key(self) -> str:
        return secrets.token_urlsafe(32)

    @pytest.fixture
    async def make_store(self, pg_dsn: str, master_key: str):
        stores: list[LocalPostgresStore] = []

        async def factory(key: str | None = None) -> LocalPostgresStore:
            store = await LocalPostgresStore.open(master_key=key or master_key, dsn=pg_dsn)
            stores.append(store)
            return store

        yield factory
        while stores:
            st = stores.pop()
            await st.close()

    @pytest.fixture
    async def raw_rows(self, pg_dsn: str):
        async def _rows() -> list[str]:
            conn = await asyncpg.connect(pg_dsn)
            try:
                chunks: list[str] = []
                for table in ("secret_values", "secret_audit"):
                    rows = await conn.fetch(f"SELECT * FROM {table}")
                    for row in rows:
                        chunks.extend(str(v) for v in row.values() if v is not None)
                return chunks
            finally:
                await conn.close()

        return _rows

    @pytest.fixture
    async def copy_ciphertext(self, pg_dsn: str):
        async def _copy(src: SecretRef, dst: SecretRef) -> None:
            conn = await asyncpg.connect(pg_dsn)
            try:
                row = await conn.fetchrow(
                    "SELECT version, nonce, ciphertext, key_id, public, updated_by "
                    "FROM secret_values WHERE namespace=$1 AND scope=$2 AND scope_id=$3 AND name=$4",
                    src.namespace,
                    src.scope.value,
                    src.scope_id,
                    src.name,
                )
                assert row is not None
                await conn.execute(
                    """
                    INSERT INTO secret_values (
                        namespace, scope, scope_id, name, version, nonce, ciphertext,
                        key_id, public, updated_by
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
                    """,
                    dst.namespace,
                    dst.scope.value,
                    dst.scope_id,
                    dst.name,
                    row["version"],
                    row["nonce"],
                    row["ciphertext"],
                    row["key_id"],
                    row["public"],
                    row["updated_by"],
                )
            finally:
                await conn.close()

        return _copy

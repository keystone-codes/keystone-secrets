import asyncio
import os
import secrets

import asyncpg
import pytest

from keystone_secrets.backends.local_postgres import (
    DROP_V1,
    LocalPostgresStore,
    install_schema,
)
from keystone_secrets.protocol import SchemaMissing


@pytest.fixture
def pg_dsn() -> str:
    url = os.environ.get("SECRETS_TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "Set SECRETS_TEST_DATABASE_URL=postgresql://secrets:secrets@127.0.0.1:55433/secrets_test"
        )
    return url


@pytest.fixture
async def clean_db(pg_dsn: str):
    conn = await asyncpg.connect(pg_dsn)
    for stmt in DROP_V1:
        await conn.execute(stmt)
    await conn.close()


async def test_install_schema_idempotent(pg_dsn: str, clean_db: None) -> None:
    conn = await asyncpg.connect(pg_dsn)
    assert await install_schema(conn) is True
    assert await install_schema(conn) is False
    await conn.close()


async def test_open_without_schema(pg_dsn: str, clean_db: None) -> None:
    key = secrets.token_urlsafe(32)
    with pytest.raises(SchemaMissing):
        await LocalPostgresStore.open(master_key=key, dsn=pg_dsn)


async def test_parallel_open_single_salt(pg_dsn: str, clean_db: None) -> None:
    conn = await asyncpg.connect(pg_dsn)
    await install_schema(conn)
    await conn.close()
    key = secrets.token_urlsafe(32)

    async def _open() -> LocalPostgresStore:
        return await LocalPostgresStore.open(master_key=key, dsn=pg_dsn)

    stores = await asyncio.gather(_open(), _open())
    try:
        conn = await asyncpg.connect(pg_dsn)
        try:
            row = await conn.fetchval("SELECT value FROM secret_meta WHERE key='store_salt'")
        finally:
            await conn.close()
        salt = bytes.fromhex(row)
        assert salt
        for opened in stores:
            assert (await opened.health()).key == "ok"
    finally:
        for store in stores:
            await store.close()


async def test_drop_v1_removes_tables(pg_dsn: str, clean_db: None) -> None:
    conn = await asyncpg.connect(pg_dsn)
    await install_schema(conn)
    for stmt in DROP_V1:
        await conn.execute(stmt)
    missing = await conn.fetchval(
        "SELECT NOT EXISTS (SELECT 1 FROM information_schema.tables "
        "WHERE table_name = 'secret_values')"
    )
    assert missing
    await conn.close()

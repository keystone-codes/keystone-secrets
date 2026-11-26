import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path

import asyncpg
import pytest

from keystone_secrets.backends.local_postgres import DROP_V1, install_schema


@pytest.fixture
def pg_dsn() -> str:
    url = os.environ.get("SECRETS_TEST_DATABASE_URL")
    if not url:
        pytest.skip("SECRETS_TEST_DATABASE_URL is not set")
    return url


@pytest.fixture
async def schema_ready(pg_dsn: str):
    conn = await asyncpg.connect(pg_dsn)
    for stmt in DROP_V1:
        await conn.execute(stmt)
    await install_schema(conn)
    await conn.close()


def _run_cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    full_env = os.environ.copy()
    full_env["PYTHONPATH"] = str(root / "src")
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "keystone_secrets.cli", *args],
        capture_output=True,
        text=True,
        env=full_env,
        cwd=str(root),
    )


def test_put_value_file_mode_644(pg_dsn: str, schema_ready: None, tmp_path: Path) -> None:
    secret = "cli-secret-value"
    path = tmp_path / "val.txt"
    path.write_text(secret, encoding="utf-8")
    path.chmod(0o644)
    key = secrets.token_urlsafe(32)
    proc = _run_cli(
        "put",
        "keystone",
        "client",
        "CLI1",
        "demo",
        "--value-file",
        str(path),
        env={"SECRETS_DATABASE_URL": pg_dsn, "KEYSTONE_SECRETS_KEY": key},
    )
    assert proc.returncode == 2
    assert secret not in proc.stdout + proc.stderr


def test_put_value_file_mode_600(pg_dsn: str, schema_ready: None, tmp_path: Path) -> None:
    secret = "cli-secret-value-600"
    path = tmp_path / "val.txt"
    path.write_text(secret, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    key = secrets.token_urlsafe(32)
    proc = _run_cli(
        "put",
        "keystone",
        "client",
        "CLI2",
        "demo",
        "--value-file",
        str(path),
        env={"SECRETS_DATABASE_URL": pg_dsn, "KEYSTONE_SECRETS_KEY": key},
    )
    assert proc.returncode == 0
    assert "version=1" in proc.stdout
    assert secret not in proc.stdout + proc.stderr


def test_put_from_file_json(pg_dsn: str, schema_ready: None, tmp_path: Path) -> None:
    fields = {"token": "from-json"}
    path = tmp_path / "fields.json"
    path.write_text(json.dumps(fields), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    key = secrets.token_urlsafe(32)
    proc = _run_cli(
        "put",
        "keystone",
        "client",
        "CLI3",
        "demo",
        "--from-file",
        str(path),
        env={"SECRETS_DATABASE_URL": pg_dsn, "KEYSTONE_SECRETS_KEY": key},
    )
    assert proc.returncode == 0
    assert fields["token"] not in proc.stdout


def test_rekey_exit_codes(pg_dsn: str, schema_ready: None, tmp_path: Path) -> None:
    old_key = secrets.token_urlsafe(32)
    new_key = secrets.token_urlsafe(32)
    val = tmp_path / "v.txt"
    val.write_text("v1", encoding="utf-8")
    val.chmod(stat.S_IRUSR | stat.S_IWUSR)
    env_base = {"SECRETS_DATABASE_URL": pg_dsn}
    assert (
        _run_cli(
            "put",
            "keystone",
            "client",
            "RK",
            "s",
            "--value-file",
            str(val),
            env={**env_base, "KEYSTONE_SECRETS_KEY": old_key},
        ).returncode
        == 0
    )
    old_file = tmp_path / "old.key"
    old_file.write_text(old_key, encoding="utf-8")
    old_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    bad_old = tmp_path / "wrong.key"
    bad_old.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    bad_old.chmod(stat.S_IRUSR | stat.S_IWUSR)
    bad = _run_cli(
        "rekey",
        "--old-key-file",
        str(bad_old),
        env={**env_base, "KEYSTONE_SECRETS_KEY": new_key},
    )
    assert bad.returncode == 3
    good = _run_cli(
        "rekey",
        "--old-key-file",
        str(old_file),
        env={**env_base, "KEYSTONE_SECRETS_KEY": new_key},
    )
    assert good.returncode == 0


def test_missing_master_key(pg_dsn: str, schema_ready: None, tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    stub = tmp_path / "v.txt"
    stub.write_text("x", encoding="utf-8")
    stub.chmod(stat.S_IRUSR | stat.S_IWUSR)
    env = {k: v for k, v in os.environ.items() if k != "KEYSTONE_SECRETS_KEY"}
    env["SECRETS_DATABASE_URL"] = pg_dsn
    env["PYTHONPATH"] = str(root / "src")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "keystone_secrets.cli",
            "put",
            "keystone",
            "client",
            "X",
            "n",
            "--value-file",
            str(stub),
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(root),
    )
    assert proc.returncode == 2

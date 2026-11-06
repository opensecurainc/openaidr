"""Real invitation API and sessions in an isolated PostgreSQL schema."""

import os
from pathlib import Path
import signal
import sys
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "packages/common/src"))

import psycopg
from psycopg.conninfo import make_conninfo
import uvicorn

from openaidr.server.app import create_app
from openaidr.server.auth import hash_password
from openaidr.server.config import Config
from openaidr.server.store import Store, hash_token


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    url = os.environ["OPENAIDR_TEST_DATABASE_URL"]
    schema = "invitation_browser_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as connection:
        connection.execute(f"CREATE SCHEMA {schema}")
    st = Store(make_conninfo(url, options=f"-c search_path={schema}"))
    try:
        st.migrate()
        tenant = st.bootstrap_tenant("Invitation test", "invitation-test")["tenant"]
        password = hash_password("invitation-test-password")
        for role in ("owner", "admin", "analyst", "viewer"):
            st.create_user(tenant["id"], f"{role}@example.invalid", f"Test {role}", password, role)
        expired = st.create_invite(tenant["id"], "expired@example.invalid", "viewer", ttl=-1)
        st.execute(
            "UPDATE invites SET token_hash=$2 WHERE id=$1",
            expired["id"], hash_token("expired-browser-invitation"),
        )
        cfg = Config(
            database_url=st.url,
            public_url=os.environ.get("OPENAIDR_DEMO_URL", "http://127.0.0.1:3121"),
        )
        cfg.set_services("api")
        uvicorn.run(
            create_app(cfg, st), host="127.0.0.1",
            port=int(os.environ.get("OPENAIDR_INVITATION_TEST_API_PORT", "8787")),
            log_level="warning",
        )
    finally:
        st.close()
        with psycopg.connect(url, autocommit=True) as connection:
            connection.execute(f"DROP SCHEMA {schema} CASCADE")


if __name__ == "__main__":
    main()

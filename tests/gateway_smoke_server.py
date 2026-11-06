"""Disposable real backend for Kong smoke tests; only classifier transport is fake.

Run with PYTHONPATH=src and OPENAIDR_TEST_DATABASE_URL. Each run owns a fresh
PostgreSQL schema, which is removed on graceful shutdown. Credential files are
0600. The database must be disposable and dedicated to tests.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import httpx
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
import uvicorn
from pytest import MonkeyPatch
from intelligence_fixture import intelligence_service

from openaidr.server import auth, gateways
from openaidr.server.app import create_app
from openaidr.server.config import Config
from openaidr.server.guardrail import inline, scoring
from openaidr.server.store import Store, new_id


def private_file(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content if isinstance(content, bytes) else content.encode())


def certificates(state):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenAIDR gateway smoke test")])
    stamp = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(stamp-timedelta(minutes=1))
            .not_valid_after(stamp+timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("host.docker.internal"), x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    private_file(state / "key.pem", key.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_file(state / "ca.pem", cert.public_bytes(serialization.Encoding.PEM))


async def classifier(request):
    payload = json.loads(request.content)
    target = payload["state"]["target_event"]
    deny = any("gateway-deny" in message["content"] for message in target["messages"])
    return httpx.Response(200, json={
        "model": scoring.MODEL,
        "answers": {
            "category": {"type": "choice", "choice": "secret_exfiltration" if deny else "none", "confidence": 0.9},
            "severity": {"type": "score", "score": 4 if deny else 0, "confidence": 0.9},
        },
        "usage": {"input_tokens": 100, "output_tokens": 10},
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--public-url", help="Dashboard browser origin; defaults to this backend's HTTPS origin")
    args = parser.parse_args()
    state = args.state_dir.resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    url = os.environ["OPENAIDR_TEST_DATABASE_URL"]
    schema = "gateway_smoke_" + new_id().replace("-", "")
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    st = Store(make_conninfo(url, options="-c search_path=" + schema))
    try:
        st.migrate()
        tenant = st.create_tenant("Gateway smoke test", schema, default_rules=[])
        user = st.create_user(tenant["id"], schema + "@example.test", "Smoke operator", "unused", "owner")
        actor = {"type": "user", "id": user["id"], "name": user["name"]}
        inline.save_settings(st, tenant["id"],
                             {"enabled": True, "ask_threshold": 40, "block_threshold": 80, "timeout_ms": 10000}, actor)
        manifest = {"schema": schema, "tenant_id": tenant["id"], "gateways": {}, "port": args.port}
        for label in ("metadata", "shadow", "enforce"):
            created, _ = gateways.console(st, tenant["id"], "POST", "gateways", {"name": label}, {}, actor)
            gateway = created["gateway"]
            if label != "metadata":
                gateways.console(st, tenant["id"], "PUT", "gateways/" + gateway["id"] + "/settings",
                                 {"version": 1, "mode": label, "capture_content": True, "policy_rule_ids": []}, {}, actor)
            manifest["gateways"][label] = gateway["id"]
            private_file(state / (label + ".token"), created["credential"]["token"])
        cfg = Config(database_url=st.url, public_url=args.public_url or f"https://localhost:{args.port}",
                     tenant_id=tenant["id"], cost_processing=False)
        cfg.set_services("api,ingest")
        private_file(state / "operator.json", json.dumps({
            "Cookie": auth.cookie_name(secure=cfg.secure_cookie()) + "=" + st.create_session(user["id"], tenant["id"]),
            auth.CSRF_HEADER: "1",
        }))
        private_file(state / "manifest.json", json.dumps(manifest, indent=2))
        certificates(state)
        print("Gateway smoke backend state: " + str(state), flush=True)
        with MonkeyPatch.context() as patch, intelligence_service(
            patch, state, tenant["id"], classifier, guardrail_key="gateway-smoke-fake-key"
        ) as api:
            cfg.intelligence_origin = api.connection.origin
            cfg.intelligence_api_key = api.connection.api_key
            uvicorn.run(create_app(cfg, st), host="0.0.0.0", port=args.port,
                        ssl_keyfile=str(state / "key.pem"), ssl_certfile=str(state / "ca.pem"), access_log=False)

    finally:
        st.close()
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    main()

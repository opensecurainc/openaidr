"""The actual bundled plugin through local and authenticated tenant accounting."""

from datetime import datetime, timezone
from decimal import Decimal
import json
import os
import shutil
import subprocess
import threading
import time

import pytest
from fastapi.testclient import TestClient

from openaidr.core.agent_usage import extract
from openaidr.core.telemetry import decode_export
from openaidr.sensor import hook_opencode, hooks
from openaidr.sensor.telemetry import Telemetry
from openaidr.server.agent_cost_usage import overview, process_pending
from openaidr.server.app import create_app
from test_telemetry_sensor import config
from test_telemetry_server import backend  # noqa: F401


def run_plugin(tmp_path, options):
    node = shutil.which("node")
    assert node, "Node.js is required to verify the bundled plugin"
    plugin = tmp_path / "openaidr.mjs"
    plugin.write_text(hook_opencode.render({"telemetry": options}))
    runner = tmp_path / "usage.mjs"
    runner.write_text('''
import {OpenAIDR} from './openaidr.mjs';
const hooks = await OpenAIDR({directory:'/work/project'});
const emit = (type, properties) => hooks.event({event:{type, properties}});
const initial = {id:'message',sessionID:'session',role:'assistant',modelID:'reported-model',providerID:'provider',
  time:{created:Date.now()},cost:0,tokens:{input:0,output:0,reasoning:0,cache:{read:0,write:0}},
  private:'PRIVATE-PROMPT'};
const part = {id:'step-1',sessionID:'session',messageID:'message',type:'step-finish',
  cost:0.25,tokens:{input:30,output:15,reasoning:5,cache:{read:60,write:10}},private:'PRIVATE-OUTPUT'};
await emit('message.updated',{info:initial});
await emit('message.part.updated',{part});
await emit('message.part.updated',{part});
await emit('message.part.updated',{part:{...part,id:'step-2',cost:0}});
await emit('message.part.updated',{part:{...part,id:'invalid',tokens:{...part.tokens,input:-1}}});
await emit('message.updated',{info:{...initial,time:{created:1,completed:2},cost:0.5,tokens:part.tokens}});
await emit('message.part.updated',{part:{...part,id:'late'}});
// Fork/import events copy completed messages and assign new step IDs.
await emit('message.updated',{info:{...initial,id:'copy',sessionID:'fork',time:{created:1,completed:2},cost:0.5,tokens:part.tokens}});
await emit('message.part.updated',{part:{...part,id:'copied-step',messageID:'copy',sessionID:'fork'}});
// A fork of an in-progress message can already contain completed model steps.
await emit('message.updated',{info:{...initial,id:'running-copy',sessionID:'fork',cost:0.5,finish:'tool-calls',tokens:part.tokens}});
await emit('message.part.updated',{part:{...part,id:'running-copy-step',messageID:'running-copy',sessionID:'fork'}});
''')
    result = subprocess.run([node, str(runner)], text=True, capture_output=True, timeout=10)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", ""), result


def test_plugin_usage_reaches_local_and_tenant_ledgers_once(tmp_path, sensor_executable, backend):
    st, server_cfg, sensor, token, other, other_token, _ = backend
    cfg = config(tmp_path)
    telemetry = Telemetry(cfg)
    stop = threading.Event()
    worker = threading.Thread(target=telemetry.receive, args=(stop,))
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while telemetry.bound_address is None:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        cfg["telemetry"]["listen"] = f"127.0.0.1:{telemetry.bound_address[1]}"
        cfg.save()
        plugin = tmp_path / "installed.js"
        hooks.install(plugin, sensor_executable, "opencode", config_path=cfg.path)
        options = hook_opencode.read(plugin)["telemetry"]
        assert "token" not in options
        run_plugin(tmp_path, options)
        assert tuple(telemetry.queue.db.execute("SELECT count(*),sum(tokens),sum(cost_usd) FROM usage_calls").fetchone()) == (2, 240, 0.25)
        assert telemetry.queue.db.execute("SELECT application FROM usage_apps LIMIT 1").fetchone()[0] == "opencode"
        with TestClient(create_app(server_cfg, st)) as client:
            while batch := telemetry.queue.next():
                data = decode_export("logs", batch["body"], batch["content_type"])
                assert "PRIVATE-" not in json.dumps(data)
                event, = extract({"id": batch["batch_id"], "sensor_id": "sensor", "payload": data,
                                  "received_at": datetime.now(timezone.utc)})
                assert event["usage"]["output_tokens"] == 20
                assert event["usage"]["tokens"] == 120
                for bearer, expected in ((other_token, 403), (token, 200), (token, 200)):
                    result = client.post("/otlp/v1/logs", content=batch["body"], headers={
                        "Authorization": "Bearer " + bearer, "Content-Type": batch["content_type"],
                    })
                    assert result.status_code == expected, result.text
                telemetry.queue.confirm(batch["batch_id"])
        assert process_pending(st)["failed"] == 0
        summary = overview(st, sensor["tenant_id"])["summary"]
        assert summary["calls"] == 2 and summary["tokens"] == 240
        assert Decimal(summary["cost_usd"]) == Decimal("0.25")
        assert summary["unpriced_calls"] == 1
        assert overview(st, other["tenant_id"])["summary"]["calls"] == 0
        # Receiver failures remain quiet and cannot deny an agent action.
        run_plugin(tmp_path, {"endpoint": "http://127.0.0.1:1/v1/logs", "token": "unavailable"})
    finally:
        stop.set()
        worker.join(timeout=3)
        telemetry.close()


def test_plugin_ignores_control_credentials_and_respects_usage_opt_out(tmp_path, sensor_executable):
    cfg = config(tmp_path, local_token="first-local-token", listen="127.0.0.1:4318")
    plugin = tmp_path / "openaidr.js"
    hooks.install(plugin, sensor_executable, "opencode", config_path=cfg.path)
    assert hook_opencode.current(plugin, cfg.path)
    if os.name != "nt":
        assert plugin.stat().st_mode & 0o777 == 0o600
    cfg["telemetry"]["local_token"] = "rotated-local-token"
    cfg.save()
    assert hook_opencode.current(plugin, cfg.path)
    assert "token" not in hook_opencode.read(plugin)["telemetry"]
    cfg["telemetry"]["disabled_agents"] = ["opencode"]
    cfg.save()
    hooks.install(plugin, sensor_executable, "opencode", config_path=cfg.path)
    assert hook_opencode.read(plugin)["telemetry"] is None
    assert hook_opencode.current(plugin, cfg.path)
    cfg["telemetry"].update(disabled_agents=[], listen="192.0.2.1:4318")
    cfg.save()
    with pytest.raises(ValueError, match="loopback"):
        hooks.install(plugin, sensor_executable, "opencode", config_path=cfg.path)
    assert hook_opencode.read(plugin)["telemetry"] is None

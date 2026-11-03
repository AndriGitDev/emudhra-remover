import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from emudhra_remover.server import create_server


async def test_mcp_full_workflow(service):
    app, path, _ = service
    original = path.read_bytes()
    async with create_connected_server_and_client_session(create_server(app)) as session:
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == {
            "list_targets",
            "scan_target",
            "plan_removal",
            "inspect_plan",
            "apply_plan",
            "rollback_plan",
        }
        apply = next(t for t in tools if t.name == "apply_plan")
        assert apply.annotations.destructiveHint is True
        scan = await session.call_tool("scan_target", {"target_id": "test"})
        assert not scan.isError
        planned = await session.call_tool("plan_removal", {"target_id": "test"})
        plan_id = planned.structuredContent["plan_id"]
        result = await session.call_tool("apply_plan", {"plan_id": plan_id})
        assert not result.isError
        result = await session.call_tool("rollback_plan", {"plan_id": plan_id})
        assert not result.isError
        assert path.read_bytes() == original


async def test_real_stdio_server_defaults_to_read_only(service, tmp_path):
    app, _path, _ = service
    inventory = tmp_path / "inventory.json"
    inventory.write_text(app.inventory.model_dump_json())
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "emudhra_remover.server"],
        env={
            **os.environ,
            "EMUDHRA_INVENTORY": str(inventory),
            "EMUDHRA_STATE_DIR": str(tmp_path / "stdio-state"),
            "EMUDHRA_ENABLE_WRITES": "0",
        },
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("scan_target", {"target_id": "test"})
            assert not result.isError
            assert result.structuredContent["certificates_scanned"] == 2
            assert result.structuredContent["matches"] == []  # production policy, synthetic certs
            result = await session.call_tool("apply_plan", {"plan_id": "fake"})
            assert result.isError
            incident = await session.read_resource("incident://emudhra/2026-10")
            assert len(json.loads(incident.contents[0].text)["certificates"]) == 23

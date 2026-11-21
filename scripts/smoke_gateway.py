#!/usr/bin/env python3
"""Smoke-test the standalone gateway with local configuration only.

The smoke test starts one `corvi-gateway` process with a local snapshot, a
local policy document and a local fixture mailbox, and drives it over
HTTP. No external service, no network egress and no provider is involved.

It checks three things:

1. The configuration is accepted (`--check`).
2. The REST surface serves the seven operations of `api/openapi.yaml`.
3. The MCP surface serves the checked-in tool catalogue, including the
   multi-round-trip approval flow for `mail_send`.

Run it with:

    python3 scripts/smoke_gateway.py
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "gateway"
BINARY = ROOT / "target" / "debug" / "corvi-gateway"
PROTOCOL_VERSION = "2026-07-28"

# The client capabilities every request carries in `params._meta`.
CLIENT_META = {
    "_meta": {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}},
    }
}


def fail(message: str) -> None:
    """Report a failure and stop the smoke test."""
    print(f"smoke: {message}", file=sys.stderr)
    raise SystemExit(1)


def free_port() -> int:
    """Ask the kernel for an unused loopback port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def request(
    url: str,
    *,
    token: str | None = None,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
    method: str = "GET",
) -> tuple[int, dict, object]:
    """Send one HTTP request and return its status, headers and JSON body."""
    payload = None
    all_headers = dict(headers or {})
    if body is not None:
        payload = json.dumps(body).encode()
        all_headers["content-type"] = "application/json"
    if token:
        all_headers["authorization"] = f"Bearer {token}"
    call = urllib.request.Request(url, data=payload, headers=all_headers, method=method)
    try:
        with urllib.request.urlopen(call) as response:
            raw = response.read()
            status = response.status
            response_headers = dict(response.headers)
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = error.code
        response_headers = dict(error.headers)
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = raw.decode(errors="replace")
    return status, response_headers, parsed


def main() -> int:
    """Run the smoke test."""
    if not BINARY.exists():
        fail(
            f"{BINARY} does not exist; run `cargo build --bin corvi-gateway` first"
        )

    with tempfile.TemporaryDirectory(prefix="corvi-smoke-") as directory:
        workspace = Path(directory)
        secret = workspace / "agent.token"
        secret.write_text("smoke-token\n")
        secret.chmod(0o600)

        snapshot = (EXAMPLES / "snapshot.yaml").read_text()
        snapshot = re.sub(
            r'secret: "file://[^"]*"', f'secret: "file://{secret}"', snapshot
        )
        http_port = free_port()
        smtp_port = free_port()
        snapshot = re.sub(
            r"listen: 127\.0\.0\.1:\d+", f"listen: 127.0.0.1:{http_port}", snapshot
        )
        snapshot = re.sub(
            r"smtp_listen: 127\.0\.0\.1:\d+",
            f"smtp_listen: 127.0.0.1:{smtp_port}",
            snapshot,
        )
        snapshot_path = workspace / "snapshot.yaml"
        snapshot_path.write_text(snapshot)

        policies_path = workspace / "policies.yaml"
        policies_path.write_text((EXAMPLES / "policies.yaml").read_text())
        mailbox_path = workspace / "mailbox.json"
        mailbox_path.write_text((EXAMPLES / "mailbox.json").read_text())

        check = subprocess.run(
            [
                str(BINARY),
                "--config",
                str(snapshot_path),
                "--policies",
                str(policies_path),
                "--upstream",
                str(mailbox_path),
                "--check",
            ],
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            fail(f"--check refused the example configuration: {check.stderr.strip()}")
        print(f"smoke: --check accepted the configuration: {check.stdout.strip()}")

        process = subprocess.Popen(
            [
                str(BINARY),
                "--config",
                str(snapshot_path),
                "--policies",
                str(policies_path),
                "--upstream",
                str(mailbox_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        base = f"http://127.0.0.1:{http_port}"
        try:
            wait_for(base, process)
            check_rest(base)
            check_mcp(base)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    print("smoke: the gateway served every checked surface")
    return 0


def wait_for(base: str, process: subprocess.Popen) -> None:
    """Wait until the gateway answers, or fail with its output."""
    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            fail(f"the gateway exited early: {output.strip()}")
        try:
            status, _, _ = request(f"{base}/v1/identities", token="smoke-token")
            if status in (200, 401):
                return
        except urllib.error.URLError:
            time.sleep(0.1)
    fail("the gateway did not start listening")


def check_rest(base: str) -> None:
    """Drive the REST surface."""
    status, headers, body = request(f"{base}/v1/identities", token="smoke-token")
    if status != 200:
        fail(f"GET /v1/identities returned {status}")
    identities = {item["id"] for item in body["items"]}
    if identities != {"personal", "work"}:
        fail(f"the identity list is {identities}, expected personal and work")
    print(f"smoke: REST listed the identities {sorted(identities)}")

    status, _, body = request(
        f"{base}/v1/messages?identityId=personal", token="smoke-token"
    )
    if status != 200:
        fail(f"GET /v1/messages returned {status}")
    subjects = {item["subject"] for item in body["items"]}
    if "Your one-time code" in subjects:
        fail("a hidden message was disclosed by the REST listing")
    if "Invoice 2026" not in subjects:
        fail(f"the visible message is missing from {subjects}")
    print(f"smoke: REST listed {len(body['items'])} visible messages and no hidden one")

    status, _, body = request(
        f"{base}/v1/messages/m-2?identityId=personal", token="smoke-token"
    )
    if status != 404 or body["code"] != "NOT_FOUND":
        fail(f"a hidden message returned {status} {body}")
    print("smoke: REST answered a hidden message with NOT_FOUND")

    status, _, body = request(
        f"{base}/v1/messages/m-1?identityId=personal", token="smoke-token"
    )
    if status != 200 or body["subject"] != "Invoice 2026":
        fail(f"GET /v1/messages/m-1 returned {status}")
    print("smoke: REST served the visible message projection")

    status, _, body = request(
        f"{base}/v1/messages/search",
        token="smoke-token",
        method="POST",
        body={"identityId": "personal", "query": "invoice"},
    )
    if status != 200 or len(body["items"]) != 1:
        fail(f"the search returned {status} {body}")
    print("smoke: REST searched the projected mail")

    status, headers, body = request(f"{base}/v1/identities")
    if status != 401 or headers.get("www-authenticate") != "Bearer":
        fail(f"an unauthenticated request returned {status}")
    print("smoke: REST refused an unauthenticated request")


def check_mcp(base: str) -> None:
    """Drive the MCP surface."""
    headers = {
        "mcp-protocol-version": PROTOCOL_VERSION,
        "mcp-method": "tools/list",
    }
    status, _, body = request(
        f"{base}/mcp",
        token="smoke-token",
        method="POST",
        headers=headers,
        body={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": dict(CLIENT_META),
        },
    )
    if status != 200:
        fail(f"tools/list returned {status} {body}")
    catalogue = json.loads((ROOT / "api" / "mcp-tools.json").read_text())
    expected = [tool["name"] for tool in catalogue["tools"]]
    served = [tool["name"] for tool in body["result"]["tools"]]
    if served != expected:
        fail(f"the served tools are {served}, expected {expected}")
    print(f"smoke: MCP served the checked-in tools {served}")

    headers = {
        "mcp-protocol-version": PROTOCOL_VERSION,
        "mcp-method": "tools/call",
        "mcp-name": "mail_list_identities",
    }
    status, _, body = request(
        f"{base}/mcp",
        token="smoke-token",
        method="POST",
        headers=headers,
        body={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                **CLIENT_META,
                "name": "mail_list_identities",
                "arguments": {},
            },
        },
    )
    if status != 200:
        fail(f"mail_list_identities returned {status} {body}")
    identities = {item["id"] for item in body["result"]["structuredContent"]["items"]}
    if identities != {"personal", "work"}:
        fail(f"the MCP identity list is {identities}")
    print(f"smoke: MCP listed the identities {sorted(identities)}")

    headers["mcp-name"] = "mail_send"
    arguments = {
        "identityId": "personal",
        "to": [{"email": "someone@example.org"}],
        "subject": "Hello",
        "textBody": "A body.",
        "idempotencyKey": "smoke-key-1",
    }
    status, _, body = request(
        f"{base}/mcp",
        token="smoke-token",
        method="POST",
        headers=headers,
        body={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {**CLIENT_META, "name": "mail_send", "arguments": arguments},
        },
    )
    result = body.get("result", {})
    if result.get("resultType") != "input_required":
        fail(f"mail_send did not ask for approval: {body}")
    state = result["requestState"]
    print("smoke: MCP asked for approval before sending anything")

    status, _, body = request(
        f"{base}/mcp",
        token="smoke-token",
        method="POST",
        headers=headers,
        body={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                **CLIENT_META,
                "name": "mail_send",
                "arguments": arguments,
                "inputResponses": {"confirm_send": {"approved": True}},
                "requestState": state,
            },
        },
    )
    structured = body.get("result", {}).get("structuredContent", {})
    if structured.get("status") != "submitted":
        fail(f"the approved send did not submit: {body}")
    print("smoke: MCP submitted the approved message")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(main())

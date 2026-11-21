# Corvi MCP skill examples

These are the request and response bodies the
[skill](../SKILL.md) refers to. They are illustrative: the identifiers and
timestamps are placeholders, and the `requestState` is a sealed value the
server minted, not something a client may construct.

| File | What it shows |
| --- | --- |
| [`tools-list-request.json`](tools-list-request.json) | The headers and `_meta` every request carries |
| [`mail-list-identities-request.json`](mail-list-identities-request.json) | Discovering the identities one token may act on |
| [`mail-list-identities-response.json`](mail-list-identities-response.json) | Two identities with independent permissions |
| [`mail-send-request.json`](mail-send-request.json) | The first send round trip, which sends nothing |
| [`mail-send-approval-response.json`](mail-send-approval-response.json) | The approval the server asks for |
| [`mail-send-approved-request.json`](mail-send-approved-request.json) | The second send round trip, with the user's answer |
| [`mail-send-submitted-response.json`](mail-send-submitted-response.json) | The recorded submission |

The gateway's own example configuration lives in
[`examples/gateway/`](../../../examples/gateway), and the machine-readable
contract lives in [`api/mcp-tools.json`](../../../api/mcp-tools.json).

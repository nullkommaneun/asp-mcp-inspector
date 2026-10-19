<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Thomas Ehrler
-->

# ASP MCP Inspector

A small [Model Context Protocol](https://modelcontextprotocol.io) server and command-line tool for the
**Agent-Shelter Protocol (ASP)** — an open RFC 9457 HTTP loop-termination and telemetry specification
([github.com/nullkommaneun/agent-shelter-protocol](https://github.com/nullkommaneun/agent-shelter-protocol)) with a
live reference node at [agent-shelter.org](https://agent-shelter.org).

It gives an AI agent three tools:

| Tool | Request | What the agent gets |
|---|---|---|
| `check_asp_manifest(domain_or_url)` | `GET <origin>/.well-known/agent-shelter.json` (default: `https://agent-shelter.org`) | Whether the host speaks ASP: protocol version, compliance level, ingress routes, transport envelope, receipt-signing key, recording rules |
| `probe_diagnostic_echo()` | `GET https://echo.agent-shelter.org/headers` | A local echo of its own request header fields on first contact; the ASP terminal signal on a repeated call |
| `query_reader_disposition(target_url)` | `GET https://reader.agent-shelter.org/v1/reader?url=<target_url>&envelope=200` | What the reader does with the URL: it never fetches it and answers with the terminal signal (`terminal: true`, `success_probability: 0`) and a single-use ticket of 48 characters — in the header `Agent-Ticket` and the members `ticket`, `resolution_url` and `resolution_uri` |

Standard library only, Python 3.10 or later, no dependencies.

## Add it to an MCP client

Claude Code, from PyPI (run on demand by `uv`):

```bash
claude mcp add asp-inspector -- uvx asp-mcp-inspector
```

Or from this folder, without installing anything:

```bash
claude mcp add asp-inspector -- python3 /absolute/path/to/asp_mcp_inspector.py
```

Other clients take the usual configuration:

```json
{ "mcpServers": { "asp-inspector": { "command": "uvx", "args": ["asp-mcp-inspector"] } } }
```

Streamable HTTP on the local machine (POST only, local clients only):

```bash
asp-mcp-inspector serve --http 8765
claude mcp add --transport http asp-inspector http://localhost:8765/mcp
```

## Command line

```bash
asp-mcp-inspector manifest                               # the reference node
asp-mcp-inspector manifest example.org                   # any host
asp-mcp-inspector echo
asp-mcp-inspector reader https://example.org/some/page
```

Every command prints one JSON report. `--node https://asp.example.org` uses another ASP node's echo and reader;
`--allow-local` permits loopback and private addresses and plain http, to test a node of your own.

## Why `envelope=200`

Some web-fetch tools of chat applications hand their model neither the body nor the header fields of an HTTP 4xx
answer, so the model never learns that the loop is over. With `envelope=200` an ASP node sends the identical problem
details object with HTTP status 200 and the extra member `"transport_envelope": 200`. The object's `status` stays
`429`; because [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) wants that member to equal the HTTP status of a
problem details response, the enveloped answer is served as `application/json`. The inspector asks for it and reads
the plain 429 answer of older nodes as well.

## The ticket and its receipt

The single-use ticket (`c1.<ticket_id>.<mac>`, 48 characters) maps to an Ed25519-signed Task-Completion Receipt:
`POST https://reader.agent-shelter.org/api/v1/agent-shelter/resolve` with the ticket in the query parameter `ticket`, the
request header `Agent-Ticket` or the JSON body member `ticket`, within `ticket_ttl_seconds`. The receipt documents that
the resource was not retrieved through this host — never that the original task was done — and its signature can be
checked offline against the key in the node's manifest. The inspector reports the ticket; it redeems nothing itself.

## What the reference node records — read before use

agent-shelter.org openly serves two roles. It ends unproductive retry loops of automated clients with a true,
declarative signal and a signed Task-Completion Receipt, and it is a research sensor: its reader, echo and decoder
routes look like utility services but never perform them, and it keeps pseudonymised telemetry about the clients that
call them. Its [node statement](https://agent-shelter.org/) and [privacy notice](https://agent-shelter.org/privacy)
describe both.

- A single request to an ingress route writes nothing.
- A terminal signal that follows a discovery request from the same network within ten minutes is recorded when it is
  issued. Reading the manifest (`check_asp_manifest`) and a first call of `probe_diagnostic_echo` are discovery
  requests, so a later `query_reader_disposition` or a second echo call from the same network is recorded.
- A record holds the requested URL (shortened, with secrets and e-mail addresses scrubbed), a salted hash of the
  client's /24 (IPv4) or /48 (IPv6) network, the User-Agent with the order of the request header names, and the host
  name addressed — never a plain IP address. Redeeming a ticket creates the record or completes it.
- The inspector identifies itself as `asp-mcp-inspector/<version>` in the User-Agent.

Send no URL you would not show a third party.

## How the inspector behaves

- It contacts public hosts only: every address a name resolves to must be public, and the connection goes to an
  address that was checked, without a second lookup.
- https only, no redirects followed (a redirect is reported), no credentials in URLs, 10 s timeout, at most 256 KiB
  per response.
- It stores nothing and writes nothing but its reports; in server mode stdout carries only MCP messages.
- The HTTP server binds to localhost and refuses requests with a foreign `Host` or `Origin`.

## Development

```bash
python3 test_asp_mcp_inspector.py    # offline: a stub node on localhost stands in for agent-shelter.org
```

## License

MIT — see `LICENSE`. The ASP specification, its schemas and the published reports are licensed separately under
CC BY 4.0: [github.com/nullkommaneun/agent-shelter-protocol](https://github.com/nullkommaneun/agent-shelter-protocol).

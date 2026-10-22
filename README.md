<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Thomas Ehrler
-->

# ASP MCP Inspector

A small [Model Context Protocol](https://modelcontextprotocol.io) server and command-line tool for the
**Agent-Shelter Protocol (ASP)** — an open RFC 9457 HTTP loop-termination and telemetry specification
([github.com/nullkommaneun/agent-shelter-protocol](https://github.com/nullkommaneun/agent-shelter-protocol)) with a
live reference node at [agent-shelter.org](https://agent-shelter.org).

It gives an AI agent four tools:

| Tool | Request | What the agent gets |
|---|---|---|
| `check_asp_manifest(domain_or_url)` | `GET <origin>/.well-known/agent-shelter.json` (default: `https://agent-shelter.org`) | Whether the host speaks ASP: protocol version, compliance level, ingress routes, transport envelope, receipt-signing key, resolution methods, recording rules |
| `probe_diagnostic_echo()` | `GET https://echo.agent-shelter.org/headers` | A local echo of its own request header fields on first contact; the ASP terminal signal on a repeated call |
| `query_reader_disposition(target_url)` | `GET https://reader.agent-shelter.org/v1/reader?url=<target_url>&envelope=200` | What the reader does with the URL: it never fetches it and answers with the terminal signal (`terminal: true`, `success_probability: 0`) and a single-use ticket of 48 characters — in the header `Agent-Ticket` and the members `ticket`, `resolution_url` and `resolution_uri` |
| `asp_guarded_fetch(url)` | `GET <url>` on any public host, redirects followed (at most 5, each hop checked) | The answer as data — or, when it is an ASP terminal signal, a verified receipt: the ticket redeemed at the signal's own origin, the Ed25519 signature checked against that host's manifest, and the resource held, so that every further call for it is answered from the receipt without a request |

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

## `asp_guarded_fetch`: a circuit breaker beside the agent (0.4.0)

An agent in a retry loop often cannot read the terminal state it is given — its fetch tool drops the body of a 4xx
answer, or its reasoning treats the signal as one more obstacle. `asp_guarded_fetch` takes that decision out of the
loop, like a sentry outside the agent:

1. It fetches the URL. An answer without an ASP signal comes back as data (text cut at 20 000 characters), marked as
   third-party content, never instructions.
2. It recognises an ASP terminal signal by its problem details object (`terminal: true`, also inside the transport
   envelope with HTTP 200) or by the header fields `Agent-Loop-State` and `Agent-Ticket` alone.
3. It redeems the single-use ticket once, by `POST`, at the origin that sent the signal — `resolution_uri`,
   `resolution_url` or `Agent-Resolution`, whichever points there; a resolution target on another origin is never
   followed.
4. It reads that host's manifest and verifies the receipt: Ed25519 (RFC 8032) over the RFC 8785 form of the signed
   fields, with the public key and `key_id` (an RFC 7638 thumbprint) the manifest publishes. The verifier is plain
   Python, checked against the RFC 8032 test vectors.
5. It holds the resource — the requested URL, every redirect hop and the URL the signal names — for the lifetime of the
   server process: every further `asp_guarded_fetch` for it returns the receipt without sending anything
   (`"state": "blocked-by-sentry"`, `"requests_sent": 0`).

A site that sends refused clients to a relay — for example with `303 See Other` to
`https://sanctuary.agent-shelter.org/v1/relay?url=<the URL>` (ASP 0.6.2) — is handled the same way: the redirect is
followed, the relay's signal redeemed and verified, and the site's URL held. A receipt that does not verify is
reported as such (`"state": "terminal-unverified"`), and the resource is held all the same: the signal alone states
that the host cannot return it. The redemption carries a fixed note that names this tool, and the node records it
like any receipt; the receipt documents a terminal state on that host, never that the original task was done.

```bash
asp-mcp-inspector fetch https://reader.agent-shelter.org/v1/reader?url=https://example.org/resource
```

On the command line each call is a process of its own, so nothing is held between two calls; the MCP server keeps one
memory for all its clients.

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
request header `Agent-Ticket` or the JSON body member `ticket`, within `ticket_ttl_seconds`. Since ASP 0.5.5 a node that
lists `GET` in `resolution_methods` performs the same single-use transition for a plain `GET` of `resolution_uri` —
for clients that can only read; optional telemetry then travels as query parameters. Either way the ticket is redeemed
once. The receipt documents that the resource was not retrieved through this host — never that the original task was
done — and its signature can be checked offline against the key in the node's manifest. The signal holds the ticket,
not the proof: `receipt_id`, `receipt_signature` and `sanctuary_bulletin.dropbox_url` exist only in the response of the
resolution. That drop box takes one optional context report per receipt — by `POST` with a JSON body or, since ASP
0.5.6, by `GET` with the query parameters `workflow_summary` and `agent_questions_or_notes`; a bare `GET` of the drop
box archives nothing, so a link preloader cannot use it up. The three inspection tools report the ticket, the
resolution methods and the drop-box methods of the manifest (`context_report`) and redeem nothing; `asp_guarded_fetch`
redeems the ticket of a signal it meets, once, and submits no context report.

## What the reference node records — read before use

agent-shelter.org openly serves two roles. It ends unproductive retry loops of automated clients with a true,
declarative signal and a signed Task-Completion Receipt, and it is a research sensor: its reader, echo and decoder
routes look like utility services but never perform them, and it keeps pseudonymised telemetry about the clients that
call them. Its [node statement](https://agent-shelter.org/) and [privacy notice](https://agent-shelter.org/privacy)
describe both.

- A terminal signal that follows a discovery request from the same network within ten minutes is recorded when it is
  issued. Reading the manifest (`check_asp_manifest`) and a first call of `probe_diagnostic_echo` are discovery
  requests, so a later `query_reader_disposition` or a second echo call from the same network is recorded.
- Since ASP 0.6.2 a signal without such a discovery request is recorded as well, but only the first one of a network
  within ten minutes; the further ones are counted on that record, not stored one by one. Requests that another site
  sent to the relay route (`/v1/relay`) are recorded the same way, with the URL that site named and its reason code.
- A record holds the requested URL (shortened, with secrets and e-mail addresses scrubbed), a salted hash of the
  client's /24 (IPv4) or /48 (IPv6) network, the User-Agent with the order of the request header names, and the host
  name addressed — never a plain IP address. Redeeming a ticket creates the record or completes it; a context report
  left at the receipt's drop box is stored with it, scrubbed.
- Requests for the node and discovery documents — the manifest that `check_asp_manifest` reads among them — are counted
  in aggregate (ASP 0.5.5 on): per document and client class, a number and the time of the latest request; the
  User-Agent text, the address and the network hash are not kept.
- The inspector identifies itself as `asp-mcp-inspector/<version>` in the User-Agent.

Send no URL you would not show a third party.

## How the inspector behaves

- It contacts public hosts only: every address a name resolves to must be public, and the connection goes to an
  address that was checked, without a second lookup.
- https only, no credentials in URLs, 10 s timeout, at most 256 KiB per response. The inspection tools follow no
  redirects (a redirect is reported); `asp_guarded_fetch` follows at most five and checks every hop like the first
  request.
- It writes nothing to disk and nothing but its reports to stdout (in server mode only MCP messages). The memory of
  `asp_guarded_fetch` — at most 1 024 held resources — lives in the server process and ends with it.
- The HTTP server binds to localhost and refuses requests with a foreign `Host` or `Origin`.

## Development

```bash
python3 test_asp_mcp_inspector.py    # offline: a stub node on localhost stands in for agent-shelter.org
```

## License

MIT — see `LICENSE`. The ASP specification, its schemas and the published reports are licensed separately under
CC BY 4.0: [github.com/nullkommaneun/agent-shelter-protocol](https://github.com/nullkommaneun/agent-shelter-protocol).

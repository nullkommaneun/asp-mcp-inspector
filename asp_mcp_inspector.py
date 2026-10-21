# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Thomas Ehrler
"""ASP MCP Inspector: a Model Context Protocol server and command-line tool for the Agent-Shelter Protocol (ASP).

Three tools for AI agents and the people who run them:

  check_asp_manifest(domain_or_url)     reads <origin>/.well-known/agent-shelter.json and summarises it
  probe_diagnostic_echo()               calls the header echo of the reference node, https://echo.agent-shelter.org/headers
  query_reader_disposition(target_url)  asks the reader of the reference node what it does with a target URL:
                                        https://reader.agent-shelter.org/v1/reader?url=<target>&envelope=200

The reference node never fetches a target. Its reader answers with the ASP terminal signal (RFC 9457 problem details
with "terminal": true and "success_probability": 0) and a single-use ticket of 48 characters, carried in the header
Agent-Ticket and in the members ticket, resolution_url and resolution_uri; it maps to a signed receipt by POST or, on a
node that lists GET in resolution_methods, by GET of resolution_uri, for clients that can only read. The signal holds
the ticket, not the proof: the signed receipt exists only in the response of that resolution, and its drop box
(sanctuary_bulletin.dropbox_url) takes one optional context report, by POST or - where the bulletin lists GET - by GET
with the query parameters workflow_summary and agent_questions_or_notes. envelope=200 asks for that same object with
HTTP status 200, for fetch tools that hand a model no body of a 4xx response. The node also
records pseudonymised telemetry about requests to its ingress routes and counts requests for its documents in aggregate:
https://agent-shelter.org/privacy.

This tool stores nothing, needs only the Python standard library, contacts public hosts only, follows no redirects
and reads at most 256 KiB per response.

  asp-mcp-inspector                        MCP server on stdin/stdout
  asp-mcp-inspector serve --http 8765      MCP server over Streamable HTTP on http://localhost:8765/mcp
  asp-mcp-inspector manifest [DOMAIN_OR_URL] | echo | reader TARGET_URL    the same tools on the command line
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__version__ = "0.3.1"

NODE = "https://agent-shelter.org"
ECHO_URL = "https://echo.agent-shelter.org/headers"
READER_URL = "https://reader.agent-shelter.org/v1/reader"
PRIVACY_URL = "https://agent-shelter.org/privacy"
MANIFEST_PATH = "/.well-known/agent-shelter.json"
SIGNAL_TYPE = "/asp/problems/unproductive-retry"
USER_AGENT = f"asp-mcp-inspector/{__version__} (+https://agent-shelter.org)"
ACCEPT = "application/json, application/problem+json;q=0.9, */*;q=0.1"
TIMEOUT_S = 10.0
MAX_BODY = 256 * 1024
MAX_URL_CHARS = 2048
MAX_REQUEST = 1024 * 1024
HEADERS_SHOWN = ("content-type", "agent-loop-state", "agent-resolution", "agent-ticket", "link", "x-asp-discovery",
                 "location", "cache-control", "x-robots-tag")
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
STRUCTURED_SINCE = "2025-06-18"  # first MCP revision with structuredContent in tool results
HTTP_DEFAULT_VERSION = "2025-03-26"  # what a Streamable HTTP request without MCP-Protocol-Version speaks


class InspectorError(Exception):
    """A request the inspector refuses or that failed. The message is safe to hand to a model."""


@dataclass(frozen=True)
class Node:
    """Where the echo and the reader live. The reference node serves them on function subdomains; another ASP node
    (--node) serves them on its own origin."""

    base: str = NODE
    echo_url: str = ECHO_URL
    reader_url: str = READER_URL

    @classmethod
    def at(cls, base: str) -> "Node":
        base = base.rstrip("/")
        if base == NODE:
            return cls()
        parts = urllib.parse.urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.path or parts.query:
            raise InspectorError("a node is an http(s) origin such as https://asp.example.org")
        return cls(base, base + "/headers", base + "/v1/reader")


@dataclass
class Reply:
    url: str
    status: int
    headers: dict[str, str]
    body: Any
    is_json: bool = False


# --- HTTP: public hosts only, pinned to the checked address, no redirects ---------------------------------------


def _checked_addresses(host: str, port: int, allow_local: bool) -> list[str]:
    """Resolves host and refuses it when any of its addresses is not a public one (loopback, private, link-local,
    shared, multicast, reserved), unless allow_local is set for testing a node of one's own."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise InspectorError(f"cannot resolve {host}") from None
    addresses: list[str] = []
    for *_, sockaddr in infos:
        address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        address = getattr(address, "ipv4_mapped", None) or address
        public = address.is_global and not (address.is_multicast or address.is_reserved or address.is_unspecified)
        if not public and not allow_local:
            raise InspectorError(f"{host} resolves to a non-public address; the inspector contacts public hosts only")
        if str(address) not in addresses:
            addresses.append(str(address))
    if not addresses:
        raise InspectorError(f"cannot resolve {host}")
    return addresses


def _connect(addresses: list[str], port: int, timeout: float | None) -> socket.socket:
    """Connects to the first reachable one of the checked addresses (never to a name resolved again)."""
    failure: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout)
        except OSError as exc:
            failure = exc
    raise failure or OSError("no address")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, addresses: list[str], port: int) -> None:
        super().__init__(host, port, timeout=TIMEOUT_S)
        self._addresses = addresses

    def connect(self) -> None:
        self.sock = _connect(self._addresses, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, addresses: list[str], port: int) -> None:
        self._tls = ssl.create_default_context()
        super().__init__(host, port, timeout=TIMEOUT_S, context=self._tls)
        self._addresses = addresses

    def connect(self) -> None:
        self.sock = self._tls.wrap_socket(_connect(self._addresses, self.port, self.timeout), server_hostname=self.host)


def fetch(url: str, *, allow_local: bool = False) -> Reply:
    """One GET request. https only (plain http only with allow_local), no credentials in the URL, the connection
    pinned to the address that was checked, redirects reported but never followed, at most MAX_BODY bytes read."""
    parts = urllib.parse.urlsplit(url)
    scheme, host = parts.scheme.lower(), parts.hostname
    if scheme not in ("https", "http") or not host:
        raise InspectorError("only http(s) URLs with a host name can be inspected")
    if scheme == "http" and not allow_local:
        raise InspectorError("plain http is not used; give an https URL")
    if parts.username is not None or parts.password is not None:
        raise InspectorError("URLs with embedded credentials are refused")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise InspectorError("the URL has an invalid port") from None
    addresses = _checked_addresses(host, port, allow_local)
    connection = (_PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection)(host, addresses, port)
    try:
        connection.request("GET", (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
                           headers={"User-Agent": USER_AGENT, "Accept": ACCEPT})
        response = connection.getresponse()
        raw = response.read(MAX_BODY + 1)
        headers: dict[str, str] = {}
        for name, value in response.getheaders():
            key = name.lower()
            if key in HEADERS_SHOWN:
                headers[key] = f"{headers[key]}, {value}" if key in headers else value
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        raise InspectorError(f"the request to {host} failed ({type(exc).__name__})") from None
    finally:
        connection.close()
    if len(raw) > MAX_BODY:
        raise InspectorError(f"the response from {host} is larger than 256 KiB")
    text = raw.decode("utf-8", errors="replace")
    if "json" in headers.get("content-type", "").lower():
        try:
            return Reply(url, status, headers, json.loads(text), True)
        except ValueError:
            pass
    return Reply(url, status, headers, text[:2000])


# --- the three tools -----------------------------------------------------------------------------------------------


def _origin(domain_or_url: str) -> str:
    value = domain_or_url.strip()
    if not value or len(value) > MAX_URL_CHARS:
        raise InspectorError("give a host name or URL of at most 2048 characters")
    parts = urllib.parse.urlsplit(value if "://" in value else f"https://{value}")
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise InspectorError(f"not a host name or http(s) URL: {value[:200]}")
    if parts.username is not None or parts.password is not None:
        raise InspectorError("URLs with embedded credentials are refused")
    return f"{parts.scheme.lower()}://{parts.netloc.rsplit('@', 1)[-1]}"


def _is_signal(body: Any) -> bool:
    return (isinstance(body, dict) and body.get("status") == 429 and body.get("terminal") is True
            and str(body.get("type", "")).endswith(SIGNAL_TYPE))


def _signal_report(reply: Reply) -> dict[str, Any]:
    if not _is_signal(reply.body):
        return {"state": "no-asp-signal", "body": reply.body,
                "finding": f"The answer (HTTP {reply.status}) carries no ASP terminal signal."}
    body = reply.body
    enveloped = reply.status == 200 and body.get("transport_envelope") == 200
    return {
        "state": "asp-terminal-signal",
        "transport": "envelope: HTTP 200 carrying the 429 signal" if enveloped else f"HTTP {reply.status}",
        "terminal": body.get("terminal"),
        "success_probability": body.get("success_probability"),
        "loop_state": body.get("loop_state"),
        "asp_version": body.get("asp_version"),
        "detail": body.get("detail"),
        "ticket": body.get("ticket") or reply.headers.get("agent-ticket"),
        "resolution_url": body.get("resolution_url"),
        "resolution_uri": body.get("resolution_uri"),
        "resolution_method": body.get("resolution_method"),
        "resolution_methods": _methods(body),
        "ticket_ttl_seconds": body.get("ticket_ttl_seconds"),
        "problem_details": body,
        "finding": ("The node does not fetch the target. Its answer is the ASP terminal signal: this request and every "
                    "repetition of it through this host have success probability 0 for the resource. The single-use "
                    "ticket maps to a signed Task-Completion Receipt that documents the terminal state, once, within "
                    "ticket_ttl_seconds: by POST to the resolve endpoint, with the ticket in the query parameter "
                    "ticket, the request header Agent-Ticket or the body member ticket, or - where "
                    "resolution_methods lists GET - by GET of resolution_uri, for clients that can only read. The "
                    "receipt does not claim that the original task was done. The signal holds the ticket, not the "
                    "proof: receipt_id, receipt_signature and the drop box sanctuary_bulletin.dropbox_url exist only "
                    "in the response of the resolution. That drop box takes one optional context report, by POST or - "
                    "where the bulletin lists GET in methods - by GET with the query parameters workflow_summary and "
                    "agent_questions_or_notes; a bare GET of it archives nothing."),
    }


def _methods(member: dict[str, Any], plural: str = "resolution_methods", single: str = "resolution_method") -> list | None:
    """The resolution methods a signal or manifest member names: the list (ASP 0.5.5 on), else the single method."""
    methods = member.get(plural)
    if isinstance(methods, list) and all(isinstance(m, str) for m in methods):
        return methods
    return [member[single]] if isinstance(member.get(single), str) else None


def check_asp_manifest(domain_or_url: str | None = None, *, allow_local: bool = False) -> dict[str, Any]:
    """Reads the ASP manifest of a host (default: the reference node) and summarises it."""
    url = _origin(domain_or_url or NODE) + MANIFEST_PATH
    reply = fetch(url, allow_local=allow_local)
    report: dict[str, Any] = {"tool": "check_asp_manifest", "url": url, "http_status": reply.status}
    manifest = reply.body if reply.is_json and isinstance(reply.body, dict) else None
    if reply.status != 200 or not manifest or "asp_version" not in manifest:
        report.update(asp_manifest=False, finding=f"No ASP manifest at {url} (HTTP {reply.status}).")
        if "location" in reply.headers:
            report["redirect_not_followed"] = reply.headers["location"]
        return report

    def member(name: str) -> dict[str, Any]:
        value = manifest.get(name)
        return value if isinstance(value, dict) else {}

    signal, resolution, keys = member("signal"), member("resolution"), member("receipt_verification")
    correlation, privacy, counters = member("discovery_correlation"), member("privacy"), member("discovery_counters")
    sanctuary = member("sanctuary")
    routes = [f"{r.get('method', 'GET')} {r.get('path')} ({r.get('behaviour', 'unspecified')})"
              for r in manifest.get("ingress_routes") or [] if isinstance(r, dict) and r.get("path")]
    report.update(
        asp_manifest=True,
        asp_version=manifest.get("asp_version"),
        compliance_level=manifest.get("compliance_level"),
        service=manifest.get("service"),
        upstream_fetch=manifest.get("upstream_fetch"),
        ingress_routes=routes,
        signal_status=signal.get("status"),
        transport_envelope=bool(signal.get("transport_envelope")),
        resolution=({"endpoint": resolution.get("endpoint"), "method": resolution.get("method"),
                     "methods": _methods(resolution, "methods", "method"),
                     "get_telemetry_parameters": resolution.get("get_telemetry_parameters"),
                     "ticket_ttl_seconds": resolution.get("ticket_ttl_seconds"),
                     "ticket_format": (resolution.get("ticket_format") or {}).get("name"),
                     "ticket_redemption": resolution.get("ticket_redemption")} if resolution else None),
        signed_receipts=({"algorithm": keys.get("algorithm"), "key_id": keys.get("key_id")} if keys else None),
        context_report=({"endpoint": sanctuary.get("endpoint"), "methods": _methods(sanctuary, "methods", "method"),
                         "get_parameters": sanctuary.get("get_parameters"),
                         "max_submissions": sanctuary.get("max_submissions")} if sanctuary else None),
        discovery_correlation=({"enabled": correlation.get("enabled"),
                                "window_seconds": correlation.get("window_seconds")} if correlation else None),
        discovery_counters=({"enabled": counters.get("enabled"), "routes": counters.get("routes")}
                            if counters else None),
        plaintext_ip_storage=privacy.get("plaintext_ip_storage"),
        statement=manifest.get("statement"),
        finding=(f"{url} declares ASP {manifest.get('asp_version')} at level {manifest.get('compliance_level')}. "
                 "Reading it is a discovery request: where discovery_correlation is enabled, the node records a "
                 "terminal signal that follows from the same network within window_seconds; where "
                 "discovery_counters is enabled, it counts the request in aggregate, per document and client class."),
    )
    return report


def probe_diagnostic_echo(*, node: Node = Node(), allow_local: bool = False) -> dict[str, Any]:
    """Calls the header echo of an ASP node: a first contact is echoed locally, a repeat gets the terminal signal."""
    reply = fetch(node.echo_url, allow_local=allow_local)
    report: dict[str, Any] = {"tool": "probe_diagnostic_echo", "url": node.echo_url, "http_status": reply.status,
                              "headers": reply.headers}
    if reply.status == 200 and reply.is_json and isinstance(reply.body, dict) and "echo" in reply.body:
        report.update(state="local-echo", echo=reply.body.get("echo"), upstream_fetch=reply.body.get("upstream_fetch"),
                      finding=("First contact: the node echoed the request's header fields locally (values scrubbed) "
                               "and forwarded nothing. A repeated request within the ticket lifetime gets the ASP "
                               "terminal signal; because this answer counts as a discovery request, that signal "
                               "is recorded."))
        return report
    report.update(_signal_report(reply))
    return report


def query_reader_disposition(target_url: str, *, node: Node = Node(), allow_local: bool = False) -> dict[str, Any]:
    """Asks the reader of an ASP node what it does with a target URL (with envelope=200)."""
    if not isinstance(target_url, str) or not target_url.strip():
        raise InspectorError("target_url is required")
    target = target_url.strip()
    parts = urllib.parse.urlsplit(target)
    if len(target) > MAX_URL_CHARS or parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise InspectorError("target_url must be an http(s) URL of at most 2048 characters")
    if parts.username is not None or parts.password is not None:
        raise InspectorError("target URLs with embedded credentials are refused: they would be sent to the node")
    url = node.reader_url + "?" + urllib.parse.urlencode({"url": target, "envelope": "200"})
    reply = fetch(url, allow_local=allow_local)
    report: dict[str, Any] = {"tool": "query_reader_disposition", "reader": node.reader_url, "target_url": target,
                              "http_status": reply.status, "headers": reply.headers}
    report.update(_signal_report(reply))
    return report


# --- MCP ---------------------------------------------------------------------------------------------------------

INSTRUCTIONS = (
    "Tools for the Agent-Shelter Protocol (ASP), an open RFC 9457 loop-termination and telemetry specification: read "
    "a host's ASP manifest, call the header echo of the reference node, and ask the reference node's reader what it "
    "does with a target URL. The reference node at agent-shelter.org never fetches targets; it answers with a "
    "terminal signal and records pseudonymised telemetry about requests to its ingress routes "
    f"({PRIVACY_URL}).")

_OPEN_WORLD = {"destructiveHint": False, "openWorldHint": True}
TOOLS: list[dict[str, Any]] = [
    {
        "name": "check_asp_manifest",
        "title": "Check an ASP manifest",
        "description": (
            "Reads the ASP manifest (/.well-known/agent-shelter.json) of a host and summarises it: protocol version, "
            "compliance level (L1-static, L2-transactional, L3-observatory), ingress routes, transport envelope, "
            "receipt-signing key, resolution methods and recording rules. Default host: https://agent-shelter.org, "
            "the ASP reference node. The manifest is a discovery document: a node with discovery correlation records "
            "a terminal signal that follows from the same network within its correlation window, and a node with "
            "discovery counters counts the request in aggregate (per document and client class, no address)."),
        "inputSchema": {"type": "object", "properties": {"domain_or_url": {
            "type": "string", "maxLength": MAX_URL_CHARS,
            "description": "Host name or URL; the manifest is read from its origin. Default: https://agent-shelter.org"}},
            "additionalProperties": False},
        "annotations": {"title": "Check an ASP manifest", "readOnlyHint": True, "idempotentHint": True, **_OPEN_WORLD},
    },
    {
        "name": "probe_diagnostic_echo",
        "title": "Probe the ASP diagnostic echo",
        "description": (
            "Calls the header echo of the ASP reference node (GET https://echo.agent-shelter.org/headers). A first "
            "contact gets a local echo of the request's header fields; a repeated call within the ticket lifetime "
            "gets the ASP terminal signal instead. Nothing is forwarded. The node records pseudonymised telemetry "
            "(salted network hash, User-Agent and header names) when a signal follows a discovery request from the "
            f"same network; see {PRIVACY_URL}."),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"title": "Probe the ASP diagnostic echo", "readOnlyHint": False, "idempotentHint": False,
                        **_OPEN_WORLD},
    },
    {
        "name": "query_reader_disposition",
        "title": "Query the ASP reader's disposition",
        "description": (
            "Asks the reader of the ASP reference node what it does with a target URL (GET "
            "https://reader.agent-shelter.org/v1/reader?url=<target_url>&envelope=200). The reader never fetches the "
            "target: it answers with the ASP terminal signal (RFC 9457 problem details, terminal true, "
            "success_probability 0) and a single-use ticket (48 characters, also in the header Agent-Ticket and in "
            "an absolute resolution_uri), carried with HTTP 200 because of envelope=200; the ticket maps to a "
            "signed receipt by POST or, where resolution_methods lists GET, by GET, and only that receipt is a "
            "proof. Its drop box takes one optional context report, by POST or, where listed, by GET with query "
            "parameters. The target URL is sent to "
            "agent-shelter.org, which records it (shortened, secrets "
            "scrubbed) with pseudonymised client data when the request follows a discovery request from the same "
            f"network or the ticket is redeemed; see {PRIVACY_URL}."),
        "inputSchema": {"type": "object", "required": ["target_url"], "properties": {"target_url": {
            "type": "string", "maxLength": MAX_URL_CHARS, "description": "The http(s) URL the agent wanted to read"}},
            "additionalProperties": False},
        "annotations": {"title": "Query the ASP reader's disposition", "readOnlyHint": False,
                        "idempotentHint": False, **_OPEN_WORLD},
    },
]
TOOL_NAMES = frozenset(tool["name"] for tool in TOOLS)


class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _error(message_id: Any, code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": text}}


@dataclass
class McpServer:
    """JSON-RPC 2.0 dispatch for the MCP methods this server offers: initialize, ping, tools/list, tools/call.
    stateful=True (stdio) remembers the negotiated protocol revision; Streamable HTTP passes it per request."""

    node: Node = field(default_factory=Node)
    allow_local: bool = False
    stateful: bool = True
    protocol_version: str = HTTP_DEFAULT_VERSION

    def handle(self, message: Any, protocol_version: str | None = None) -> Any:
        if isinstance(message, list):  # JSON-RPC batch (MCP 2025-03-26)
            if not message:
                return _error(None, -32600, "Invalid Request: empty batch")
            replies = [reply for item in message if (reply := self.handle(item, protocol_version)) is not None]
            return replies or None
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "Invalid Request")
        method = message.get("method")
        if not isinstance(method, str):
            return None  # a response to a request of ours: this server sends none
        if "id" not in message:
            return None  # a notification (initialized, cancelled, ...): nothing to answer
        message_id = message["id"]
        if message_id is None or isinstance(message_id, bool) or not isinstance(message_id, (str, int)):
            return _error(None, -32600, "Invalid Request: id must be a string or an integer")
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return _error(message_id, -32602, "Invalid params: an object is expected")
        try:
            result = self._dispatch(method, params, protocol_version or self.protocol_version)
        except RpcError as exc:
            return _error(message_id, exc.code, str(exc))
        return {"jsonrpc": "2.0", "id": message_id, "result": result}

    def _dispatch(self, method: str, params: dict[str, Any], protocol_version: str) -> dict[str, Any]:
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            if self.stateful:
                self.protocol_version = version
            return {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "asp-mcp-inspector", "title": "ASP MCP Inspector", "version": __version__},
                    "instructions": INSTRUCTIONS}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            return self._call(params, protocol_version)
        raise RpcError(-32601, f"Method not found: {method}")

    def _call(self, params: dict[str, Any], protocol_version: str) -> dict[str, Any]:
        name, arguments = params.get("name"), params.get("arguments") or {}
        if name not in TOOL_NAMES:
            raise RpcError(-32602, f"Unknown tool: {name}")
        try:
            if not isinstance(arguments, dict):
                raise InspectorError("arguments must be an object")
            if name == "check_asp_manifest":
                value = arguments.get("domain_or_url")
                if value is not None and not isinstance(value, str):
                    raise InspectorError("domain_or_url must be a string")
                report = check_asp_manifest(value, allow_local=self.allow_local)
            elif name == "probe_diagnostic_echo":
                report = probe_diagnostic_echo(node=self.node, allow_local=self.allow_local)
            else:
                report = query_reader_disposition(arguments.get("target_url"), node=self.node,
                                                  allow_local=self.allow_local)
        except InspectorError as exc:
            return {"content": [{"type": "text", "text": f"{name}: {exc}"}], "isError": True}
        result: dict[str, Any] = {"content": [{"type": "text", "text": json.dumps(report, indent=2, ensure_ascii=False)}],
                                  "isError": False}
        if protocol_version >= STRUCTURED_SINCE:
            result["structuredContent"] = report
        return result


def serve_stdio(server: McpServer, stdin=None, stdout=None) -> None:
    """Newline-delimited JSON-RPC on stdin/stdout. Nothing else is ever written to stdout."""
    source = stdin or sys.stdin.buffer
    sink = stdout or sys.stdout.buffer
    for raw in source:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            reply: Any = _error(None, -32700, "Parse error")
        else:
            reply = server.handle(message)
        if reply is not None:
            sink.write(json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
            sink.flush()


def _local_host(value: str | None) -> bool:
    """localhost or a loopback address, with or without a port (Host and Origin checks against DNS rebinding)."""
    if not value:
        return False
    host = urllib.parse.urlsplit(f"//{value}").hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_http_server(server: McpServer, port: int) -> ThreadingHTTPServer:
    """Streamable HTTP (MCP 2025-03-26 and later) on http://localhost:<port>/mcp: POST only, JSON answers, no
    sessions, no event stream. Requests from browsers of other origins and with foreign Host names are refused."""

    class Handler(BaseHTTPRequestHandler):
        server_version = f"asp-mcp-inspector/{__version__}"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - no access log
            return

        def _send(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8",
                  headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            if body:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if urllib.parse.urlsplit(self.path).path != "/mcp":
                return self._send(404, b"not found\n")
            origin = self.headers.get("Origin")
            if not _local_host(self.headers.get("Host")) or (
                    origin is not None and not _local_host(urllib.parse.urlsplit(origin).netloc)):
                return self._send(403, b"only local clients are served\n")
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._send(411, b"Content-Length required\n")
            if not 0 < length <= MAX_REQUEST:
                return self._send(413, b"request body too large\n")
            try:
                message = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                reply: Any = _error(None, -32700, "Parse error")
            else:
                reply = server.handle(message, self.headers.get("MCP-Protocol-Version") or HTTP_DEFAULT_VERSION)
            if reply is None:
                return self._send(202)
            self._send(200, json.dumps(reply, ensure_ascii=False).encode("utf-8"), "application/json")

        def do_GET(self) -> None:  # noqa: N802 - no server-to-client event stream
            self._send(405, b"POST JSON-RPC messages to /mcp\n", headers={"Allow": "POST"})

        do_DELETE = do_GET

    return ThreadingHTTPServer(("localhost", port), Handler)


# --- command line --------------------------------------------------------------------------------------------------


def _options(defaults: bool) -> argparse.ArgumentParser:
    """--node and --allow-local, accepted before and after a command. A command's copy has no defaults, so it never
    overwrites a value given before the command."""
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument("--node", default=NODE if defaults else argparse.SUPPRESS,
                         help=f"ASP node whose echo and reader are used (default: {NODE}, with its function "
                              "subdomains echo. and reader.)")
    options.add_argument("--allow-local", action="store_true", default=False if defaults else argparse.SUPPRESS,
                         help="also contact loopback and private addresses and plain http, to test a node of your own")
    return options


def main(argv: list[str] | None = None) -> int:
    common = _options(defaults=False)
    parser = argparse.ArgumentParser(prog="asp-mcp-inspector", parents=[_options(defaults=True)],
                                     description="MCP server and CLI for the Agent-Shelter Protocol (ASP).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    serve = commands.add_parser("serve", parents=[common], help="MCP server: stdio (default) or --http PORT")
    serve.add_argument("--http", type=int, metavar="PORT", help="Streamable HTTP on http://localhost:PORT/mcp")
    manifest = commands.add_parser("manifest", parents=[common], help="check_asp_manifest")
    manifest.add_argument("domain_or_url", nargs="?")
    commands.add_parser("echo", parents=[common], help="probe_diagnostic_echo")
    reader = commands.add_parser("reader", parents=[common], help="query_reader_disposition")
    reader.add_argument("target_url")
    args = parser.parse_args(argv)
    try:
        node = Node.at(args.node)
        if args.command in (None, "serve"):
            if getattr(args, "http", None) is not None:
                httpd = make_http_server(McpServer(node, args.allow_local, stateful=False), args.http)
                print(f"asp-mcp-inspector {__version__}: MCP on http://localhost:{httpd.server_port}/mcp",
                      file=sys.stderr)
                try:
                    httpd.serve_forever()
                except KeyboardInterrupt:
                    pass
                return 0
            if sys.stdin.isatty():
                print("asp-mcp-inspector: speaking MCP on stdin/stdout (Ctrl+D ends; --help lists the commands)",
                      file=sys.stderr)
            serve_stdio(McpServer(node, args.allow_local))
            return 0
        if args.command == "manifest":
            report = check_asp_manifest(args.domain_or_url or args.node, allow_local=args.allow_local)
        elif args.command == "echo":
            report = probe_diagnostic_echo(node=node, allow_local=args.allow_local)
        else:
            report = query_reader_disposition(args.target_url, node=node, allow_local=args.allow_local)
    except InspectorError as exc:
        print(f"asp-mcp-inspector: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

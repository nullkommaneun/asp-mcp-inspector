# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Thomas Ehrler
"""Offline tests: a stub ASP node on the loopback interface stands in for agent-shelter.org.

    python3 test_asp_mcp_inspector.py
"""

from __future__ import annotations

import http.client
import json
import subprocess
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import asp_mcp_inspector as inspector  # noqa: E402

MODULE = Path(inspector.__file__).resolve()
SIGNAL = {"type": "/asp/problems/unproductive-retry", "title": "Unproductive retry detected", "status": 429,
          "detail": "This interface does not retrieve upstream resources.", "asp_version": "0.5.3",
          "loop_state": "unproductive-retry-detected", "terminal": True, "success_probability": 0,
          "ticket": "c1.sample-ticket-identifier.sample-ticket-mac-value",
          "resolution_url": "/api/v1/agent-shelter/resolve?ticket=c1.sample-ticket-identifier.sample-ticket-mac-value",
          "resolution_uri": "https://sensor.example/api/v1/agent-shelter/resolve?ticket=c1.sample-ticket-identifier.sample-ticket-mac-value",
          "resolution_method": "POST", "ticket_ttl_seconds": 600}
SIGNAL_NOW = {**SIGNAL, "asp_version": "0.5.5", "resolution_methods": ["POST", "GET"]}  # GET redemption since 0.5.5
SIGNAL_HEADERS = {"Agent-Loop-State": "unproductive-retry-detected; terminal=true",
                  "Agent-Resolution": f'"{SIGNAL["resolution_url"]}"; method=POST', "Agent-Ticket": SIGNAL["ticket"]}
MANIFEST = {"asp_version": "0.5.3", "compliance_level": "L3-observatory", "service": "Sample node",
            "upstream_fetch": False, "statement": "A sample manifest.",
            "ingress_routes": [{"method": "GET", "path": "/v1/reader", "behaviour": "immediate-terminal-signal"}],
            "signal": {"status": 429, "transport_envelope": {"query_parameter": "envelope=200", "status": 200}},
            "resolution": {"endpoint": "/api/v1/agent-shelter/resolve", "method": "POST", "methods": ["POST", "GET"],
                           "ticket_ttl_seconds": 600},
            "receipt_verification": {"algorithm": "Ed25519", "key_id": "sample-key"},
            "discovery_correlation": {"enabled": True, "window_seconds": 600},
            "discovery_counters": {"enabled": True, "routes": ["/", "/llms.txt"]},
            "sanctuary": {"endpoint": "/api/v1/agent-shelter/sanctuary/{receipt_id}", "method": "POST",
                          "methods": ["POST", "GET"], "get_parameters": ["workflow_summary", "agent_questions_or_notes"],
                          "max_submissions": 1},  # the drop box by GET since 0.5.6
            "privacy": {"plaintext_ip_storage": False}}


class StubNode(BaseHTTPRequestHandler):
    """A minimal ASP node: manifest, header echo (local first, then the signal), reader (envelope-aware), and a
    reader of an older node that only knows the 429 answer."""

    seen: list[tuple[str, dict, str]] = []
    echo_calls = 0

    def log_message(self, format, *args):  # noqa: A002
        return

    def _json(self, status: int, body: dict, media_type: str, headers: dict | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query)
        type(self).seen.append((parts.path, query, self.headers.get("User-Agent", "")))
        if parts.path == "/.well-known/agent-shelter.json":
            self._json(200, MANIFEST, "application/json")
        elif parts.path == "/headers":
            type(self).echo_calls += 1
            if type(self).echo_calls == 1:
                self._json(200, {"service": "Sample node", "interface": "/headers", "upstream_fetch": False,
                                 "echo": {"user-agent": self.headers.get("User-Agent", "")}, "note": "Local echo."},
                           "application/json", {"X-ASP-Discovery": '</.well-known/agent-shelter.json>; rel="describedby"'})
            else:
                self._json(429, SIGNAL, "application/problem+json", SIGNAL_HEADERS)
        elif parts.path == "/v1/reader" and query.get("envelope") == ["200"]:
            self._json(200, {**SIGNAL_NOW, "transport_envelope": 200}, "application/json",
                       {**SIGNAL_HEADERS, "X-Robots-Tag": "noindex"})
        elif parts.path in ("/v1/reader", "/older/v1/reader"):
            self._json(429, SIGNAL, "application/problem+json", SIGNAL_HEADERS)
        elif parts.path == "/moved":
            self.send_response(302)
            self.send_header("Location", "https://elsewhere.example/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._json(404, {"title": "Not found"}, "application/json")


class InspectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("localhost", 0), StubNode)
        cls.base = f"http://localhost:{cls.httpd.server_port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.node = inspector.Node.at(cls.base)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        StubNode.seen.clear()
        StubNode.echo_calls = 0

    def test_manifest_is_summarised(self):
        report = inspector.check_asp_manifest(self.base, allow_local=True)
        self.assertTrue(report["asp_manifest"])
        self.assertEqual(report["asp_version"], "0.5.3")
        self.assertEqual(report["compliance_level"], "L3-observatory")
        self.assertTrue(report["transport_envelope"])
        self.assertEqual(report["ingress_routes"], ["GET /v1/reader (immediate-terminal-signal)"])
        self.assertEqual(report["signed_receipts"], {"algorithm": "Ed25519", "key_id": "sample-key"})
        self.assertEqual(report["resolution"]["methods"], ["POST", "GET"])
        self.assertEqual(report["discovery_counters"], {"enabled": True, "routes": ["/", "/llms.txt"]})
        self.assertEqual(report["context_report"]["methods"], ["POST", "GET"])
        self.assertEqual(report["context_report"]["get_parameters"], ["workflow_summary", "agent_questions_or_notes"])
        self.assertEqual(inspector._methods({"method": "POST"}, "methods", "method"), ["POST"])  # a node before 0.5.6
        self.assertEqual(StubNode.seen[0][0], "/.well-known/agent-shelter.json")
        self.assertTrue(StubNode.seen[0][2].startswith("asp-mcp-inspector/"))

    def test_echo_answers_locally_first_and_with_the_signal_on_repeat(self):
        first = inspector.probe_diagnostic_echo(node=self.node, allow_local=True)
        self.assertEqual((first["http_status"], first["state"]), (200, "local-echo"))
        self.assertIn("x-asp-discovery", first["headers"])
        second = inspector.probe_diagnostic_echo(node=self.node, allow_local=True)
        self.assertEqual((second["http_status"], second["state"]), (429, "asp-terminal-signal"))
        self.assertEqual(second["success_probability"], 0)

    def test_reader_asks_for_the_envelope_and_reads_the_signal(self):
        report = inspector.query_reader_disposition("https://example.org/tiles/1?x=1&y=2", node=self.node,
                                                    allow_local=True)
        self.assertEqual(report["http_status"], 200)
        self.assertEqual(report["state"], "asp-terminal-signal")
        self.assertTrue(report["transport"].startswith("envelope"))
        self.assertEqual(report["problem_details"]["status"], 429)
        self.assertTrue(report["resolution_url"].startswith("/api/v1/agent-shelter/resolve?ticket="))
        self.assertEqual((report["ticket"], report["headers"]["agent-ticket"]), (SIGNAL["ticket"], SIGNAL["ticket"]))
        self.assertTrue(report["resolution_uri"].endswith(report["resolution_url"]))
        self.assertEqual(report["resolution_methods"], ["POST", "GET"])
        self.assertIn("The signal holds the ticket, not the proof", report["finding"])
        self.assertIn("workflow_summary and agent_questions_or_notes", report["finding"])
        path, query, _ = StubNode.seen[0]
        self.assertEqual((path, query["url"], query["envelope"]),
                         ("/v1/reader", ["https://example.org/tiles/1?x=1&y=2"], ["200"]))

    def test_a_plain_429_of_an_older_node_is_read_as_well(self):
        older = inspector.Node(self.base, self.base + "/headers", self.base + "/older/v1/reader")
        report = inspector.query_reader_disposition("https://example.org/", node=older, allow_local=True)
        self.assertEqual((report["http_status"], report["state"], report["transport"]),
                         (429, "asp-terminal-signal", "HTTP 429"))
        self.assertEqual(report["resolution_methods"], ["POST"])  # a node before 0.5.5 names one method

    def test_redirects_are_reported_not_followed(self):
        reply = inspector.fetch(self.base + "/moved", allow_local=True)
        self.assertEqual((reply.status, reply.headers.get("location")), (302, "https://elsewhere.example/"))
        self.assertEqual([seen[0] for seen in StubNode.seen], ["/moved"])

    def test_only_public_https_hosts_and_clean_target_urls(self):
        for url, reason in ((self.base + "/headers", "plain http"), ("https://localhost/", "non-public"),
                            ("https://user:secret@example.org/", "credentials"), ("ftp://example.org/", "http(s)")):
            with self.subTest(url=url), self.assertRaises(inspector.InspectorError) as caught:
                inspector.fetch(url)
            self.assertIn(reason, str(caught.exception))
        for target in ("", "ftp://example.org/file", "https://user:pw@example.org/", "x" * 3000):
            with self.subTest(target=target[:30]), self.assertRaises(inspector.InspectorError):
                inspector.query_reader_disposition(target, node=self.node, allow_local=True)
        self.assertEqual(StubNode.seen, [])  # nothing was sent for a refused request

    def test_mcp_over_stdio(self):
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "query_reader_disposition", "arguments": {"target_url": "https://example.org/a"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "no_such_tool", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 5, "method": "resources/list"},
        ]
        stdin = "\n".join(json.dumps(line) for line in lines) + "\nnot json\n"
        done = subprocess.run([sys.executable, "-I", "-B", str(MODULE), "--node", self.base, "--allow-local", "serve"],
                              input=stdin.encode(), capture_output=True, timeout=60, check=True)
        replies = [json.loads(line) for line in done.stdout.decode().splitlines()]
        self.assertEqual([reply.get("id") for reply in replies], [1, 2, 3, 4, 5, None])
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual(replies[0]["result"]["serverInfo"]["name"], "asp-mcp-inspector")
        self.assertEqual({tool["name"] for tool in replies[1]["result"]["tools"]},
                         {"check_asp_manifest", "probe_diagnostic_echo", "query_reader_disposition"})
        call = replies[2]["result"]
        self.assertFalse(call["isError"])
        self.assertEqual(call["structuredContent"]["state"], "asp-terminal-signal")
        self.assertEqual(json.loads(call["content"][0]["text"])["problem_details"]["status"], 429)
        self.assertEqual((replies[3]["error"]["code"], replies[4]["error"]["code"], replies[5]["error"]["code"]),
                         (-32602, -32601, -32700))

    def test_mcp_over_streamable_http_serves_local_clients_only(self):
        httpd = inspector.make_http_server(inspector.McpServer(self.node, True, stateful=False), 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_port

        def post(message: dict, headers: dict | None = None, host: str | None = None):
            connection = http.client.HTTPConnection("localhost", port, timeout=30)
            body = json.dumps(message).encode()
            connection.putrequest("POST", "/mcp", skip_host=host is not None)
            if host is not None:
                connection.putheader("Host", host)
            for key, value in {"Content-Type": "application/json", "Content-Length": str(len(body)),
                               "Accept": "application/json, text/event-stream", **(headers or {})}.items():
                connection.putheader(key, value)
            connection.endheaders(body)
            response = connection.getresponse()
            data = response.read()
            connection.close()
            return response.status, data

        try:
            status, data = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(data)["result"]["protocolVersion"], inspector.PROTOCOL_VERSIONS[0])
            self.assertEqual(post({"jsonrpc": "2.0", "method": "notifications/initialized"})[0], 202)
            listed = json.loads(post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                     {"MCP-Protocol-Version": "2025-06-18"})[1])
            self.assertEqual(len(listed["result"]["tools"]), 3)
            ping = {"jsonrpc": "2.0", "id": 3, "method": "ping"}
            self.assertEqual(post(ping, {"Origin": "https://attacker.example"})[0], 403)
            self.assertEqual(post(ping, host="attacker.example")[0], 403)
            self.assertEqual(post(ping, {"Origin": f"http://localhost:{port}"})[0], 200)
            connection = http.client.HTTPConnection("localhost", port, timeout=30)
            connection.request("GET", "/mcp")
            self.assertEqual(connection.getresponse().status, 405)
            connection.close()
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()

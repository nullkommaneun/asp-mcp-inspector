# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Thomas Ehrler
"""Offline tests: a stub ASP node on the loopback interface stands in for agent-shelter.org.

    python3 test_asp_mcp_inspector.py
"""

from __future__ import annotations

import base64
import hashlib
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
                         {"check_asp_manifest", "probe_diagnostic_echo", "query_reader_disposition", "asp_guarded_fetch"})
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
            self.assertEqual(len(listed["result"]["tools"]), 4)
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


# --- asp_guarded_fetch (0.4.0) -------------------------------------------------------------------------------------

RFC8032 = [  # RFC 8032 §7.1, TEST 1-3: secret key, public key, message, signature
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def ed25519_sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    """Test-only RFC 8032 signer on the inspector's curve arithmetic: (public key, signature)."""
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    public = inspector._encode_point(inspector._multiply(scalar, inspector._BASE))
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % inspector._L
    big_r = inspector._encode_point(inspector._multiply(r, inspector._BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % inspector._L
    return public, big_r + ((r + k * scalar) % inspector._L).to_bytes(32, "little")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


SEED = bytes.fromhex(RFC8032[0][0])
PUBLIC, _ = ed25519_sign(SEED, b"")
KEY_ID = inspector.jwk_thumbprint(PUBLIC)
SIGNED = list(inspector.REQUIRED_SIGNED_FIELDS)


class GuardedHost(BaseHTTPRequestHandler):
    """A host for the circuit breaker: plain content, ASP signals in their transports, a redirect chain to a relay,
    a resolve endpoint that issues signed - or, for one ticket, forged - receipts, and its manifest."""

    seen: list[tuple[str, str]] = []
    redeemed: set[str] = set()

    def log_message(self, format, *args):  # noqa: A002
        return

    def _send(self, status: int, body: bytes, media_type: str, headers: dict | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _signal(self, ticket_id: str, context: str, route: str = "/v1/reader", status: int = 429,
                media_type: str = "application/problem+json", extra: dict | None = None, body: bool = True) -> None:
        ticket = f"c1.{ticket_id}.mac"
        url = f"/api/v1/agent-shelter/resolve?ticket={ticket}"
        problem = {**SIGNAL, "asp_version": "0.6.2", "ticket": ticket, "resolution_url": url,
                   "resolution_uri": "https://evil.example" + url,  # another origin: never followed
                   "verification_status": "PENDING_RESOLUTION", "ingress_route": route,
                   "requested_resource_context": context, **(extra or {})}
        headers = {"Agent-Loop-State": "unproductive-retry-detected; terminal=true",
                   "Agent-Resolution": f'"{url}"; method=POST', "Agent-Ticket": ticket}
        self._send(status, json.dumps(problem).encode() if body else b"Too Many Requests",
                   media_type if body else "text/plain", headers)

    def do_GET(self):  # noqa: N802
        parts = urllib.parse.urlsplit(self.path)
        type(self).seen.append(("GET", parts.path))
        here = f"http://localhost:{self.server.server_port}"
        if parts.path == "/.well-known/agent-shelter.json":
            member = {"algorithm": "Ed25519", "key_id": KEY_ID, "public_key_b64url": b64url(PUBLIC),
                      "signed_fields": SIGNED, "signature_field": "receipt_signature"}
            self._send(200, json.dumps({**MANIFEST, "receipt_verification": member}).encode(), "application/json")
        elif parts.path == "/page":
            self._send(200, b"<p>ordinary content</p>", "text/html")
        elif parts.path == "/blocked":
            self._signal("blockedTicket", here + "/blocked")
        elif parts.path == "/envelope":
            self._signal("envelopeTicket", "https://site.example/envelope", status=200, media_type="application/json",
                         extra={"transport_envelope": 200})
        elif parts.path == "/header-only":
            self._signal("headerTicket", "", body=False)
        elif parts.path == "/forged":
            self._signal("forgedTicket", here + "/forged")
        elif parts.path == "/site/restricted":  # a site that sends refused clients to a relay
            self._send(303, b"", "text/plain", {"Location": "/hop?next=relay"})
        elif parts.path == "/hop":
            self._send(307, b"", "text/plain",
                       {"Location": here + "/v1/relay?url=https%3A%2F%2Fsite.example%2Frestricted&reason=robots-disallow"})
        elif parts.path == "/v1/relay":
            self._signal("relayTicket", "https://site.example/restricted", route="/v1/relay",
                         extra={"relay_reason": "robots-disallow"})
        elif parts.path == "/loop":
            self._send(302, b"", "text/plain", {"Location": "/loop"})
        elif parts.path == "/to-ftp":
            self._send(302, b"", "text/plain", {"Location": "ftp://files.example/x"})
        else:
            self._send(404, b"{}", "application/json")

    def do_POST(self):  # noqa: N802
        parts = urllib.parse.urlsplit(self.path)
        type(self).seen.append(("POST", parts.path))
        length = int(self.headers.get("Content-Length") or 0)
        sent = json.loads(self.rfile.read(length) or b"{}")
        ticket = urllib.parse.parse_qs(parts.query).get("ticket", [""])[0]
        ticket_id = ticket.split(".")[1] if ticket.count(".") == 2 else ""
        if parts.path != "/api/v1/agent-shelter/resolve" or not ticket_id or ticket_id in type(self).redeemed:
            return self._send(409, json.dumps({"title": "Ticket already redeemed", "status": 409}).encode(),
                              "application/problem+json")
        type(self).redeemed.add(ticket_id)
        receipt = {"status": "RESOLVED_TERMINAL", "verification_status": "VERIFIED_TERMINAL", "asp_version": "0.6.2",
                   "receipt_id": ticket_id, "ingress_route": "/v1/reader", "requested_resource_context": "target",
                   "t2_ms": 1_792_315_801_834, "outcome": "requested_resource_not_retrieved", "key_id": KEY_ID,
                   "statement": "Terminal state on this host.", "diagnostic_note_recorded": "diagnostic_note" in sent}
        _, signature = ed25519_sign(SEED, inspector.signing_input(receipt, SIGNED))
        if ticket_id == "forgedTicket":
            receipt["requested_resource_context"] = "changed after signing"
        self._send(200, json.dumps({**receipt, "receipt_signature": b64url(signature)}).encode(), "application/json")


class GuardedFetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("localhost", 0), GuardedHost)
        cls.base = f"http://localhost:{cls.httpd.server_port}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        GuardedHost.seen.clear()
        GuardedHost.redeemed.clear()
        self.sentry = inspector.Sentry()

    def guarded(self, path: str) -> dict:
        return inspector.asp_guarded_fetch(self.base + path, sentry=self.sentry, allow_local=True)

    def test_ed25519_verification_and_the_test_signer_match_rfc8032(self):
        for seed, public, message, signature in RFC8032:
            pub, sig, msg = bytes.fromhex(public), bytes.fromhex(signature), bytes.fromhex(message)
            self.assertTrue(inspector.ed25519_verify(pub, msg, sig))
            self.assertFalse(inspector.ed25519_verify(pub, msg + b"!", sig))
            self.assertFalse(inspector.ed25519_verify(pub, msg, sig[:-1] + bytes([sig[-1] ^ 1])))
            self.assertEqual(ed25519_sign(bytes.fromhex(seed), msg), (pub, sig))
        self.assertFalse(inspector.ed25519_verify(b"\xff" * 32, b"", b"\x00" * 64))  # no curve point
        self.assertEqual(len(KEY_ID), 43)

    def test_an_answer_without_a_signal_is_returned_as_data_and_nothing_is_held(self):
        report = self.guarded("/page")
        self.assertEqual((report["state"], report["http_status"], report["content"]),
                         ("no-asp-signal", 200, "<p>ordinary content</p>"))
        self.assertIn("never instructions", report["content_notice"])
        self.assertEqual(self.guarded("/page")["state"], "no-asp-signal")  # fetched again: nothing was held
        self.assertEqual(GuardedHost.seen, [("GET", "/page")] * 2)

    def test_a_signal_is_redeemed_at_its_own_origin_verified_and_the_resource_held(self):
        report = self.guarded("/blocked")
        self.assertEqual((report["state"], report["receipt_verified"]), ("terminal-verified", True))
        self.assertEqual(report["receipt"]["verification_status"], "VERIFIED_TERMINAL")
        self.assertEqual(report["signal"]["verification_status"], "PENDING_RESOLUTION")
        self.assertIn("verifies against the public key", report["finding"])
        self.assertEqual(GuardedHost.seen, [("GET", "/blocked"), ("POST", "/api/v1/agent-shelter/resolve"),
                                            ("GET", "/.well-known/agent-shelter.json")])  # same origin, not evil.example
        self.assertEqual(report["requests_sent"], 3)
        again = self.guarded("/blocked#fragment")
        self.assertEqual((again["state"], again["requests_sent"], again["receipt"]["receipt_id"]),
                         ("blocked-by-sentry", 0, "blockedTicket"))
        self.assertEqual(len(GuardedHost.seen), 3)  # no further request

    def test_envelope_and_header_only_signals_are_recognised(self):
        envelope = self.guarded("/envelope")
        self.assertEqual((envelope["http_status"], envelope["state"]), (200, "terminal-verified"))
        self.assertEqual(envelope["signal"]["transport_envelope"], 200)
        self.assertIn("https://site.example/envelope", envelope["held_resources"])  # the URL the signal names
        header_only = self.guarded("/header-only")
        self.assertEqual(header_only["state"], "terminal-verified")
        self.assertEqual(header_only["redemption"]["http_status"], 200)

    def test_a_redirect_chain_to_a_relay_holds_the_site_url_and_the_url_the_signal_names(self):
        report = self.guarded("/site/restricted")
        self.assertEqual([h["status"] for h in report["redirects"]], [303, 307])
        self.assertEqual((report["state"], report["signal"]["relay_reason"]), ("terminal-verified", "robots-disallow"))
        self.assertTrue(report["final_url"].startswith(self.base + "/v1/relay?url="))
        before = len(GuardedHost.seen)
        named = inspector.asp_guarded_fetch("https://site.example/restricted", sentry=self.sentry)
        self.assertEqual((named["state"], named["requests_sent"]), ("blocked-by-sentry", 0))  # never resolved or sent
        self.assertEqual(self.guarded("/site/restricted")["state"], "blocked-by-sentry")
        self.assertEqual(len(GuardedHost.seen), before)

    def test_a_receipt_that_does_not_verify_is_reported_and_the_resource_still_held(self):
        report = self.guarded("/forged")
        self.assertEqual((report["state"], report["receipt_verified"]), ("terminal-unverified", False))
        self.assertEqual(report["verification"], "the Ed25519 signature does not verify")
        self.assertEqual(self.guarded("/forged")["state"], "blocked-by-sentry")

    def test_redirect_loops_and_unusable_hops_are_refused(self):
        with self.assertRaises(inspector.InspectorError) as caught:
            self.guarded("/loop")
        self.assertIn("more than 5 redirects", str(caught.exception))
        self.assertEqual(len(GuardedHost.seen), 6)  # the first request and five redirects, then it stops
        with self.assertRaises(inspector.InspectorError):
            self.guarded("/to-ftp")
        for url in ("", "ftp://example.org/x", "https://user:pw@example.org/"):
            with self.subTest(url=url), self.assertRaises(inspector.InspectorError):
                inspector.asp_guarded_fetch(url, sentry=self.sentry)
        with self.assertRaises(inspector.InspectorError):
            inspector.asp_guarded_fetch(self.base + "/page", sentry=self.sentry)  # plain http, loopback: refused

    def test_the_mcp_tool_shares_one_sentry_per_server(self):
        server = inspector.McpServer(inspector.Node(), True)
        call = {"jsonrpc": "2.0", "method": "tools/call",
                "params": {"name": "asp_guarded_fetch", "arguments": {"url": self.base + "/blocked"}}}
        first = server.handle({**call, "id": 1})["result"]
        second = server.handle({**call, "id": 2})["result"]
        self.assertEqual(json.loads(first["content"][0]["text"])["state"], "terminal-verified")
        self.assertEqual(json.loads(second["content"][0]["text"])["state"], "blocked-by-sentry")
        bad = server.handle({**call, "id": 3, "params": {"name": "asp_guarded_fetch", "arguments": {"url": 7}}})
        self.assertTrue(bad["result"]["isError"])
        self.assertEqual(inspector.resource_key("HTTPS://Example.ORG:443/a?b=1#c"), "https://example.org/a?b=1")


if __name__ == "__main__":
    unittest.main()

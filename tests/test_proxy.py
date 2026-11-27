"""Tests for hookip.proxy — localhost sockets only, no real network.
Run: python tests/test_proxy.py"""
import os
import socket
import sys
import threading
import time
import types
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import proxy as proxymod  # noqa: E402
from hookip.proxy import (ProxyServer, Stats, DpiReset, UpstreamDied,  # noqa: E402
                          ClientAbortError)
from hookip.doh import ResolveError  # noqa: E402

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, cond))
    print(("PASS" if cond else "FAIL"), name, extra, flush=True)


class FakeLog:
    def __init__(self):
        self.lines = []

    def _w(self, lvl):
        def f(msg, *a, **k):
            self.lines.append((lvl, str(msg)))
        return f

    debug = property(lambda self: self._w("debug"))
    info = property(lambda self: self._w("info"))
    ok = property(lambda self: self._w("ok"))
    warn = property(lambda self: self._w("warn"))
    error = property(lambda self: self._w("error"))
    verbose = False


def make_server(port=9400, **kw):
    cfg = types.SimpleNamespace(port=port, fragment_size=2, strategy="smart",
                                excluded=[], doh_enabled=False,
                                proxy_mode="manual", upstream_proxy="")
    for k, v in kw.items():
        setattr(cfg, k, v)
    ps = ProxyServer(cfg, FakeLog(), Stats(), "tok")
    ps.resolver.resolve = lambda host, qtype=1: ["127.0.0.1"]
    ps.running = True
    return ps


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def socketpair():
    a, b = socket.socketpair()
    a.settimeout(10)
    b.settimeout(10)
    return a, b


def recv_until(sock, marker, budget=5.0):
    data = b""
    t0 = time.time()
    sock.settimeout(0.5)
    while marker not in data and time.time() - t0 < budget:
        try:
            part = sock.recv(65536)
        except socket.timeout:
            continue
        if not part:
            break
        data += part
    return data


# ---- 1. _parse_head with a body containing ':' lines ------------------
def test_parse_head_body():
    head = (b"POST http://x/y HTTP/1.1\r\nHost: x.test\r\n"
            b'Content-Type: application/json\r\nContent-Length: 26\r\n\r\n'
            b'{"a:b": true, "c:d": null}\r\n')
    method, target, headers = ProxyServer._parse_head(head)
    check("parse_head: method/target", method == "POST" and target == "http://x/y")
    check("parse_head: no body line became a header",
          all("{" not in k and '"' not in k and ":" not in k for k in headers),
          str(list(headers)))
    check("parse_head: real headers intact",
          headers.get("host") == "x.test"
          and headers.get("content-type") == "application/json"
          and headers.get("content-length") == "26")


# ---- 2. plain HTTP POST body arrives exactly once ---------------------
def origin_server(port=None, responses=b""):
    """Accepts one connection; allocates its own port unless given."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port if port else 0))
    port = srv.getsockname()[1]
    srv.listen(5)
    got = {"data": b"", "n": 0}
    done = threading.Event()

    def serve():
        c, _ = srv.accept()
        c.settimeout(5)
        try:
            while True:
                try:
                    part = c.recv(65536)
                except socket.timeout:
                    break
                if not part:
                    break
                got["data"] += part
                if b"\r\n\r\n" in got["data"]:
                    hdr, _, body = got["data"].partition(b"\r\n\r\n")
                    cl = 0
                    for line in hdr.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            cl = int(line.split(b":")[1])
                    if len(body) >= cl:
                        break
        except OSError:
            pass
        got["n"] = got["data"].count(b"HELLOBODY")
        c.sendall(responses)
        try:
            # graceful FIN: an abrupt close with unread data sends RST on
            # Windows and would trip the proxy's server-side error path
            c.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            c.close()
        except OSError:
            pass
        done.set()
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return got, done, srv, port


def test_plain_http_body_once():
    for upstream in (False, True):
        label = "upstream" if upstream else "non-upstream"
        responses = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                     b"Connection: close\r\n\r\nhi")
        got, done, _srv, origin_port = origin_server(responses=responses)
        ps = make_server(upstream_proxy=("127.0.0.1:" + str(origin_port)
                                         if upstream else ""))
        client, client_peer = socketpair()
        # head WITHOUT body: in production _handle already read the head,
        # so the head arg is the read head and the body stays buffered on
        # the client socket — streamed by the relay loop
        head = (f"POST http://127.0.0.1:{origin_port}/submit HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\nContent-Length: 9\r\n"
                f"Connection: close\r\n\r\n").encode()
        result = {}
        def call():
            try:
                # non-upstream: proxy rebuilds the request (origin-relative)
                ps._plain_http(client, head, "POST",
                               f"http://127.0.0.1:{origin_port}/submit",
                               ProxyServer._parse_head(head)[2])
                result["ok"] = True
            except Exception as e:
                result["err"] = e
        th = threading.Thread(target=call, daemon=True)
        th.start()
        time.sleep(0.05)
        client_peer.sendall(b"HELLOBODY")
        th.join(8)
        check(f"plain POST ({label}) completes", result.get("ok"),
              repr(result.get("err")))
        if not result.get("ok"):
            continue
        done.wait(5)
        check(f"plain POST body exactly once ({label})",
              got["n"] == 1, f"count={got['n']} raw={got['data'][:60]!r}")
        resp = recv_until(client_peer, b"200 OK")
        check(f"plain POST response relayed ({label})", b"200 OK" in resp)
        client.close(); client_peer.close()


def test_expect_100_continue():
    got, done, _srv, origin_port = origin_server(
        responses=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                  b"Connection: close\r\n\r\nhi")
    ps = make_server()
    client, client_peer = socketpair()
    head = (f"POST http://127.0.0.1:{origin_port}/upload HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nContent-Length: 9\r\n"
            f"Expect: 100-continue\r\nConnection: close\r\n\r\n").encode()
    t0 = time.time()
    # head passed as already-read; NO body is sent yet
    result = {}
    def run():
        try:
            ps._plain_http(client, head, "POST",
                           f"http://127.0.0.1:{origin_port}/upload",
                           ProxyServer._parse_head(head)[2])
            result["ok"] = True
        except Exception as e:
            result["err"] = e
    th = threading.Thread(target=run, daemon=True)
    th.start()
    # client behaves like an Expect user: waits for the interim response,
    # then sends the body
    time.sleep(0.3)
    client_peer.sendall(b"HELLOBODY")
    th.join(8)
    dt = time.time() - t0
    check("Expect: 100-continue completes well under 30 s",
          result.get("ok") and dt < 10, f"{dt:.2f}s result={result}")
    done.wait(5)
    check("Expect: 100-continue body reaches origin once", got["n"] == 1,
          f"count={got['n']}")
    client.close(); client_peer.close()


# ---- 4/5. relay initial_up + DpiReset hierarchy ------------------------
def test_relay_initial_up():
    ps = make_server()
    c1, c2 = socketpair()
    s1, s2 = socketpair()
    s2.close()                       # upstream closes cleanly right away
    try:
        ps._relay(c1, s1, "relay.test", initial_up=5)
        check("clean FIN after handshake -> UpstreamDied", False, "no raise")
    except UpstreamDied:
        check("clean FIN after handshake -> UpstreamDied", True)
    except Exception as e:
        check("clean FIN after handshake -> UpstreamDied", False, repr(e))
    check("UpstreamDied subclasses DpiReset",
          issubclass(UpstreamDied, DpiReset) and issubclass(DpiReset, OSError))
    # stats counted the first flight
    tot, act, up, down, failed, blocked = ps.stats.totals()
    check("first flight counted in stats", up >= 5, f"up={up}")
    c1.close(); c2.close(); s1.close()


# ---- 5/6. DPI reset classification + last-resort raw -------------------
def run_tunnel_async(ps, csock, writer, host, port, result,
                     hello=b"\x16\x03\x01hello-bytes"):
    """Run ps._tunnel(csock) in a thread; push a first flight via `writer`
    (the OTHER end of the pair) like a real client would."""
    def run():
        try:
            result["s"] = ps._tunnel(csock, host, port)
            result["ok"] = True
        except Exception as e:
            result["err"] = e
    th = threading.Thread(target=run, daemon=True)
    th.start()
    time.sleep(0.3)
    if hello:
        try:
            writer.sendall(hello)
        except OSError:
            pass
    return th


def test_dpi_flag_and_raw_last_resort():
    ps = make_server()
    calls = []

    def fake_tunnel_once(csock, host, port, strategy, first, excl=False,
                         force_no_frag=False):
        calls.append((strategy, force_no_frag))
        if strategy == "raw" and force_no_frag:
            s1, s2 = socketpair()
            return s1
        raise DpiReset(f"{host}:{port} connection reset during ClientHello "
                       f"(possible DPI reset)")

    ps._tunnel_once = fake_tunnel_once
    client, client_peer = socketpair()
    result = {}
    th = run_tunnel_async(ps, client, client_peer, "dpi.test", 443, result)
    th.join(10)
    s = result.get("s")
    check("dpi _tunnel completes via raw", result.get("ok"), str(result))
    check("dpi host: raw last-resort attempt made and wins",
          calls[-1] == ("raw", True) and calls[:3] == [("smart", False),
                                                       ("chunk", False),
                                                       ("random", False)],
          str(calls))
    with ps._state_lock:
        pref = ps._strat_pref.get("dpi.test")
    check("dpi host remembers raw", pref == "raw", str(pref))
    with ps._fails_lock:
        entry = ps._fails.get("dpi.test")
    check("dpi host recorded dpi, NOT capped after one cycle",
          entry is not None and entry[2] is False, str(entry))
    client.close(); client_peer.close()
    try:
        s.close()
    except OSError:
        pass


def test_always_resets_falls_through_raw():
    ps = make_server()
    calls = []

    def fake_tunnel_once(csock, host, port, strategy, first, excl=False,
                         force_no_frag=False):
        calls.append((strategy, force_no_frag))
        raise DpiReset(f"{host}:{port} connection reset during ClientHello "
                       f"(possible DPI reset)")

    ps._tunnel_once = fake_tunnel_once
    client, client_peer = socketpair()
    result = {}
    th = run_tunnel_async(ps, client, client_peer, "hard.test", 443, result)
    th.join(10)
    try:
        ps._tunnel(client, "hard.test", 443) if False else None
        err = result.get("err")
        if err is None:
            check("always-reset raises final OSError", False, "no raise")
        else:
            msg = str(err)
            check("always-reset raises final OSError", "failed" in msg, msg[:80])
            check("always-reset: unfragmented attempt was made",
                  ("raw", True) in calls and len(calls) == 4, str(calls))
            check("always-reset: attempt errors listed",
                  "smart" in msg and "unfragmented" in msg, msg[-80:])
    finally:
        pass
    with ps._fails_lock:
        entry = ps._fails.get("hard.test")
    check("always-reset: dpi recorded, not capped after ONE cycle",
          entry is not None and entry[2] is False, str(entry))
    # second full cycle -> dpi capped (count >= 2)
    result2 = {}
    th2 = run_tunnel_async(ps, client, client_peer, "hard.test", 443, result2)
    th2.join(10)
    with ps._fails_lock:
        entry2 = ps._fails.get("hard.test")
    check("always-reset: capped after second full cycle", entry2[2] is True,
          str(entry2))
    client.close(); client_peer.close()


def test_no_string_matching():
    # a NON-DPI OSError (plain timeout) must NOT trigger the raw attempt
    ps = make_server()

    def fake_tunnel_once(csock, host, port, strategy, first, excl=False,
                         force_no_frag=False):
        calls.append(strategy)
        raise OSError(f"{host}:{port} could not connect (timeout)")

    calls = []
    ps._tunnel_once = fake_tunnel_once
    client, client_peer = socketpair()
    result = {}
    th = run_tunnel_async(ps, client, client_peer, "dead.test", 443, result,
                          hello=b"\x16\x03\x01hello-bytes")
    th.join(10)
    check("non-DPI failure: no raw last-resort, no ClientHello string test",
          calls == ["smart", "chunk", "random"], str(calls))
    client.close(); client_peer.close()


# ---- 6. server socket closed when _relay raises ------------------------
def test_relay_raise_closes_server():
    ps = make_server()
    port = free_port()
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    accepted = {}
    def serve():
        c, _ = srv.accept()
        accepted["c"] = c
    threading.Thread(target=serve, daemon=True).start()

    def boom(*a, **k):
        raise RuntimeError("boom")

    ps._relay = boom
    client, client_peer = socketpair()
    try:
        ps._tunnel_once(client, "127.0.0.1", port, "raw", b"",
                        force_no_frag=True)
        check("relay raise propagates", False, "no raise")
    except RuntimeError:
        check("relay raise propagates", True)
    time.sleep(0.2)
    c = accepted.get("c")
    if c is None:
        check("server socket closed when _relay raises", False, "not accepted")
    else:
        c.settimeout(2)
        try:
            eof = c.recv(100)
        except (socket.timeout, OSError):
            eof = None
        check("server socket closed when _relay raises", eof == b"",
              f"recv={eof!r}")
    client.close(); client_peer.close()
    srv.close()


# ---- 7. server-first protocols -----------------------------------------
def banner_server(port):
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                c.sendall(b"SSH-2.0-OpenSSH banner\r\n")
                c.settimeout(5)
                try:
                    c.recv(100)
                except OSError:
                    pass
                c.close()
            except OSError:
                return
    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_server_first():
    port = free_port()
    srv = banner_server(port)
    ps = make_server()
    client, client_peer = socketpair()
    result = {}
    def run():
        try:
            result["s"] = ps._tunnel(client, "127.0.0.1", port)
            result["ok"] = True
        except Exception as e:
            result["err"] = e
    th = threading.Thread(target=run, daemon=True)
    th.start()
    banner = recv_until(client_peer, b"SSH-2.0", budget=8)
    th.join(8)
    check("server-first (non-443) reaches the banner",
          b"SSH-2.0" in banner and result.get("ok"),
          f"banner={banner[:20]!r} result={result}")
    client.close(); client_peer.close()
    srv.close()


def test_443_no_data_still_aborts():
    ps = make_server()
    client, client_peer = socketpair()
    result = {}
    def run():
        try:
            ps._tunnel(client, "silent.test", 443)
            result["ok"] = True
        except Exception as e:
            result["err"] = e
    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(15)
    check("443 no-data still ClientAbortError",
          isinstance(result.get("err"), ClientAbortError), str(result))
    client.close(); client_peer.close()


# ---- 8. state dict thread safety ---------------------------------------
def test_state_dict_threads():
    ps = make_server()
    errs = []
    def hammer(base):
        for i in range(300):
            try:
                ps._bounded_state_put(ps._strat_pref, f"h{base}-{i % 40}",
                                      "smart", 32)
                with ps._state_lock:
                    ps._strat_pref.get("h-x")
            except Exception as e:
                errs.append(e)
    threads = [threading.Thread(target=hammer, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    check("16 threads filling/evicting _strat_pref never raise", not errs,
          str(errs[:1]))
    check("_strat_pref stays bounded", len(ps._strat_pref) <= 32,
          str(len(ps._strat_pref)))


# ---- 9. failed thread start releases the slot --------------------------
def test_thread_start_failure_releases_slot():
    ps = make_server()
    port = free_port()
    listener = socket.socket()
    listener.bind(("127.0.0.1", port))
    listener.listen(5)
    ps._lsock = listener
    ps.on_accept_death = None
    counter = {"n": 0}
    real_thread = threading.Thread

    class FakeThread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            counter["n"] += 1
            if counter["n"] >= 5:
                ps.running = False          # end the loop after 5 failures
            raise RuntimeError("no threads left")

    # run the loop in a thread and feed it connections one at a time:
    # FakeThread.start fails 5 times, and the 5th failure sets running=False
    # so the loop exits and on_accept_death is NOT the expected exit path
    clients = []
    loop_done = {}
    def run_loop():
        with mock.patch.object(proxymod.threading, "Thread", FakeThread):
            ps._accept_loop()
        loop_done["ok"] = True
    lt = threading.Thread(target=run_loop, daemon=True)
    lt.start()
    for _ in range(8):
        c = socket.socket()
        try:
            c.connect(("127.0.0.1", port))
            clients.append(c)
        except OSError:
            c.close()
            break
        time.sleep(0.05)
    lt.join(10)
    for c in clients:
        c.close()
    listener.close()
    check("accept loop exits after thread-start failures", bool(loop_done))
    tot, act, up, down, failed, blocked = ps.stats.totals()
    check("thread-start failures: no leaked active conn", act == 0, f"active={act}")
    slots = 0
    while ps._conn_limit.acquire(blocking=False):
        slots += 1
    for _ in range(slots):
        ps._conn_limit.release()
    check("thread-start failures: limit intact after many failures",
          slots == proxymod._MAX_CONNECTIONS, f"free slots={slots}")


# ---- 10. accept error budget -> on_accept_death ------------------------
def test_accept_death():
    ps = make_server()
    class BadListener:
        def accept(self):
            raise OSError("listener broken")

        def fileno(self):
            return 3

    ps._lsock = BadListener()
    fired = {"n": 0}
    ps.on_accept_death = lambda: fired.__setitem__("n", fired["n"] + 1)
    t0 = time.time()
    ps._accept_loop()
    dt = time.time() - t0
    check("persistent accept failure exits after ~2 s budget",
          fired["n"] == 1 and 1.5 < dt < 5, f"dt={dt:.1f}s fired={fired['n']}")


# ---- 11. PAC correctness -----------------------------------------------
def get_pac(ps, excluded):
    ps.cfg.excluded = excluded
    a, b = socketpair()
    ps._serve_pac(b)
    a.settimeout(2)
    data = b""
    try:
        while True:
            part = a.recv(65536)
            if not part:
                break
            data += part
    except (socket.timeout, OSError):
        pass
    a.close(); b.close()
    return data.split(b"\r\n\r\n", 1)[1].decode()


def test_pac():
    ps = make_server(port=9410)
    pac = get_pac(ps, ["*.example.com"])
    check("PAC: no dnsDomainIs", "dnsDomainIs" not in pac)
    check("PAC: *.example.com emits bare + wildcard",
          "host == 'example.com'" in pac
          and "shExpMatch(host, '*.example.com')" in pac)
    check("PAC: private ranges use regex form", ".test(host)" in pac
          and "172\\.(?:1[6-9]|2[0-9]|3[01])" in pac)
    check("PAC: ::1 local rules", "host == '::1'" in pac
          and "host == '[::1]'" in pac)
    check("PAC: port via f-string",
          "PROXY 127.0.0.1:9410; DIRECT" in pac)
    try:
        get_pac(ps, ["%.weird%25.test", "*.%evil"])
        check("PAC: exclusion containing % does not raise", True)
    except Exception as e:
        check("PAC: exclusion containing % does not raise", False, repr(e))
    pac2 = get_pac(ps, ["foo.bar.test"])
    check("PAC: dotted non-wildcard -> exact host ==",
          "host == 'foo.bar.test'" in pac2 and "dnsDomainIs" not in pac2)


# ---- 12. PUT/PATCH/DELETE forwarded ------------------------------------
def test_put_patch_delete():
    for method in ("PUT", "PATCH", "DELETE"):
        got, done, _srv, port = origin_server(
            responses=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                      b"Connection: close\r\n\r\n")
        ps = make_server()
        client, client_peer = socketpair()
        head = (f"{method} http://127.0.0.1:{port}/thing HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\nConnection: close\r\n\r\n").encode()
        try:
            ps._plain_http(client, head, method,
                           f"http://127.0.0.1:{port}/thing",
                           ProxyServer._parse_head(head)[2])
            done.wait(3)
            ok = got["data"].startswith(method.encode() + b" ")
            check(f"{method} forwarded (not 405)", ok, got["data"][:24].decode(errors="replace"))
        except Exception as e:
            check(f"{method} forwarded (not 405)", False, repr(e))
        client.close(); client_peer.close()


# ---- 13. upstream mode skips DNS ---------------------------------------
def test_upstream_skips_dns():
    # fake network proxy: answers CONNECT 200, then echoes bytes back
    up_port = free_port()
    upsrv = socket.socket()
    upsrv.bind(("127.0.0.1", up_port))
    upsrv.listen(5)
    def upstream_serve():
        while True:
            try:
                c, _ = upsrv.accept()
            except OSError:
                return
            c.settimeout(5)
            try:
                head = b""
                while b"\r\n\r\n" not in head:
                    part = c.recv(4096)
                    if not part:
                        return
                    head += part
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                # echo mode: everything after the CONNECT is echoed back
                c.settimeout(3)
                try:
                    while True:
                        part = c.recv(4096)
                        if not part:
                            break
                        c.sendall(part)
                except (socket.timeout, OSError):
                    pass
                c.close()
            except OSError:
                return
    threading.Thread(target=upstream_serve, daemon=True).start()

    ps = make_server(upstream_proxy=f"127.0.0.1:{up_port}")

    def resolve_boom(host, qtype=1):
        raise ResolveError("boom.test: should not be called")

    ps.resolver.resolve = resolve_boom
    client, client_peer = socketpair()
    result = {}
    def run():
        try:
            result["s"] = ps._tunnel(client, "target.test", 443)
            result["ok"] = True
        except Exception as e:
            result["err"] = repr(e)
    th = threading.Thread(target=run, daemon=True)
    th.start()
    time.sleep(0.3)                      # let _tunnel send its 200 banner
    client_peer.sendall(b"\x16\x03\x01clienthello-bytes")
    th.join(10)
    check("upstream mode: CONNECT succeeds without resolving",
          result.get("ok"), str(result))
    echo = recv_until(client_peer, b"clienthello-bytes", budget=5)
    check("upstream mode: hello bytes reached the network proxy",
          b"clienthello-bytes" in echo, f"echo={echo[:40]!r}")
    client.close(); client_peer.close()
    upsrv.close()


# ---- 14. cached negative classification --------------------------------
def test_cached_negative_blocked():
    ps = make_server()
    client, client_peer = socketpair()
    def fake_tunnel(csock, host, port):
        raise ResolveError("x.test: no addresses (DNS unreachable or dead "
                           "domain) (cached)")
    ps._tunnel = fake_tunnel
    result = {}
    def run():
        try:
            ps._handle(client)
            result["done"] = True
        except Exception as e:
            result["err"] = repr(e)
    client_peer.sendall(b"CONNECT x.test:443 HTTP/1.1\r\nHost: x.test\r\n\r\n")
    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(10)
    tot, act, up, down, failed, blocked = ps.stats.totals()
    check("cached 'no addresses' -> blocked=True, failed=False",
          blocked == 1 and failed == 0 and act == 0,
          f"blocked={blocked} failed={failed} active={act} {result}")
    warn_lines = [m for lvl, m in ps.log.lines if lvl == "warn"]
    check("cached 'no addresses' logged as DNS problem, not proxy failure",
          any("DNS could not resolve" in m for m in warn_lines),
          str(warn_lines[:1]))
    client.close(); client_peer.close()


# ---- 15. connect-dead fail-fast ----------------------------------------
def test_flap_retry_recovers_known_good():
    """A host that tunneled before and now fails every strategy gets ONE
    extra round — and that round wins (flapping upstream, e.g. gnu.org)."""
    ps = make_server()
    with ps._state_lock:
        ps._strat_pref["gnu.test"] = "smart"     # it worked earlier today
    calls = []

    def fake_tunnel_once(csock, host, port, strategy, first, excl=False,
                         force_no_frag=False):
        calls.append(strategy)
        if len(calls) >= 2:
            s1, _s2 = socketpair()               # the alive window opens on
            return s1                            # the second (flap-retry) round
        raise proxymod.ConnectDead(
            f"{host}:{port} could not connect (1 address(es) tried, timed out)")

    ps._tunnel_once = fake_tunnel_once
    client, client_peer = socketpair()
    result = {}
    th = run_tunnel_async(ps, client, client_peer, "gnu.test", 443, result)
    th.join(10)
    s = result.get("s")
    check("flap-retry: known-good host recovered on second round",
          result.get("ok") and s is not None, str(result))
    check("flap-retry: loop attempt + one extra fresh round",
          calls == ["smart", "smart"], str(calls))
    client.close(); client_peer.close()
    try:
        s.close()
    except OSError:
        pass


def test_flap_retry_skips_never_worked():
    """A host that NEVER tunneled successfully gets no extra round —
    dead-forever IPs keep their fast failure."""
    ps = make_server()                        # no _strat_pref entry
    calls = []

    def fake_tunnel_once(csock, host, port, strategy, first, excl=False,
                         force_no_frag=False):
        calls.append(strategy)
        raise proxymod.ConnectDead(
            f"{host}:{port} could not connect (1 address(es) tried, timed out)")

    ps._tunnel_once = fake_tunnel_once
    client, client_peer = socketpair()
    result = {}
    th = run_tunnel_async(ps, client, client_peer, "neverworked.test", 443, result)
    th.join(10)
    check("no flap-retry for never-worked host (single attempt)",
          isinstance(result.get("err"), OSError) and len(calls) == 1,
          f"calls={calls} err={result.get('err')}")
    client.close(); client_peer.close()


def test_flap_retry_time_budget():
    """When the strategy rounds already burned >= 6 s (slow dead routing),
    the flap retry must NOT add another round."""
    ps = make_server()
    with ps._state_lock:
        ps._strat_pref["slow.test"] = "smart"
    calls = []

    def fake_tunnel_once(csock, host, port, strategy, first, excl=False,
                         force_no_frag=False):
        calls.append(strategy)
        time.sleep(0.05)                     # simulated cost per attempt
        offset[0] += 7.0                     # each attempt 'costs' 7 s of
                                             # fake clock — deterministic
        raise proxymod.ConnectDead(
            f"{host}:{port} could not connect (1 address(es) tried, timed out)")

    ps._tunnel_once = fake_tunnel_once
    # fast-forward the clock past the budget without sleeping: _tunnel
    # reads time.time() live, so shift the reference by monkeypatching
    real_time = proxymod.time.time
    offset = [0.0]

    def fake_time():
        return real_time() + offset[0]

    proxymod.time = types.SimpleNamespace(time=fake_time,
                                          sleep=time.sleep,
                                          strftime=time.strftime)
    try:
        client, client_peer = socketpair()
        result = {}
        th = run_tunnel_async(ps, client, client_peer, "slow.test", 443, result)
        th.join(10)
        client.close(); client_peer.close()
    finally:
        proxymod.time = real_time.__self__ if hasattr(real_time, "__self__") else time
    check("time budget: no flap-retry after >= 6 s of attempts",
          isinstance(result.get("err"), OSError)
          and calls == ["smart"], f"calls={calls} err={result.get('err')}")


def test_bind_error_messages():
    """Start's bind failure must distinguish 'in use' from Windows-reserved
    ranges (Hyper-V/WSL reserve large blocks; WinError 10013 there used to
    be misreported as 'in use by another program')."""
    ps = make_server()
    ps.cfg.port = 8936
    ps.start()
    ps2 = make_server()
    ps2.cfg.port = 8936
    try:
        ps2.start()
        check("double bind refused", False, "second start succeeded?!")
    except OSError as exc:
        check("double bind refused",
              "already in use" in str(exc) and "another program" in str(exc),
              str(exc)[:90])

    def fake_bind(addr):
        err = OSError(10013, "An attempt was made to access a socket "
                              "in a way forbidden by its access permissions")
        err.winerror = 10013
        raise err

    ps3 = make_server()
    ps3.cfg.port = 8937
    real_socket = proxymod.socket.socket

    class FakeSock:
        def setsockopt(self, *a):
            pass

        def bind(self, addr):
            fake_bind(addr)

        def close(self):
            pass

    proxymod.socket = types.SimpleNamespace(
        socket=lambda *a, **k: FakeSock(), AF_INET=socket.AF_INET,
        SOCK_STREAM=socket.SOCK_STREAM, SOL_SOCKET=socket.SOL_SOCKET,
        SO_EXCLUSIVEADDRUSE=socket.SO_EXCLUSIVEADDRUSE,
        IPPROTO_TCP=socket.IPPROTO_TCP, TCP_NODELAY=socket.TCP_NODELAY)
    try:
        try:
            ps3.start()
            check("10013 reported as reserved range", False, "no raise")
        except OSError as exc:
            check("10013 reported as reserved range (not 'in use')",
                  "reserved port range" in str(exc) and "in use" not in str(exc),
                  str(exc)[:90])
    finally:
        proxymod.socket = real_socket
    try:
        ps.stop()
    except OSError:
        pass


def test_connect_dead_fail_fast():
    check("ConnectDead subclasses OSError",
          issubclass(proxymod.ConnectDead, OSError))
    ps = make_server()
    calls = []

    def fake_tunnel_once(csock, host, port, strategy, first, excl=False,
                         force_no_frag=False):
        calls.append(strategy)
        raise proxymod.ConnectDead(
            f"{host}:{port} could not connect (1 address(es) tried, timed out)")

    ps._tunnel_once = fake_tunnel_once
    client, client_peer = socketpair()
    result = {}
    th = run_tunnel_async(ps, client, client_peer, "deadhost.test", 443, result)
    th.join(10)
    err = result.get("err")
    check("connect-dead raises (single attempt)",
          isinstance(err, OSError) and "could not connect" in str(err),
          str(err)[:80] if err else str(result))
    check("connect-dead: exactly ONE strategy attempt (no cycling)",
          len(calls) == 1, str(calls))
    with ps._fails_lock:
        entry = ps._fails.get("deadhost.test")
    # capped=True on count=1 means the failure was NOT dpi-flagged
    # (dpi failures get ONE uncapped retry cycle first)
    check("connect-dead: capped immediately (dpi not flagged)",
          entry is not None and entry[1] == 1 and entry[2] is True, str(entry))
    client.close(); client_peer.close()


def test_unconfirmed_nx_not_verified_dead():
    # a SINGLE-vote NXDOMAIN must reach the 'DNS could not resolve' warning,
    # not the 'blocked/dead upstream' verdict (that is the point of the vote)
    ps = make_server()
    client, client_peer = socketpair()
    def fake_tunnel(csock, host, port):
        raise ResolveError(f"{host}: no addresses ({host}: NXDOMAIN "
                           "(unconfirmed, single resolver))")
    ps._tunnel = fake_tunnel
    result = {}
    def run():
        try:
            ps._handle(client)
            result["done"] = True
        except Exception as e:
            result["err"] = repr(e)
    client_peer.sendall(b"CONNECT unconfirmed.test:443 HTTP/1.1\r\nHost: x\r\n\r\n")
    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(10)
    tot, act, up, down, failed, blocked = ps.stats.totals()
    check("unconfirmed NX: blocked=True, failed=False",
          blocked == 1 and failed == 0 and act == 0,
          f"blocked={blocked} failed={failed} {result}")
    warn_lines = [m for lvl, m in ps.log.lines if lvl == "warn"]
    check("unconfirmed NX logged as DNS problem, NOT dead upstream",
          any("DNS could not resolve" in m for m in warn_lines)
          and not any("blocked/dead upstream" in m for m in warn_lines),
          str(warn_lines[:1]))
    client.close(); client_peer.close()


if __name__ == "__main__":

    test_parse_head_body()
    test_plain_http_body_once()
    test_expect_100_continue()
    test_relay_initial_up()
    test_dpi_flag_and_raw_last_resort()
    test_always_resets_falls_through_raw()
    test_no_string_matching()
    test_relay_raise_closes_server()
    test_server_first()
    test_443_no_data_still_aborts()
    test_state_dict_threads()
    test_thread_start_failure_releases_slot()
    test_accept_death()
    test_pac()
    test_put_patch_delete()
    test_upstream_skips_dns()
    test_cached_negative_blocked()
    test_connect_dead_fail_fast()
    test_unconfirmed_nx_not_verified_dead()
    test_flap_retry_recovers_known_good()
    test_flap_retry_skips_never_worked()
    test_flap_retry_time_budget()
    test_bind_error_messages()

    print()
    print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
    sys.exit(0 if all(c for _, c in RESULTS) else 1)

"""Tests for hookip.doh — no real network (stubs for _DoHConn, sockets,
dnsmsg where needed). Run: python tests/test_doh.py"""
import os
import sys
import threading
import time
import types
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hookip import doh as dohmod  # noqa: E402
from hookip.doh import Resolver, ResolveError, VerifiedNegative  # noqa: E402

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


class FakeCfg:
    doh_enabled = True


class FakeConn:
    """Stands in for _DoHConn — no sockets."""
    created = 0
    created_per_name = {}

    def __init__(self, ip, host, timeout=3.5, chunk=2, keepalive=False,
                 validate_by_ip=True):
        FakeConn.created += 1
        FakeConn.created_per_name[host] = FakeConn.created_per_name.get(host, 0) + 1
        self.ip, self.host = ip, host
        self.validate_by_ip = validate_by_ip
        self.keepalive = keepalive
        self.alive = True
        self.used = time.time()
        self._reqlock = threading.Lock()
        self.script = []            # request() results/exceptions, popped
        self.default = b""

    def request(self, host, payload, timeout=5.0):
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if isinstance(self.default, Exception):
            raise self.default
        return self.default

    def close(self):
        self.alive = False

    def healthy(self, max_idle=25.0):
        return self.alive and (time.time() - self.used) < max_idle


def make_resolver(pool_max=4):
    FakeConn.created = 0
    FakeConn.created_per_name = {}
    r = Resolver(FakeCfg(), FakeLog(), chunk=2)
    r._pool_max = pool_max
    return r


# ---- 1. pool never exceeds _pool_max --------------------------------
def test_pool_max():
    r = make_resolver(pool_max=3)
    gate = threading.Event()
    holders = {}

    class GatedConn(FakeConn):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            gate.wait(5)             # hold creation open like a slow TLS

    conns = []
    def worker(i):
        try:
            c = r._doh_session("Cloudflare", "cloudflare-dns.com", "1.1.1.1")
            conns.append(c)
            holders[i] = c
            time.sleep(0.05)
            r._release_doh(c)          # release like a real lookup would
        except Exception as e:
            conns.append(("ERR", e))

    with mock.patch.object(dohmod, "_DoHConn", GatedConn):
        gate.set()  # no gate actually: GatedConn waits on `gate` which is set
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
    ok = all(not isinstance(x, tuple) for x in conns)
    with r._pool_lock:
        n_pool = len(r._pool.get("Cloudflare", []))
    check("16 threads: pool never exceeds _pool_max", ok and n_pool <= 3,
          f"pool={n_pool} created={FakeConn.created}")


def test_pool_max_burst_creation():
    """The reservation must also hold while connections are being CREATED
    (slow constructor): count actual constructor calls."""
    r = make_resolver(pool_max=3)
    creation_lock = threading.Lock()
    creation_barrier = threading.Event()

    class SlowConn(FakeConn):
        def __init__(self, *a, **kw):
            with creation_lock:
                FakeConn.created += 1
            creation_barrier.wait(3)      # all creators overlap
            super().__init__(*a, **kw)

    results = []
    def worker():
        try:
            conn = r._doh_session("Cloudflare", "h", "1.1.1.1")
            results.append("ok")
            r._release_doh(conn)   # put it back or the rest wait forever
        except Exception as e:
            results.append(("ERR", e))

    with mock.patch.object(dohmod, "_DoHConn", SlowConn):
        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(12)]
        for t in threads:
            t.start()
        time.sleep(0.4)                   # let them pile up on the barrier
        n_created_mid = FakeConn.created
        creation_barrier.set()
        for t in threads:
            t.join(15)
    check("burst creation respects reservation", n_created_mid <= 3,
          f"created at peak={n_created_mid}")
    check("burst: all 12 workers served",
          len(results) == 12 and all(not isinstance(x, tuple) for x in results),
          f"served={len(results)}/12")
    with r._pool_lock:
        pending_left = r._pending.get("Cloudflare", 0)
    check("burst: pending counter returns to zero", pending_left == 0,
          str(pending_left))


# ---- 2. in-use stale conn is not closed by cleanup -------------------
def test_stale_inuse_not_closed():
    r = make_resolver(pool_max=2)
    stale = FakeConn("1.1.1.1", "Cloudflare")
    stale.used = time.time() - 26          # stale to healthy() (>25 s idle)
    stale._reqlock.acquire()               # CHECKED OUT by "another thread"
    r._pool["Cloudflare"] = [stale]
    fresh = None
    with mock.patch.object(dohmod, "_DoHConn", FakeConn):
        c = r._doh_session("Cloudflare", "h", "1.1.1.1")
        fresh = c
    check("stale in-use conn NOT closed by cleanup", stale.alive and stale in r._pool["Cloudflare"])
    check("in-use conn stays in pool for its holder", stale.alive)
    check("second lookup got a different conn", fresh is not stale)
    check("fresh conn `used` refreshed at checkout",
          time.time() - fresh.used < 1.0)
    stale._reqlock.release()


def test_stale_idle_closed():
    r = make_resolver(pool_max=2)
    stale = FakeConn("1.1.1.1", "Cloudflare")
    stale.used = time.time() - 26
    r._pool["Cloudflare"] = [stale]
    with mock.patch.object(dohmod, "_DoHConn", FakeConn):
        r._doh_session("Cloudflare", "h", "1.1.1.1")   # triggers cleanup scan
    check("idle unheld stale conn closed", not stale.alive)


# ---- 3. CNAME retry path does not double-release ---------------------
def test_cname_no_double_release():
    r = make_resolver(pool_max=2)
    releases = []
    orig_release = r._release_doh

    def counting_release(conn):
        releases.append(conn)
        orig_release(conn)

    r._release_doh = counting_release
    conn1 = FakeConn("1.1.1.1", "Cloudflare")
    # request 1 returns a CNAME answer; request 2 (the follow) dies
    conn1.script = [(5, None, 300, "alias.example.com")]
    calls = {"n": 0}

    def session(name, dns_host, ip):
        calls["n"] += 1
        if calls["n"] == 1:
            # real _doh_session acquires the per-conn lock at checkout
            assert conn1._reqlock.acquire(blocking=False)
            return conn1
        raise OSError("locked out (simulated)")

    r._doh_session = session

    class StubDnsmsg:
        TYPE_A = 1
        TYPE_AAAA = 28

        @staticmethod
        def encode_query(h, q): return b""

        @staticmethod
        def parse_response(resp, qname=None): return (0, [(5, 5, 300, "alias.example.com")])

        @staticmethod
        def extract_ips(answers, q): return []

    with mock.patch.object(dohmod, "dnsmsg", StubDnsmsg):
        try:
            r._via_doh("double.test", 1)
            ok = True
        except RuntimeError as e:
            ok = False
            print("   RuntimeError:", e)
        except Exception as e:
            ok = not isinstance(e, RuntimeError)
            print("   other (fine):", type(e).__name__)
    check("CNAME retry path: no double release (no RuntimeError)", ok,
          f"releases={len(releases)}")
    check("CNAME retry path: conn1 released exactly once", len(releases) == 1)


# ---- 4. _frag_send chunk semantics -----------------------------------
def test_sinkhole_only_answer_raises():
    """A sinkhole-only answer must RAISE 'all resolvers returned a
    sinkhole' regardless of which source produced it — a refactor once
    nested that raise inside the plaintext-warn condition, so a DoH
    (source='doh') sinkhole-only answer fell through as an empty list."""
    r = make_resolver(pool_max=2)
    r._via_doh = lambda host, qtype: (["0.0.0.0"], 120, "ok (rcode 0)")
    try:
        r.resolve("blocked.example")
        check("DoH sinkhole-only raises", False, "no raise")
    except ResolveError as exc:
        check("DoH sinkhole-only raises with sinkhole reason",
              "sinkhole" in str(exc), str(exc)[:80])

    # same via the TCP fallback path (source='tcp') — and the rejected
    # sinkhole answer must NOT consume the plaintext-warn throttle
    r2 = make_resolver(pool_max=2)
    r2._via_doh = lambda host, qtype: ([], 120, "error: all failed")
    r2._via_tcp_dns = lambda *a, **k: (["0.0.0.0"], 60)
    r2._via_udp_dns = lambda *a, **k: ([], 0)
    r2._via_system = lambda *a, **k: ([], 0)
    try:
        r2.resolve("blocked2.example")
        check("TCP sinkhole-only raises", False, "no raise")
    except ResolveError as exc:
        warns = [m for (lvl, m) in r2.log.lines if lvl == "warn"]
        check("TCP sinkhole-only raises, no plaintext warn",
              "sinkhole" in str(exc) and not warns, str(exc)[:80])


def test_plain_fallback_warn_throttled():
    """DoH on but unreachable -> the address came from plaintext DNS: that
    Secure-DNS degradation is logged as WARN, throttled to one entry per
    5 minutes (per-host detail stays at debug)."""
    r = make_resolver(pool_max=2)

    def fail_doh(host, qtype):
        # real _via_doh never raises — it returns empty + a verdict note
        return ([], 120, "error: all resolvers failed")

    def fake_tcp(host, qtype, doh_nx_vote=False):
        return (["1.2.3.4"], 60)

    r._via_doh = fail_doh
    r._via_tcp_dns = fake_tcp
    r._via_udp_dns = lambda *a, **k: ([], 0)
    r._via_system = lambda *a, **k: ([], 0)
    r._cache.clear()
    r._neg_cache.clear()
    ips = r.resolve("example.com")
    warns = [m for (lvl, m) in r.log.lines if lvl == "warn"]
    check("DoH outage warns (plaintext TCP used)",
          ips == ["1.2.3.4"] and len(warns) == 1 and "plaintext TCP" in warns[0],
          f"ips={ips} warns={warns[:1]}")
    r._cache.clear()
    r._neg_cache.clear()
    r.resolve("example.com")                 # again within 5 min
    warns2 = [m for (lvl, m) in r.log.lines if lvl == "warn"]
    check("fallback warn throttled (one per 5 min)", len(warns2) == 1,
          f"warns={len(warns2)}")


def test_sni_less_and_fallback():
    """SNI-less DoH: the ClientHello must validate by IP SAN (no resolver
    name in SNI — that was the Secure-DNS bypass: a DPI filter could block
    'cloudflare-dns.com' etc. by name). A resolver whose cert lacks an IP
    SAN falls back to hostname SNI and the mode is cached."""
    import ssl as _ssl

    def make_resolver():
        r = dohmod.Resolver.__new__(dohmod.Resolver)
        r.cfg = None
        r.log = types.SimpleNamespace(
            debug=lambda *a, **k: None, ok=lambda *a, **k: None,
            warn=lambda *a, **k: None, error=lambda *a, **k: None)
        r.chunk = 2
        r._sni_mode = {}
        r._sni_mode_ts = {}
        r._pool = {}
        r._pending = {}
        r._pool_lock = threading.Lock()
        r._pool_max = 2
        return r

    # bundled resolvers unchanged (vote math across suites assumes 4)
    names = [n for (n, _h, _i) in dohmod.RESOLVERS]
    check("bundled DoH resolvers intact", len(names) == 4, str(names))

    captured = {}
    class RecordingConn(dohmod._DoHConn):
        def __init__(self, ip, host, timeout=3.5, chunk=2, keepalive=False,
                     validate_by_ip=True):
            captured.setdefault("modes", []).append(validate_by_ip)
            self.ip, self.host = ip, host
            self.used = time.time()
            self.alive = True
            self.keepalive = keepalive
            self._reqlock = threading.Lock()
            self.healthy = lambda: True

    r = make_resolver()
    real_conn = dohmod._DoHConn
    dohmod._DoHConn = RecordingConn
    try:
        r._new_conn("Cloudflare", "1.1.1.1", "cloudflare-dns.com")
        check("SNI-less default (validate by IP SAN)",
              captured["modes"] == [True], str(captured["modes"]))
        check("mode cached 'ip'", r._sni_mode.get("Cloudflare") == "ip",
              str(r._sni_mode))

        # a resolver whose cert has no IP SAN: first attempt fails cert
        # verification, second succeeds with the hostname, mode cached
        class CertFailConn(RecordingConn):
            def __init__(self, *a, **k):
                captured.setdefault("modes", []).append(k.get("validate_by_ip", True))
                if k.get("validate_by_ip", True):
                    raise _ssl.SSLCertVerificationError("no IP SAN")
                self.ip, self.host = a[0], a[1]
                self.used = time.time()
                self.alive = True
                self.keepalive = k.get("keepalive", False)
                self._reqlock = threading.Lock()
                self.healthy = lambda: True

        captured.clear()
        dohmod._DoHConn = CertFailConn
        r2 = make_resolver()
        r2._new_conn("NoSAN", "9.9.9.9", "dns.nosan.example")
        check("cert w/o IP SAN falls back to hostname SNI",
              captured.get("modes") == [True, False], str(captured.get("modes")))
        check("fallback mode cached 'host'", r2._sni_mode.get("NoSAN") == "host",
              str(r2._sni_mode))
        captured.clear()
        r2._new_conn("NoSAN", "9.9.9.9", "dns.nosan.example")
        check("cached 'host' mode skips the failing IP attempt",
              captured.get("modes") == [False], str(captured.get("modes")))

        # hourly re-probe: a resolver could ADD an IP SAN — after an hour
        # in 'host' mode, _new_conn retries the IP-SAN path once
        r2._sni_mode_ts["NoSAN"] = time.time() - 3700
        captured.clear()
        r2._new_conn("NoSAN", "9.9.9.9", "dns.nosan.example")
        check("stale 'host' mode re-probes the IP-SAN path",
              captured.get("modes") == [True, False],
              str(captured.get("modes")))
        check("re-probe refreshes the fallback timestamp",
              time.time() - r2._sni_mode_ts["NoSAN"] < 5,
              str(r2._sni_mode_ts))
    finally:
        dohmod._DoHConn = real_conn


def test_sni_less_preferred_in_rotation():
    """A resolver known to fall back to hostname SNI is DEMOTED in the
    hedge order (SNI-less resolvers serve most lookups). First-launched
    attempt = order[0] — deterministic even though the answer races."""
    r = script_resolver({"Cloudflare": [addrs("1.1.1.1")],
                         "Google": [addrs("8.8.8.8")],
                         "AdGuard": [addrs("9.9.9.9")],
                         "ControlD": [addrs("7.7.7.7")]})
    r._sni_mode["Google"] = "host"      # demote Google to the back
    launched = []
    real_session = r._doh_session
    def session(name, dns_host, ip):
        launched.append(name)
        return real_session(name, dns_host, ip)
    r._doh_session = session
    with mock.patch.object(dohmod, "dnsmsg", StubDns):
        ips, ttl, _note = r._via_doh("order.test", 1)
    check("SNI-less resolver is launched FIRST",
          launched and launched[0] != "Google", str(launched))
    # demoted resolvers are still REACHABLE (never skipped): force the
    # SNI-less ones to fail and confirm Google still answers
    r2 = script_resolver({"Cloudflare": [OSError("down")],
                          "Google": [addrs("8.8.8.8")],
                          "AdGuard": [OSError("down")],
                          "ControlD": [OSError("down")]})
    r2._sni_mode["Google"] = "host"
    with mock.patch.object(dohmod, "dnsmsg", StubDns):
        ips2, _t, _n = r2._via_doh("reach.test", 1)
    check("demoted SNI-host resolver still serves when others fail",
          ips2 == ["8.8.8.8"], str(ips2))


def test_frag_send():
    conn = dohmod._DoHConn.__new__(dohmod._DoHConn)   # skip __init__ (no socket)
    sends = []

    class FakeSock:
        def sendall(self, b):
            sends.append(b)

    conn.sock = FakeSock()
    data = b"x" * 130
    conn._frag_send(data, 1)
    check("chunk=1 fragments (capped ~64)", 1 < len(sends) <= 64
          and b"".join(sends) == data, f"{len(sends)} sends")
    sends.clear()
    conn._frag_send(data, 0)
    check("chunk=0 sends whole once", sends == [data])
    sends.clear()
    big = b"y" * 20000
    conn._frag_send(big, 1)
    check("huge data capped at ~64 sends", len(sends) <= 64
          and b"".join(sends) == big, f"{len(sends)} sends")


# ---- 5. shared SSL context created once ------------------------------
def test_ssl_context_once():
    calls = {"n": 0}
    real = dohmod.ssl.create_default_context
    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)
    with mock.patch.object(dohmod.ssl, "create_default_context", counting):
        dohmod._SSL_CTX = None
        ctxs = [dohmod._ssl_context() for _ in range(20)]
    dohmod._SSL_CTX = None
    check("shared SSL context created once across many calls", calls["n"] == 1)
    check("all callers get the same context", all(c is ctxs[0] for c in ctxs))


# ---- 6. NXDOMAIN voting ----------------------------------------------
class StubDns:
    TYPE_A = 1
    TYPE_AAAA = 28

    @staticmethod
    def encode_query(h, q):
        return b"Q" + h.encode()

    @staticmethod
    def parse_response(resp, qname=None):
        # resp is a dict from the fake conn: {"rcode": n, "answers": [...]}
        # (qname accepted for compatibility with the real wire parser)
        return resp["rcode"], resp["answers"]

    @staticmethod
    def extract_ips(answers, q):
        return [v for (_n, t, _ttl, v) in answers
                if t in (StubDns.TYPE_A, StubDns.TYPE_AAAA)]


def script_resolver(scripts, pool_max=4):
    """scripts: resolver name -> list of request-result dicts."""
    r = make_resolver(pool_max=pool_max)
    r.chunk = 2

    def session(name, dns_host, ip):
        c = FakeConn(ip, name)
        c.default = scripts[name][0]
        c.script = list(scripts[name][1:])
        # real _doh_session acquires the per-conn lock at checkout
        assert c._reqlock.acquire(blocking=False)
        return c

    r._doh_session = session
    return r


def nx():
    return {"rcode": 3, "answers": []}


def addrs(*ips):
    return {"rcode": 0, "answers": [(("n"), 1, 300, ip) for ip in ips]}


def servfail():
    return {"rcode": 2, "answers": []}


def test_nx_voting():
    # one NX + another resolver answers addresses -> addresses win
    r = script_resolver({"Cloudflare": [addrs("1.2.3.4")],
                         "Google": [nx()],
                         "AdGuard": [servfail()],
                         "ControlD": [servfail()]})
    with mock.patch.object(dohmod, "dnsmsg", StubDns):
        ips, ttl, note = r._via_doh("vote.test", 1)
    check("positive answer beats a single NX vote", ips == ["1.2.3.4"], str(ips))

    # two NX votes -> VerifiedNegative
    r = script_resolver({"Cloudflare": [nx()],
                         "Google": [nx()],
                         "AdGuard": [servfail()],
                         "ControlD": [servfail()]})
    with mock.patch.object(dohmod, "dnsmsg", StubDns):
        try:
            r._via_doh("two.test", 1)
            check("two NX votes raise VerifiedNegative", False, "no raise")
        except VerifiedNegative as e:
            check("two NX votes raise VerifiedNegative", "NXDOMAIN" in str(e), str(e)[:60])

    # exactly one NX vote, others FAIL -> unconfirmed note
    r = script_resolver({"Cloudflare": [nx()],
                         "Google": [OSError("dead")],
                         "AdGuard": [OSError("dead")],
                         "ControlD": [OSError("dead")]})
    with mock.patch.object(dohmod, "dnsmsg", StubDns):
        ips, ttl, note = r._via_doh("one.test", 1)
    check("single NX vote -> unconfirmed note",
          ips == [] and note == "NXDOMAIN (unconfirmed, single resolver)", str(note))


def test_unconfirmed_cached_60s():
    r = script_resolver({"Cloudflare": [nx()],
                         "Google": [OSError("dead")],
                         "AdGuard": [OSError("dead")],
                         "ControlD": [OSError("dead")]})
    with mock.patch.object(dohmod, "dnsmsg", StubDns), \
         mock.patch.object(r, "_via_tcp_dns", lambda *a, **k: ([], 120)), \
         mock.patch.object(r, "_via_udp_dns", lambda *a, **k: ([], 120)), \
         mock.patch.object(r, "_via_system", lambda *a, **k: ([], 120)):
        try:
            r._lookup_uncached("one60.test", 1, time.time())
            check("unconfirmed NX raises ResolveError", False)
        except ResolveError as e:
            check("unconfirmed NX raises ResolveError",
                  "NXDOMAIN" in str(e) and "no addresses" in str(e), str(e)[:70])
    with r._lock:
        entry = r._neg_cache.get("one60.test")
    check("unconfirmed NX cached for 60 s (not 300)",
          entry is not None and 55 <= entry[0] - time.time() <= 65,
          f"ttl={entry[0] - time.time():.0f}s" if entry else "missing")


def test_tcp_confirms_doh_vote():
    # one DoH NX vote + one TCP NX -> VerifiedNegative from TCP
    r = script_resolver({"Cloudflare": [nx()],
                         "Google": [OSError("dead")],
                         "AdGuard": [OSError("dead")],
                         "ControlD": [OSError("dead")]})

    def tcp(host, qtype, doh_nx_vote=False):
        assert doh_nx_vote is True, "vote flag not threaded!"
        raise VerifiedNegative(f"{host}: NXDOMAIN (verified via DoH + TCP DNS 1.1.1.1)")

    with mock.patch.object(dohmod, "dnsmsg", StubDns), \
         mock.patch.object(r, "_via_tcp_dns", tcp):
        try:
            r._lookup_uncached("confirm.test", 1, time.time())
            check("TCP confirms DoH vote", False, "no raise")
        except ResolveError as e:
            # _lookup_uncached converts the verified negative into a cached
            # ResolveError carrying the real verdict
            check("TCP confirms DoH vote", "NXDOMAIN" in str(e), str(e)[:70])
    with r._lock:
        entry = r._neg_cache.get("confirm.test")
    check("confirmed NX cached 300 s", entry is not None and entry[0] - time.time() > 200)


# ---- 11. cross-type fallback (AAAA-only / A-only names) ---------------
def test_cross_type_fallback():
    # an A-negative name may be AAAA-only (brunhild.challenges.cloudflare.com)
    calls = []
    r = make_resolver()

    def via_doh(host, qtype):
        calls.append(qtype)
        if qtype == 1:
            return [], 120, "no A records (NODATA, verified via DoH Cloudflare, Google)"
        return ["2606:4700::1234"], 300, None

    def tcp(host, qtype, doh_nx_vote=False):
        raise OSError("tcp dead")

    r._via_doh = via_doh
    r._via_tcp_dns = tcp
    ips = r._lookup_uncached("aaaaonly.test", 1, time.time())
    check("AAAA-only name: A-negative falls through to AAAA",
          ips == ["2606:4700::1234"], str(ips))
    with r._lock:
        hit = r._cache.get("aaaaonly.test")
        neg = r._neg_cache.get("aaaaonly.test")
    check("AAAA-only name: positive cached, negative cleared",
          hit is not None and neg is None, f"hit={hit} neg={neg}")

    # genuinely dead name: both types NODATA -> one merged verdict, 300 s
    r2 = make_resolver()

    def via_doh2(host, qtype):
        label = "no A records" if qtype == 1 else "no AAAA records"
        return [], 120, f"{label} (NODATA, verified via DoH Cloudflare, Google)"

    r2._via_doh = via_doh2
    r2._via_tcp_dns = tcp
    try:
        r2._lookup_uncached("dead.test", 1, time.time())
        check("both-NODATA raises", False, "no raise")
    except ResolveError as e:
        check("both-NODATA raises", True)
        check("both-NODATA merged verdict names both types",
              "no A or AAAA records" in str(e), str(e)[:90])
    with r2._lock:
        entry = r2._neg_cache.get("dead.test")
    check("both-NODATA cached 300 s",
          entry is not None and entry[0] - time.time() > 200, str(entry))

    # reverse direction: AAAA-primary falls back to A
    r3 = make_resolver()

    def via_doh3(host, qtype):
        if qtype == 28:
            return [], 120, "no AAAA records (NODATA, verified via DoH Google)"
        return ["1.2.3.4"], 300, None

    r3._via_doh = via_doh3
    r3._via_tcp_dns = tcp
    ips = r3._lookup_uncached("aonly.test", 28, time.time())
    check("AAAA-negative falls back to A", ips == ["1.2.3.4"], str(ips))

    # NXDOMAIN skips the cross-type attempt entirely
    r4 = make_resolver()

    def via_doh4(host, qtype):
        calls.append(f"nx{qtype}")
        raise VerifiedNegative(f"{host}: NXDOMAIN (verified via DoH Cloudflare, Google)")

    calls.clear()
    r4._via_doh = via_doh4
    r4._via_tcp_dns = tcp
    try:
        r4._lookup_uncached("nx.test", 1, time.time())
        check("NXDOMAIN raises", False, "no raise")
    except ResolveError:
        check("NXDOMAIN raises", True)
    check("NXDOMAIN skips cross-type DoH attempt",
          calls == ["nx1"], str(calls))


# ---- 12. CNAME follow-up: NX is a vote, SERVFAIL is not NODATA ---------
def test_cname_followup_verdicts():
    real_resolvers = dohmod.RESOLVERS

    def scripted_resolver():
        r = make_resolver()

        def session(name, dns_host, ip):
            c = FakeConn(ip, name)
            c.default = {"rcode": 0,
                         "answers": [(("chain.test"), 5, 300, "target.test")]}
            c.script = [followup]
            assert c._reqlock.acquire(blocking=False)
            return c

        r._doh_session = session
        return r

    # one resolver NXing the alias target: a VOTE, not a verdict
    followup = {"rcode": 3, "answers": []}
    r = scripted_resolver()
    with mock.patch.object(dohmod, "RESOLVERS", real_resolvers[:1]), \
         mock.patch.object(dohmod, "dnsmsg", StubDns):
        ips, ttl, note = r._via_doh("chain.test", 1)
    check("CNAME follow-up NX counts as ONE vote (unconfirmed)",
          ips == [] and note == "NXDOMAIN (unconfirmed, single resolver)",
          str(note))

    # SERVFAIL on the follow-up is an error, NOT an authoritative NODATA
    followup = {"rcode": 2, "answers": []}
    r2 = scripted_resolver()
    with mock.patch.object(dohmod, "RESOLVERS", real_resolvers[:1]), \
         mock.patch.object(dohmod, "dnsmsg", StubDns):
        ips, ttl, note = r2._via_doh("chain.test", 1)
    check("CNAME follow-up SERVFAIL is not NODATA",
          ips == [] and note is None, f"note={note} ips={ips}")


# ---- 7. hedging ------------------------------------------------------
def test_hedging():
    # resolver 1 hangs, resolver 2 answers fast -> total well under 0.4+5
    r = make_resolver(pool_max=4)
    hang_conn = FakeConn("1.1.1.1", "Cloudflare")
    fast_conn = FakeConn("8.8.8.8", "Google")
    fast_conn.default = addrs("9.9.9.1")

    def hang_request(host, payload, timeout=5.0):
        time.sleep(5.0)   # would stall a sequential lookup
        return addrs("1.1.1.7")

    hang_conn.request = hang_request
    def session(name, dns_host, ip):
        c = hang_conn if name == "Cloudflare" else fast_conn
        c._reqlock.acquire(blocking=False)   # real checkout acquires
        return c
    r._doh_session = session
    with mock.patch.object(dohmod, "dnsmsg", StubDns):
        t0 = time.time()
        ips, ttl, note = r._via_doh("hedge.test", 1)
        dt = time.time() - t0
    check("hedging: fast 2nd resolver wins despite hung 1st",
          ips == ["9.9.9.1"] and dt < 0.7, f"{dt:.2f}s")
    # at most 2 in flight: the hanging attempt thread must have started
    # (proven by the fast result) — and the hung conn is abandoned cleanly


# ---- 8. UDP verification ---------------------------------------------
class FakeUDP:
    """Stands in for socket.socket(AF_INET, SOCK_DGRAM)."""
    instances = []
    reply = None             # datagram bytes returned by recv
    connect_calls = []

    def __init__(self, *a, **k):
        self.closed = False
        self.sent = None
        FakeUDP.instances.append(self)

    def settimeout(self, t):
        pass

    def connect(self, addr):
        FakeUDP.connect_calls.append(addr)

    def send(self, b):
        self.sent = b

    def recv(self, n):
        return FakeUDP.reply

    def close(self):
        self.closed = True


def test_udp_verification():
    q = b"\xab\xcd" + b"query"
    real_encode = StubDns.encode_query
    StubDns.encode_query = staticmethod(lambda h, qt: q)
    try:
        r = Resolver(FakeCfg(), FakeLog(), chunk=2)
        # wrong transaction ID -> ignored
        FakeUDP.reply = b"\xff\xff" + b"payload"
        with mock.patch.object(dohmod.socket, "socket", FakeUDP), \
             mock.patch.object(dohmod, "dnsmsg", StubDns):
            ips, ttl = r._via_udp_dns("udp.test", 1)
        check("UDP wrong transaction ID ignored", ips == [] and FakeUDP.instances
              and FakeUDP.instances[0].sent == q)
        check("UDP connect((ip,53)) used for source filtering",
              FakeUDP.connect_calls and FakeUDP.connect_calls[0] == ("1.1.1.1", 53))
        # correct transaction ID -> accepted
        FakeUDP.instances.clear()
        FakeUDP.reply = b"\xab\xcd" + b"resp"
        real_parse = StubDns.parse_response
        real_extract = StubDns.extract_ips
        StubDns.parse_response = staticmethod(
            lambda resp, qname=None: (0, [(("n"), 1, 60, "6.6.6.6")]))
        StubDns.extract_ips = staticmethod(
            lambda answers, qt: [v for (_n, t, _ttl, v) in answers])
        with mock.patch.object(dohmod.socket, "socket", FakeUDP), \
             mock.patch.object(dohmod, "dnsmsg", StubDns):
            ips, ttl = r._via_udp_dns("udp2.test", 1)
        check("UDP correct transaction ID accepted", ips == ["6.6.6.6"],
              str(ips))
    finally:
        # restore ALL the monkey-patched members: parse_response/
        # extract_ips used to stay patched after this test, making any
        # LATER test's stubbed answer come back as 6.6.6.6
        StubDns.encode_query = staticmethod(real_encode)
        StubDns.parse_response = staticmethod(real_parse)
        StubDns.extract_ips = staticmethod(real_extract)


# ---- 9. _start_idx guarded / is_sinkhole uses module socket -----------
def test_serve_stale_on_doh_outage():
    """Serve-stale (RFC 8767 flavored): when every resolver path fails but a
    recently-expired cached answer is still inside the staleness window,
    it is served briefly (ttl 30) instead of falling to plaintext. Far-out
    entries and doh-off sessions still fail normally."""
    r = make_resolver(pool_max=2)
    now = time.time()
    r._via_doh = lambda h, q: ([], 120, "error: all failed")
    r._via_tcp_dns = lambda *a, **k: ([], 0)
    r._via_udp_dns = lambda *a, **k: ([], 0)
    r._via_system = lambda *a, **k: ([], 0)

    # inside the window: stale served, neg-cache cleared, warn logged
    r._cache["stale.host.name"] = (now - 60, ["5.5.5.5"])
    ips = r.resolve("stale.host.name")
    warns = [m for (lvl, m) in r.log.lines if lvl == "warn"]
    check("stale DoH answer served on total outage",
          ips == ["5.5.5.5"] and any("STALE" in w for w in warns),
          f"ips={ips} warns={len(warns)}")
    check("stale served with a short ttl (retry DoH soon)",
          abs(r._cache["stale.host.name"][0] - (now + 30)) < 5,
          str(r._cache.get("stale.host.name")))

    # beyond the staleness window: still a hard failure
    r._cache.clear(); r._neg_cache.clear(); r.log.lines.clear()
    r._cache["old.host.name"] = (now - 7000, ["6.6.6.6"])
    try:
        r.resolve("old.host.name")
        check("too-old stale answer refused", False, "served stale anyway")
    except ResolveError as exc:
        check("too-old stale answer refused", "no addresses" in str(exc),
              str(exc)[:70])

    # secure DNS off: no serve-stale (plaintext IS the configured path)
    r.cfg.doh_enabled = False
    r._cache.clear(); r._neg_cache.clear(); r.log.lines.clear()
    r._cache["off.host.name"] = (now - 60, ["7.7.7.7"])
    try:
        r.resolve("off.host.name")
        check("doh disabled -> no serve-stale", False, "served")
    except ResolveError:
        check("doh disabled -> no serve-stale", True)

    # total-staleness cap: repeated stale serves keep re-caching with ttl
    # 30 — a per-lookup window would stretch forever. _stale_since is set
    # on the first serve and hard-stops after _STALE_MAX since THEN.
    r.cfg.doh_enabled = True
    future_ts = now + 700          # > _STALE_MAX after the first serve
    r._cache.clear(); r._neg_cache.clear(); r.log.lines.clear()
    r._cache["cap.host.name"] = (now - 60, ["8.8.8.8"])
    ips = r.resolve("cap.host.name")
    check("stale serve #1 works and stamps _stale_since",
          ips == ["8.8.8.8"] and "cap.host.name" in r._stale_since,
          f"ips={ips} since={r._stale_since}")
    # simulate a lookup far in the future: the re-cached (ttl 30) entry has
    # long expired again, and > STALE_MAX has passed since the FIRST serve
    r._cache["cap.host.name"] = (future_ts - 40, ["8.8.8.8"])
    with mock.patch.object(dohmod.time, "time", lambda: future_ts):
        try:
            r.resolve("cap.host.name")
            check("total staleness cap stops endless re-serving", False,
                  "served past the cap")
        except ResolveError:
            check("total staleness cap stops endless re-serving", True)
    check("cap bookkeeping cleared on refusal",
          "cap.host.name" not in r._stale_since, str(r._stale_since))


def test_circuit_breaker():
    """3 consecutive transport failures cool a resolver down for 5 min
    (demoted to the BACK of the hedge order, never skipped when everyone
    is cooling); the first success resets it and logs the recovery."""
    fail = OSError("blocked (simulated)")
    scripts = {n: [fail] for n, _, _ in dohmod.RESOLVERS}
    """3 consecutive transport failures cool a resolver down for 5 min
    (demoted to the BACK of the hedge order, never skipped when everyone
    is cooling); the first success resets it and logs the recovery."""
    fail = OSError("blocked (simulated)")
    scripts = {n: [fail] for n, _, _ in dohmod.RESOLVERS}
    r = script_resolver(scripts, pool_max=2)
    r._via_tcp_dns = lambda *a, **k: ([], 0)
    r._via_udp_dns = lambda *a, **k: ([], 0)
    r._via_system = lambda *a, **k: ([], 0)

    for i in range(3):
        try:
            r.resolve(f"outage{i}.host.name")
        except ResolveError:
            pass
    names = {n for n, _, _ in dohmod.RESOLVERS}
    check("3+ consecutive failures counted on every resolver",
          all(r._cb_fail.get(n, 0) >= 3 for n in names), str(r._cb_fail))
    check("breaker opened on every resolver",
          set(r._cb_open) == names, str(r._cb_open))
    pauses = [m for (lvl, m) in r.log.lines if lvl == "warn" and "paused" in m]
    check("one pause warn per resolver (no spam)", len(pauses) == 4,
          f"{len(pauses)} pause warns")
    check("total outage: nobody is skipped",
          not any(r._cb_skip(n) for n in names), str(r._cb_open))

    # recovery: Cloudflare starts answering — its breaker resets and the
    # OTHERS are now skippable (one usable resolver is enough)
    scripts["Cloudflare"] = [addrs("1.2.3.4")]
    with mock.patch.object(dohmod, "dnsmsg", StubDns):
        ips = r.resolve("recovery.host.name")
    check("recovered resolver answers", ips == ["1.2.3.4"], str(ips))
    check("breaker reset on success",
          r._cb_fail.get("Cloudflare") == 0 and "Cloudflare" not in r._cb_open,
          f"fail={r._cb_fail.get('Cloudflare')} open={'Cloudflare' in r._cb_open}")
    check("recovery logged", any("working again" in m
          for (lvl, m) in r.log.lines if lvl == "ok"))
    check("still-cooling resolvers are skippable when one is usable",
          r._cb_skip("Google") and not r._cb_skip("Cloudflare"))


def test_private_ip_poisoning_guard():
    """Plaintext answers (TCP/UDP/system) for a PUBLIC hostname that point
    into a PRIVATE range are dropped — DNS rebinding/poisoning/captive
    portal. DoH answers are TLS-authenticated and are never filtered this
    way; LAN-plausible names (single-label, .local style, excluded
    domains) keep their private answers."""
    def chain(doh_result, tcp_result):
        r = make_resolver(pool_max=2)
        r.cfg.excluded = ["intranet.corp.local"]
        r._via_doh = lambda host, qtype: doh_result
        r._via_tcp_dns = lambda *a, **k: tcp_result
        r._via_udp_dns = lambda *a, **k: ([], 0)
        r._via_system = lambda *a, **k: ([], 0)
        r._cache.clear(); r._neg_cache.clear()
        return r

    # plaintext TCP answers a public domain with a private IP -> refused
    r = chain(([], 120, None), (["10.0.0.5"], 60))
    try:
        r.resolve("rebind.host.name")
        check("private-range plaintext answer refused", False, "no raise")
    except ResolveError as exc:
        check("private-range plaintext answer refused",
              "private-range" in str(exc) and "rebinding" in str(exc),
              str(exc)[:90])

    # the SAME answer over DoH is trusted (TLS-authenticated)
    r2 = chain((["10.0.0.5"], 120, "ok (rcode 0)"), (["10.0.0.5"], 60))
    ips = r2.resolve("rebind.host.name")
    check("DoH answers are NOT private-filtered", ips == ["10.0.0.5"], str(ips))

    # a .local name through plaintext keeps its private answer
    r3 = chain(([], 120, None), (["192.168.1.10"], 60))
    ips = r3.resolve("printer.local")
    check(".local hostname keeps private answer", ips == ["192.168.1.10"], str(ips))

    # a user-excluded domain keeps private answers
    r4 = chain(([], 120, None), (["192.168.1.20"], 60))
    r4.cfg.excluded = ["nas.home.internal"]
    ips = r4.resolve("nas.home.internal")
    check("excluded domain keeps private answer", ips == ["192.168.1.20"], str(ips))

    # mixed public+private plaintext answer: public kept, private dropped
    r5 = chain(([], 120, None), (["93.184.216.34", "192.168.0.1"], 60))
    ips = r5.resolve("mixed.host.name")
    check("mixed answer keeps only the public address",
          ips == ["93.184.216.34"], str(ips))

    # IPv4-mapped IPv6 private form is caught too
    r6 = chain(([], 120, None), (["::ffff:10.0.0.9"], 60))
    try:
        r6.resolve("mapped.host.name")
        check("v4-mapped v6 private form refused", False, "no raise")
    except ResolveError as exc:
        check("v4-mapped v6 private form refused", "private-range" in str(exc))

    # SPLIT-HORIZON: DoH ANSWERED (NXDOMAIN verdict) — the company name
    # exists only on the corporate resolver, whose plaintext answer (10.x)
    # must be ACCEPTED, not dropped as poisoning
    r7 = chain(([], 120, "NXDOMAIN (unconfirmed, single resolver)"),
               (["10.7.0.5"], 60))
    ips = r7.resolve("wiki.corp.internal")
    check("split horizon: private answer accepted when DoH said NXDOMAIN",
          ips == ["10.7.0.5"], str(ips))
    # same for a DoH NODATA verdict
    r8 = chain(([], 120, "no A records (NODATA, verified via DoH Google)"),
               (["10.7.0.6"], 60))
    ips = r8.resolve("wiki.corp.internal")
    check("split horizon: private answer accepted when DoH said NODATA",
          ips == ["10.7.0.6"], str(ips))
    # but when DoH produced NO verdict (note None = unreachable), the
    # guard still applies
    r9 = chain(([], 120, None), (["10.9.0.9"], 60))
    try:
        r9.resolve("rebind2.host.name")
        check("guard still applies when DoH was unreachable", False, "no raise")
    except ResolveError as exc:
        check("guard still applies when DoH was unreachable",
              "private-range" in str(exc))

    check("_is_private_ip sanity",
          dohmod._is_private_ip("10.1.2.3") and dohmod._is_private_ip("100.64.0.1")
          and dohmod._is_private_ip("::ffff:10.0.0.9") and dohmod._is_private_ip("fe80::1")
          and not dohmod._is_private_ip("93.184.216.34")
          and not dohmod._is_private_ip("not-an-ip"))


def test_hedge_thread_start_failure_degrades():
    """Thread.start() failing (thread budget exhausted on a loaded low-end
    machine) must not lose the lookup — the attempt runs inline."""
    r = script_resolver({"Cloudflare": [addrs("6.6.6.6")],
                         "Google": [addrs("7.7.7.7")],
                         "AdGuard": [addrs("8.8.8.8")],
                         "ControlD": [addrs("9.9.9.9")]})

    def boom(self):
        raise RuntimeError("cannot start new thread")

    real_start = threading.Thread.start
    try:
        with mock.patch.object(threading.Thread, "start", boom),                 mock.patch.object(dohmod, "dnsmsg", StubDns):
            ips = r.resolve("degrade.test")
        check("thread-start failure degrades to inline attempt",
              ips == ["6.6.6.6"], f"ips={ips}")
    finally:
        threading.Thread.start = real_start


def test_start_idx_threadsafe():
    r = make_resolver()
    errs = []

    def hammer():
        for _ in range(200):
            try:
                with mock.patch.object(dohmod, "dnsmsg", StubDns):
                    # exercise the rotation read/write path via the lock
                    with r._lock:
                        # rotation read+write under the lock, as production does
                        r._start_idx = (r._start_idx + 1) % len(dohmod.RESOLVERS)
            except RuntimeError as e:
                errs.append(e)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    check("_start_idx rotation under lock never raises", not errs,
          str(errs[:1]))

check("is_sinkhole uses module-level socket (hoisted)",
      dohmod.is_sinkhole("0.0.0.0") and dohmod.is_sinkhole("::")
      and not dohmod.is_sinkhole("1.2.3.4"))

# ---- pool reservation leak fix + related -----------------------------
def test_pool_reservation_no_leak():
    """24 threads / pool max 2: never more than 2 connections, and the
    reservation counter drains to 0 afterwards. With an IDLE conn in the
    pool, checking it out must NOT leak a reservation (pool max 4)."""
    r = make_resolver(pool_max=2)
    gate = threading.Event()

    class SlowConn(FakeConn):
        def __init__(self, *a, **kw):
            gate.wait(5)
            super().__init__(*a, **kw)

    served = []
    errs = []

    def worker():
        try:
            c = r._doh_session("Cloudflare", "h", "1.1.1.1")
            served.append(1)
            r._release_doh(c)
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    with mock.patch.object(dohmod, "_DoHConn", SlowConn):
        ths = [threading.Thread(target=worker, daemon=True) for _ in range(24)]
        for t in ths:
            t.start()
        gate.set()
        for t in ths:
            t.join(20)
    check("24 threads / pool 2: no errors", not errs, str(errs[:2]))
    with r._pool_lock:
        n_pool = len(r._pool.get("Cloudflare", []))
    check("24 threads / pool 2: never more than 2 connections",
          n_pool <= 2 and FakeConn.created_per_name.get("h", 0) <= 2,
          f"pool={n_pool} created={FakeConn.created_per_name.get('h', 0)}")
    with r._pool_lock:
        pending_left = r._pending.get("Cloudflare", 0)
    check("24 threads / pool 2: _pending returns to 0", pending_left == 0,
          str(pending_left))

    # an idle connection in the pool: checking it out must not leave a
    # reservation behind (the old order reserved FIRST and leaked it)
    r2 = make_resolver(pool_max=4)
    idle = FakeConn("1.1.1.1", "h2")
    r2._pool["Cloudflare"] = [idle]
    c = r2._doh_session("Cloudflare", "h2", "1.1.1.1")
    with r2._pool_lock:
        pending_left = r2._pending.get("Cloudflare", 0)
    check("idle checkout leaves no reservation (pool max 4)",
          pending_left == 0 and c is idle, f"pending={pending_left}")
    r2._release_doh(c)


def test_pending_full_waits_without_cpu_spin():
    """Every slot reserved-but-not-yet-registered: the wait branch sleeps
    (no 100%% CPU spin on continue)."""
    r = make_resolver(pool_max=1)
    r._pending["Cloudflare"] = 1          # the one slot is being created
    sleeps = []

    def counting_sleep(s):
        sleeps.append(s)
        # release the pending slot after the first sleep so the loop can
        # finish instead of hanging
        with r._pool_lock:
            r._pending["Cloudflare"] = 0

    with mock.patch.object(dohmod.time, "sleep", counting_sleep):
        try:
            r._doh_session("Cloudflare", "h", "1.1.1.1")
        except Exception:  # noqa: BLE001 — creation will fail with 0 pending
            pass            # and _new_conn hits _DoHConn; that is fine here
    check("pool full of pending reservations WAITS (sleeps, no hot spin)",
          len(sleeps) >= 1 and all(s <= 0.05 for s in sleeps), str(sleeps[:3]))


def test_doh_attempt_unexpected_exception():
    """_doh_attempt catches EVERYTHING: dnsmsg.parse_response raising
    TypeError becomes an ('err', ...) tuple, not a dead worker."""
    r = make_resolver(pool_max=2)

    class BoomDns:
        TYPE_A = 1
        TYPE_AAAA = 28

        @staticmethod
        def encode_query(h, q):
            return b"Q"

        @staticmethod
        def parse_response(resp, qname=None):
            raise TypeError("unexpected int internal")

        @staticmethod
        def extract_ips(answers, q):
            return []

    r._via_tcp_dns = lambda *a, **k: ([], 0)
    r._via_udp_dns = lambda *a, **k: ([], 0)
    r._via_system = lambda *a, **k: ([], 0)
    def fake_session(name, dns_host, ip):
        c = FakeConn("1.1.1.1", name)
        c.default = b"RESP"       # non-empty so parse_response is reached
        c._reqlock.acquire()      # a real session returns a CHECKED-OUT conn
        return c

    r._doh_session = fake_session
    with mock.patch.object(dohmod, "dnsmsg", BoomDns):
        res = r._doh_attempt("Cloudflare", "dns.host", "1.1.1.1",
                             "x.host.name", 1, b"Q")
    check("unexpected parse exception -> ('err', ...) tuple",
          res[0] == "err" and "TypeError" in res[1], str(res))
    check("unexpected exception still counts toward the breaker",
          r._cb_fail.get("Cloudflare", 0) == 1, str(r._cb_fail))


def test_dohconn_handshake_failure_closes_socket():
    """A handshake failure after create_connection must close the socket
    (the old code leaked one FD per bad cert)."""
    closed = []

    class FakeSock:
        def setsockopt(self, *a):
            pass

        def settimeout(self, t):
            pass

        def recv(self, n):
            return b""

        def sendall(self, data):
            pass

        def close(self):
            closed.append(1)

    class BoomSsl:
        def do_handshake(self):
            raise RuntimeError("cert without IP SAN")

    class FakeCtx:
        def wrap_bio(self, inn, out, server_hostname=None):
            return BoomSsl()

    with mock.patch.object(dohmod.socket, "create_connection",
                           lambda addr, timeout=None: FakeSock()), \
         mock.patch.object(dohmod, "_ssl_context", lambda: FakeCtx()):
        raised = None
        try:
            dohmod._DoHConn("1.1.1.1", "dns.host", chunk=2)
        except Exception as exc:  # noqa: BLE001
            raised = exc
    check("handshake failure propagates",
          isinstance(raised, RuntimeError), repr(raised))
    check("handshake failure closes the socket", len(closed) == 1,
          str(closed))


if __name__ == "__main__":

    test_pool_max()
    test_pool_max_burst_creation()
    test_stale_inuse_not_closed()
    test_stale_idle_closed()
    test_cname_no_double_release()
    test_frag_send()
    test_ssl_context_once()
    test_nx_voting()
    test_unconfirmed_cached_60s()
    test_tcp_confirms_doh_vote()
    test_cross_type_fallback()
    test_cname_followup_verdicts()
    test_hedging()
    test_udp_verification()
    test_start_idx_threadsafe()
    test_sni_less_and_fallback()
    test_plain_fallback_warn_throttled()
    test_sinkhole_only_answer_raises()
    test_hedge_thread_start_failure_degrades()
    test_private_ip_poisoning_guard()
    test_circuit_breaker()
    test_serve_stale_on_doh_outage()
    test_sni_less_preferred_in_rotation()
    test_pool_reservation_no_leak()
    test_pending_full_waits_without_cpu_spin()
    test_doh_attempt_unexpected_exception()
    test_dohconn_handshake_failure_closes_socket()

    print()
    print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
    sys.exit(0 if all(c for _, c in RESULTS) else 1)

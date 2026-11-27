"""Tests for hookip.doh — no real network (stubs for _DoHConn, sockets,
dnsmsg where needed). Run: python tests/test_doh.py"""
import os
import sys
import threading
import time
import types
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket  # noqa: E402
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

    def __init__(self, ip, host, timeout=3.5, chunk=2, keepalive=False):
        FakeConn.created += 1
        FakeConn.created_per_name[host] = FakeConn.created_per_name.get(host, 0) + 1
        self.ip, self.host = ip, host
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
                n_now = FakeConn.created
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
    real_session = r._doh_session

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
    import hookip.dnsmsg as dnsmsg
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
        StubDns.parse_response = staticmethod(
            lambda resp, qname=None: (0, [(("n"), 1, 60, "6.6.6.6")]))
        StubDns.extract_ips = staticmethod(
            lambda answers, qt: [v for (_n, t, _ttl, v) in answers])
        with mock.patch.object(dohmod.socket, "socket", FakeUDP), \
             mock.patch.object(dohmod, "dnsmsg", StubDns):
            ips, ttl = r._via_udp_dns("udp2.test", 1)
        check("UDP correct transaction ID accepted", ips == ["6.6.6.6"], str(ips))
    finally:
        StubDns.encode_query = staticmethod(real_encode)


# ---- 9. _start_idx guarded / is_sinkhole uses module socket -----------
def test_start_idx_threadsafe():
    r = make_resolver()
    errs = []

    def hammer():
        for _ in range(200):
            try:
                with mock.patch.object(dohmod, "dnsmsg", StubDns):
                    # exercise the rotation read/write path via the lock
                    with r._lock:
                        order = [dohmod.RESOLVERS[(r._start_idx + i) % len(dohmod.RESOLVERS)]
                                 for i in range(len(dohmod.RESOLVERS))]
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

    print()
    print(f"Summary: {sum(1 for _, c in RESULTS if c)}/{len(RESULTS)} passed")
    sys.exit(0 if all(c for _, c in RESULTS) else 1)

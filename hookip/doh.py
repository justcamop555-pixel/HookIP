"""DNS resolution: DNS-over-HTTPS with a hand-driven, fragmented TLS
handshake (so DoH itself cannot be SNI-blocked), falling back to
DNS-over-TCP, DNS-over-UDP and finally the system resolver."""
import ipaddress
import socket
import ssl
import struct
import threading
import time

from . import dnsmsg
from .perf import profile

RESOLVERS = [
    ("Cloudflare", "cloudflare-dns.com", "1.1.1.1"),
    ("Google", "dns.google", "8.8.8.8"),
    ("AdGuard", "dns.adguard-dns.com", "94.140.14.14"),
    ("ControlD", "freedns.controld.com", "76.76.2.11"),
]
TCP_DNS_FALLBACKS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
UDP_DNS_LAST_RESORT = ["1.1.1.1", "8.8.8.8"]

SINKHOLE_ADDRESSES = {"0.0.0.0", "::"}

# one shared SSL context for ALL DoH connections: create_default_context
# reloads the Windows CA store on EVERY call (tens of ms); contexts are
# thread-safe for wrap_bio
_SSL_CTX = None
_SSL_CTX_LOCK = threading.Lock()


def _ssl_context():
    global _SSL_CTX
    with _SSL_CTX_LOCK:
        if _SSL_CTX is None:
            _SSL_CTX = ssl.create_default_context()
    return _SSL_CTX


def is_sinkhole(ip):
    """Ad/tracker-blocking resolvers answer blocked names with a sinkhole
    address (0.0.0.0, ::) — treat those as 'no answer', not as a real
    destination. Canonicalizes first so every textual form of :: or 0.0.0.0
    is caught (e.g. 0:0:0:0:0:0:0:0)."""
    try:
        if ":" in ip:
            return socket.inet_pton(socket.AF_INET6, ip) == socket.inet_pton(socket.AF_INET6, "::")
        return socket.inet_pton(socket.AF_INET, ip) == socket.inet_pton(socket.AF_INET, "0.0.0.0")
    except (OSError, ValueError):
        pass
    return ip in SINKHOLE_ADDRESSES or ip.startswith("127.") or ip == "::1"


class ResolveError(Exception):
    pass


_PRIVATE_SUFFIXES = (".local", ".lan", ".home", ".internal", ".corp",
                     ".intranet", ".localdomain", ".private", ".test",
                     ".example", ".invalid", ".localhost")


def _is_private_ip(ip):
    """True for loopback/link-local/private/CGNAT/ULA/reserved addresses —
    ranges a PUBLIC hostname should never legitimately point at in a
    plaintext answer. Handles IPv4-mapped IPv6 forms."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    cgnat = (isinstance(a, ipaddress.IPv4Address)
             and a in ipaddress.ip_network("100.64.0.0/10"))
    return (not a.is_global) or cgnat


def _public_hostname(host, excluded=()):
    """False for names that plausibly live on a LAN and may legitimately
    resolve to private addresses: single-label, private-ish suffixes,
    reserved names, or user-excluded domains."""
    h = host.strip("[]").lower().rstrip(".")
    if not h or "." not in h or h == "localhost":
        return False
    if h.endswith(_PRIVATE_SUFFIXES):
        return False
    try:
        from .proxy import is_excluded
        if is_excluded(h, excluded or ()):
            return False
    except Exception:
        pass
    return True


class VerifiedNegative(ResolveError):
    """NXDOMAIN confirmed over a trusted channel (DoH / DNS-over-TCP).
    Falling back to plaintext/system DNS would risk serving poisoned data."""
    pass


class _DoHConn:
    """A DoH HTTPS connection with a fragmented ClientHello.
    Supports HTTP/1.1 keep-alive so one connection can serve many queries."""

    def __init__(self, ip, host, timeout=3.5, chunk=2, keepalive=False,
                 validate_by_ip=True):
        self.ip = ip
        self.host = host
        self.validate_by_ip = validate_by_ip   # True = SNI-LESS (IP-SAN)
        self.sock = socket.create_connection((ip, 443), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(timeout)
        ctx = _ssl_context()
        self._bio_in = ssl.MemoryBIO()
        self._bio_out = ssl.MemoryBIO()
        # SNI-LESS by default: server_hostname=IP validates the cert's
        # iPAddress SAN and Python omits the SNI extension entirely for IP
        # literals. With the old server_hostname=<resolver name> every
        # ClientHello carried 'cloudflare-dns.com' etc. in PLAINTEXT SNI —
        # a DPI filter could block each DoH endpoint BY NAME and silently
        # push HookIP down the plaintext fallbacks. Certificates without
        # an IP SAN fail here; _new_conn retries with the hostname.
        sni = ip if validate_by_ip else host
        self.ssl = ctx.wrap_bio(self._bio_in, self._bio_out, server_hostname=sni)
        self._handshake(chunk)
        self.keepalive = keepalive
        self.alive = True
        self.used = time.time()
        self._reqlock = threading.Lock()   # one query at a time on this conn

    def _frag_send(self, data, chunk):
        """chunk >= 1 fragments (1-byte segments at chunk=1); chunk < 1
        (0 — what _handshake passes for non-first flights) sends whole."""
        if chunk < 1:
            self.sock.sendall(data)
            return
        # cap the first flight at ~64 sendall calls: chunk=1 on a
        # multi-KB ClientHello would otherwise mean thousands of tiny
        # syscalls (each a separate TCP push). Raising the effective
        # chunk size keeps the first record split across segments
        # without hundreds of syscalls.
        eff = chunk
        if len(data) > 64 * eff:
            eff = -(-len(data) // 64)          # ceil(len/64)
        i = 0
        while i < len(data):
            size = min(eff, len(data) - i)
            self.sock.sendall(data[i:i + size])
            i += size

    def _handshake(self, chunk):
        first = True
        while True:
            try:
                self.ssl.do_handshake()
                return
            except ssl.SSLWantReadError:
                out = self._bio_out.read()
                if out:
                    self._frag_send(out, chunk if first else 0)
                    first = False
                d = self.sock.recv(16384)
                if not d:
                    raise ResolveError("connection closed during DoH handshake")
                self._bio_in.write(d)
            except ssl.SSLWantWriteError:
                out = self._bio_out.read()
                if out:
                    self._frag_send(out, chunk if first else 0)
                    first = False

    def _flush_out(self):
        while True:
            out = self._bio_out.read()
            if not out:
                break
            self.sock.sendall(out)

    def request(self, host, payload, timeout=5.0):
        # NOTE: the caller (Resolver pool checkout) holds self._reqlock for
        # the duration of this call — locking here again would deadlock.
        if not self.alive:
            raise ResolveError("session closed")
        self.sock.settimeout(timeout)
        conn_hdr = "keep-alive" if self.keepalive else "close"
        head = (
            "POST /dns-query HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/dns-message\r\n"
            "Accept: application/dns-message\r\n"
            "Accept-Encoding: identity\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: {conn_hdr}\r\n\r\n"
        ).encode("ascii")
        self.ssl.write(head + payload)
        self._flush_out()
        buf = b""
        body = None
        clen = None
        chunked = False
        while True:
            if chunked and body is not None:
                body = _dechunk(body)
                if body is not None:
                    self.used = time.time()
                    return self._validated(body, payload)
            elif clen is not None and body is not None and len(body) >= clen:
                self.used = time.time()
                return self._validated(body[:clen], payload)
            try:
                chunk = self.ssl.read(65536)
            except ssl.SSLWantReadError:
                try:
                    data = self.sock.recv(65536)
                except (socket.timeout, OSError):
                    self.alive = False
                    break
                if not data:
                    self.alive = False
                    break
                self._bio_in.write(data)
                continue
            except ssl.SSLWantWriteError:
                self._flush_out()
                continue
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                self.alive = False
                break
            if not chunk:
                self.alive = False
                break
            buf += chunk
            if clen is None:
                sep = buf.find(b"\r\n\r\n")
                if sep < 0:
                    if len(buf) > 65536:
                        self.alive = False
                        break
                    continue
                headers = buf[:sep].decode("latin1", "replace")
                for line in headers.split("\r\n")[1:]:
                    low = line.lower()
                    if low.startswith("content-length:"):
                        try:
                            clen = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            clen = None
                    elif low.startswith("transfer-encoding:") and "chunked" in low:
                        chunked = True
                body = buf[sep + 4:]
            else:
                # accumulate the body — overwriting with `buf` would paste
                # the HTTP HEADERS back into the DNS message (this caused
                # 'truncated name' parse failures on multi-record
                # responses, e.g. Google DoH). body is always bytes here
                # (this branch only runs after the header block set it);
                # `or b""` keeps that provable for type checkers.
                body = (body or b"") + chunk
        # connection ended — anything short of the promised length is
        # incomplete; raising triggers a fresh-session retry upstream
        if body and clen is not None and len(body) < clen:
            raise ResolveError("incomplete DoH response (connection cut)")
        if not body:
            return b""
        return self._validated(body, payload)

    def _validated(self, body, payload):
        """Guard against transport garbage (HTTP headers, split bodies): a DNS
        response must echo the query's transaction ID."""
        if len(body) >= 12 and body[:2] == payload[:2]:
            return body
        raise ResolveError("response is not a DNS message")

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass

    def healthy(self, max_idle=25.0):
        """Reusable if alive and idle under ~30s (server-side keep-alive timeout)."""
        return self.alive and (time.time() - self.used) < max_idle


def _dechunk(data):
    """Decode a chunked body; return the full payload once the final chunk
    (0-length) has arrived, else None (need more data)."""
    out = bytearray()
    i = 0
    while True:
        nl = data.find(b"\r\n", i)
        if nl < 0:
            return None
        try:
            size = int(data[i:nl].split(b";")[0], 16)
        except ValueError:
            return bytes(out)
        if size == 0:
            return bytes(out)
        if len(data) < nl + 2 + size + 2:
            return None
        out += data[nl + 2: nl + 2 + size]
        i = nl + 2 + size + 2


class Resolver:
    """Cached, fault-tolerant resolver shared by the proxy threads."""

    def __init__(self, cfg, log, chunk=2):
        self.cfg = cfg
        self.log = log
        self.chunk = chunk
        self._cache = {}                      # name -> (expiry, ips)
        self._neg_cache = {}                  # name -> (expiry, reason)
        self._lock = threading.Lock()
        self._start_idx = 0
        self._lat = {}                          # resolver name -> EMA latency (s)
        self._cb_fail = {}                      # resolver -> consecutive failures
        self._cb_open = {}                      # resolver -> cooldown-until (ts)
        self._inflight = {}                     # host -> Event (lookup coalescing)
        self._inflight_lock = threading.Lock()
        self.verbose_stats = {}               # resolver -> success count
        self._pool = {}                       # resolver name -> [_DoHConn, ...]
        self._sni_mode = {}                   # resolver -> 'ip' | 'host'
        self._last_plain_warn = 0.0           # throttles the DoH-fallback warn
        # how long past its expiry a cached DoH answer may be served as
        # stale when every resolver path fails (RFC 8767-style)
        self._STALE_MAX = 600
        self._pool_lock = threading.Lock()
        self._pool_max = profile().doh_pool_per_resolver  # hardware-scaled
        self._pending = {}                    # resolver -> conns being created
                                              # (slot reserved pre-creation;
                                              # guarded by _pool_lock)

    def _new_conn(self, name, ip, dns_host):
        """Create one pooled DoH connection, SNI-less when the resolver's
        certificate carries an IP SAN (all bundled resolvers do, verified
        live). A cert without an IP SAN falls back to the hostname (SNI
        visible) and the working mode is cached per resolver."""
        mode = self._sni_mode.get(name, "ip")
        try:
            conn = _DoHConn(ip, dns_host, chunk=max(1, self.chunk),
                            keepalive=True, validate_by_ip=(mode == "ip"))
            self._sni_mode[name] = mode
            return conn
        except ssl.SSLCertVerificationError:
            if mode != "ip":
                raise
            conn = _DoHConn(ip, dns_host, chunk=max(1, self.chunk),
                            keepalive=True, validate_by_ip=False)
            self._sni_mode[name] = "host"
            self.log.debug(f"DoH {name}: certificate has no IP SAN — "
                           "falling back to hostname SNI")
            return conn

    def _doh_session(self, name, dns_host, ip):
        """Check out a pooled keep-alive connection with its per-connection
        lock HELD (release it after request() finishes via _release_doh).
        Parallel lookups to different hosts use different connections in the
        pool instead of serializing behind one TLS session; a new connection
        is created while slots are free (a slot is RESERVED under the lock
        before creation, so a burst of N parallel lookups can never open N
        TLS sessions to one resolver)."""
        while True:
            new_conn = None
            reserved = False
            with self._pool_lock:
                pool = self._pool.get(name, [])
                conns = []
                stale = []
                for c in pool:
                    # FIX: never treat a CHECKED-OUT connection as stale —
                    # healthy() keys off `used`, which another thread could
                    # see as expired mid-request. A conn whose _reqlock is
                    # held stays in the pool and is never closed here.
                    if c.healthy() or self._lock_held(c):
                        conns.append(c)
                    else:
                        stale.append(c)
                self._pool[name] = conns
                # reservation check AND increment in ONE lock section —
                # split sections let N threads all pass the same check
                if len(conns) + self._pending.get(name, 0) < self._pool_max:
                    self._pending[name] = self._pending.get(name, 0) + 1
                    reserved = True
            for c in stale:
                c.close()
            for conn in conns:
                if conn._reqlock.acquire(blocking=False):
                    conn.used = time.time()   # refresh at checkout
                    return conn
            # CONFLICT FIX: connection setup (TCP+TLS, up to ~3.5 s) must NOT
            # happen while holding _pool_lock — every other resolver's checkout
            # would stall behind it. Create outside, register after (the
            # slot was reserved under the lock BEFORE creating).
            if reserved:
                try:
                    new_conn = self._new_conn(name, ip, dns_host)
                except BaseException:
                    # reservation released whether creation succeeded or failed
                    with self._pool_lock:
                        self._pending[name] -= 1
                    raise
                new_conn._reqlock.acquire()   # we just built it — it is ours
                with self._pool_lock:
                    # decrement + append in ONE section: split, a gap shows
                    # a slot free that is about to be filled again
                    self._pending[name] -= 1
                    self._pool.setdefault(name, []).append(new_conn)
                new_conn.used = time.time()   # refresh at checkout
                return new_conn
            # all slots busy and pool full — wait for the first conn
            with self._pool_lock:
                conns = self._pool.get(name, [])
                fallback = conns[0] if conns else None
            if fallback is None:
                # every slot is reserved-but-not-yet-registered: spinning
                # here would burn CPU at full speed for up to 3.5 s while
                # the other thread completes its TLS handshake (worst on
                # the low hardware tier, 1 conn per resolver + hedging)
                time.sleep(0.01)
                continue
            if not fallback._reqlock.acquire(timeout=4):
                time.sleep(0.01)
                continue          # race: slot freed or conn died — re-scan
            if not fallback.healthy():
                fallback._reqlock.release()
                self._drop_doh_session(name, fallback)
                continue
            fallback.used = time.time()           # refresh at checkout
            return fallback

    def _lock_held(self, conn):
        """True when conn._reqlock is currently held (in use by a lookup).
        Non-blocking test — safe to call while holding _pool_lock."""
        if conn._reqlock.acquire(blocking=False):
            conn._reqlock.release()
            return False
        return True

    def _release_doh(self, conn):
        conn._reqlock.release()

    def _drop_doh_session(self, name, conn):
        with self._pool_lock:
            pool = self._pool.get(name)
            if pool and conn in pool:
                pool.remove(conn)
        conn.close()

    # ------------------------------------------------------------------
    def resolve(self, host, qtype=dnsmsg.TYPE_A):
        host = host.strip("[]").lower()
        if not host:
            raise ResolveError("empty host")
        if _is_ip(host):
            return [host]

        now = time.time()
        with self._lock:
            neg = self._neg_cache.get(host)
            if neg and neg[0] > now:
                # reason stored with the entry (NXDOMAIN / NODATA / sinkhole) —
                # the old code always said 'NXDOMAIN' even when it wasn't
                raise ResolveError(f"{host}: {neg[1]} (cached)")
            hit = self._cache.get(host)
            if hit and hit[0] > now:
                return list(hit[1])

        # In-flight coalescing: browsers open many parallel connections to
        # the same host — without this, each connection triggers its own
        # full DoH resolver rotation. Follows wait for the first lookup.
        ev = None
        while True:
            with self._inflight_lock:
                ev = self._inflight.get(host)
                if ev is None:
                    self._inflight[host] = threading.Event()
                    break
            ev.wait(6.0)
            now = time.time()
            with self._lock:
                neg = self._neg_cache.get(host)
                if neg and neg[0] > now:
                    raise ResolveError(f"{host}: {neg[1]} (cached)")
                hit = self._cache.get(host)
                if hit and hit[0] > now:
                    return list(hit[1])
            # wait expired with no result — loop and take over if needed

        try:
            return self._lookup_uncached(host, qtype, time.time())
        finally:
            with self._inflight_lock:
                ev = self._inflight.pop(host, None)
            if ev:
                ev.set()

    def _plain_fallback_warn(self, host, source):
        """Secure-DNS degradation notice: DoH was on but could not answer,
        and the address came from plaintext DNS. Logged as WARN (throttled
        to one entry per 5 minutes — per-host detail stays at debug)."""
        with self._lock:
            last = self._last_plain_warn
        if time.time() - last <= 300:
            self.log.debug(f"plaintext {source} DNS resolved {host} "
                           "(DoH unavailable — warn throttled)")
            return
        with self._lock:
            self._last_plain_warn = time.time()
        self.log.warn(
            f"Secure DNS (DoH) unreachable — {host} was resolved via "
            f"plaintext {source.upper()} DNS, which is visible to the "
            "network. HookIP keeps trying DoH for new lookups; if this "
            "repeats on every lookup, this network is blocking DoH.")

    def _lookup_uncached(self, host, qtype, now):
        """Full resolver chain (DoH → TCP → UDP → system) with caching.
        Called at most once per host at a time (in-flight coalescing)."""
        ips = []
        ttl = 120
        verified_neg = None    # trusted negative verdict string (NXDOMAIN / NODATA)
        doh_note = None        # detailed last DoH verdict (helps messaging)
        source = None          # where the winning answer came from (logging)
        try:
            if self.cfg.doh_enabled:
                ips, ttl, doh_note = self._via_doh(host, qtype)
                if ips:
                    source = "doh"
            else:
                ips, ttl, doh_note = [], 120, None
            if not ips:
                # a single unconfirmed DoH NXDOMAIN vote makes TCP DNS the
                # second opinion (one agreeing server confirms it); with no
                # DoH vote, two TCP servers must agree
                try:
                    ips, ttl = self._via_tcp_dns(
                        host, qtype,
                        doh_nx_vote=bool(doh_note
                                         and doh_note.startswith("NXDOMAIN (unconfirmed")))
                except VerifiedNegative:
                    raise           # a confirming vote is a verdict, not noise
                except (ResolveError, OSError):
                    ips, ttl = [], ttl
                if ips:
                    source = "tcp"
        except VerifiedNegative as exc:
            verified_neg = str(exc)
            ips, ttl = [], ttl
        if not ips and verified_neg is None:
            ips, ttl = self._via_udp_dns(host, qtype)
            if ips:
                source = "udp"
        if not ips and verified_neg is None:
            ips, ttl = self._via_system(host, qtype)
            if ips:
                source = "system"
        if not ips:
            # A resolver that ANSWERED (rcode 0) but has no usable records
            # is a trusted verdict (NODATA). A single unconfirmed DoH
            # NXDOMAIN vote is NOT — cache it briefly (60 s), not like a
            # confirmed negative (300 s).
            unconfirmed_nx = bool(verified_neg is None and doh_note
                                  and doh_note.startswith("NXDOMAIN (unconfirmed"))
            if verified_neg is None and doh_note:
                verified_neg = doh_note
            if verified_neg:
                # store the reason WITHOUT the host (the cached-raise adds it)
                reason = (verified_neg.split(": ", 1)[1]
                          if verified_neg.startswith(host + ": ") else verified_neg)
            else:
                reason = "no addresses (DNS unreachable or dead domain)"
            neg_ttl = 60 if unconfirmed_nx else (300 if verified_neg else 120)
            with self._lock:
                self._neg_cache[host] = (now + neg_ttl, reason)

            # CROSS-TYPE last chance: a name can be AAAA-only
            # (brunhild.challenges.cloudflare.com: the A query is a verified
            # NODATA from every provider, but AAAA has live addresses) or
            # A-only. This runs whether or not the first verdict was
            # verified — NXDOMAIN skips it (the name does not exist at all,
            # so no record type can answer). Finding a usable address here
            # beats reporting a false 'dead domain'.
            nx_verdict = bool(verified_neg and "NXDOMAIN" in verified_neg)
            other = (dnsmsg.TYPE_AAAA if qtype == dnsmsg.TYPE_A
                     else dnsmsg.TYPE_A)
            other_note = None
            if not nx_verdict:
                try:
                    if self.cfg.doh_enabled:
                        ips, ttl, other_note = self._via_doh(host, other)
                        if ips:
                            source = "doh"
                except (ResolveError, OSError):
                    ips, other_note = [], None
                if not ips:
                    try:
                        ips, ttl = self._via_tcp_dns(
                            host, other,
                            doh_nx_vote=bool(other_note and other_note.startswith(
                                "NXDOMAIN (unconfirmed")))
                        if ips:
                            source = "tcp"
                    except (ResolveError, OSError):
                        ips = []
                if ips:
                    ips = [ip for ip in ips if not is_sinkhole(ip)]
                if ips:
                    # the negative mark above is WRONG now (a working
                    # address exists) — clear it or resolve() would report
                    # a cached negative while the positive cache below is
                    # written with real addresses
                    with self._lock:
                        self._neg_cache.pop(host, None)
                elif other_note and not other_note.startswith("NXDOMAIN"):
                    # both types answered-empty: one honest merged verdict
                    other_kind = "AAAA" if qtype == dnsmsg.TYPE_A else "A"
                    if verified_neg and "(" in verified_neg:
                        kind = ("no A or AAAA records"
                                if qtype == dnsmsg.TYPE_A
                                else "no AAAA or A records")
                        reason = f"{kind} ({verified_neg.split('(', 1)[1]}"
                        if not reason.endswith(")"):
                            reason += ")"
                        neg_ttl = 300
                    elif verified_neg:
                        reason = f"{reason}; {other_kind} check: {other_note}"
                        neg_ttl = 120
                    else:
                        # primary lookups were network-dead, but the cross
                        # type was answered-empty — say both halves
                        reason = (f"{reason} ({other_kind} lookup answered "
                                  f"empty: {other_note})")
                        neg_ttl = 60
                    with self._lock:
                        self._neg_cache[host] = (now + neg_ttl, reason)
            if not ips:
                # SERVE-STALE (RFC 8767 flavored): every path failed, but if
                # a recently-expired DoH answer is still within the
                # staleness window, serve it briefly instead of falling to
                # plaintext. The last authenticated answer beats a fresh
                # forged one — and on flapping DoH the site keeps working.
                stale = None
                if self.cfg.doh_enabled:
                    with self._lock:
                        entry = self._cache.get(host)
                        if entry and now < entry[0] + self._STALE_MAX:
                            stale = entry
                if stale:
                    ips = list(stale[1])
                    ttl = 30      # brief — the resolver retries DoH soon
                    with self._lock:
                        self._neg_cache.pop(host, None)
                        self._cache[host] = (now + ttl, ips)
                    self.log.warn(
                        f"DoH unreachable — serving the STALE cached answer "
                        f"for {host} (ttl {ttl}s); plaintext fallback skipped")
            if not ips:
                raise ResolveError(reason if reason.startswith("no addresses for ")
                                   else f"no addresses for {host} ({reason})")

        # ANTI-REBINDING / POISONING GUARD: a PLAINTEXT answer (TCP/UDP/
        # system — every path an on-path attacker can forge) for a
        # public-looking hostname that points into a PRIVATE range is
        # almost certainly an attack: DNS rebinding, a poisoned record, or
        # a captive portal hijacking the name. DoH answers are TLS-
        # authenticated and cannot be forged on path, so this guard
        # applies to the plaintext fallbacks only. LAN-plausible names
        # (single-label, .local/.lan style, excluded domains) keep their
        # private answers.
        if (source not in ("doh", None) and self.cfg.doh_enabled
                and ips and _public_hostname(host, getattr(self.cfg, "excluded", ()) or ())):
            priv = [ip for ip in ips if _is_private_ip(ip)]
            if priv and len(priv) == len(ips):
                with self._lock:
                    self._neg_cache[host] = (
                        now + 120,
                        "plaintext answer pointed into a private range "
                        "(possible poisoning)")
                raise ResolveError(
                    f"no addresses for {host} (plaintext {source.upper()} "
                    "DNS answered with private-range address(es) — dropped "
                    "as possible DNS rebinding/poisoning)")
            if priv:
                ips = [ip for ip in ips if not _is_private_ip(ip)]
                self.log.warn(
                    f"plaintext {source.upper()} DNS answered {host} with "
                    f"{len(priv)} private-range address(es) — dropped as "
                    "possible DNS rebinding/poisoning")

        blocked = [ip for ip in ips if is_sinkhole(ip)]
        if blocked:
            ips = [ip for ip in ips if not is_sinkhole(ip)]
            self.log.debug(f"resolve {host}: dropped sinkhole answer(s) {', '.join(blocked)}")
            if not ips:
                with self._lock:
                    self._neg_cache[host] = (now + 120, "all resolvers returned a sinkhole")
                raise ResolveError(f"no addresses for {host} (all resolvers returned a sinkhole)")
        # the Secure-DNS degradation notice: warn once per 5 minutes when
        # DoH was enabled but a plaintext path produced the address (after
        # the sinkhole filter so a rejected answer never consumes the
        # throttle slot, and only for a genuinely usable answer)
        if source and source != "doh" and self.cfg.doh_enabled and ips:
            self._plain_fallback_warn(host, source)

        ttl = min(300, max(10, int(ttl or 120)))   # None -> sensible default
        with self._lock:
            cap = profile().cache_cap
            neg_cap = profile().neg_cache_cap
            if len(self._cache) > cap:
                # marathon sessions: drop expired entries first, then the
                # oldest — the cache must never grow without bound
                now2 = time.time()
                alive = {h: e for h, e in self._cache.items() if e[0] > now2}
                if len(alive) > cap:
                    alive = dict(sorted(alive.items(), key=lambda kv: kv[1][0])[:cap // 2])
                self._cache = alive
            if len(self._neg_cache) > neg_cap:
                now2 = time.time()
                self._neg_cache = {h: e for h, e in self._neg_cache.items() if e[0] > now2}
            self._cache[host] = (now + ttl, list(ips))
        self.log.debug(f"resolve {host} -> {', '.join(ips[:4])} (ttl {ttl}s)")
        return list(ips)

    # -- strategies ------------------------------------------------------
    # -- circuit breaker -------------------------------------------------
    # A resolver that fails repeatedly (blocked IPs, dead network path)
    # used to be retried on EVERY lookup — each miss burned a hedge slot
    # and 0.4 s of latency for the other resolvers. After 3 consecutive
    # failures it now cools down for 5 minutes and is skipped by the
    # rotation (unless ALL resolvers are cooling, in which case nobody is
    # skipped — a total outage must still be attempted). The first
    # success resets it.
    _CB_FAILS = 3          # consecutive failures before the cooldown
    _CB_COOLDOWN = 300.0   # seconds

    def _cb_note(self, name, ok):
        with self._lock:
            prev = self._cb_fail.get(name, 0)
            if ok:
                if prev >= self._CB_FAILS:
                    self.log.ok(f"DoH {name}: working again after "
                                f"{prev} consecutive failures — back in rotation")
                self._cb_fail[name] = 0
                self._cb_open.pop(name, None)
            else:
                fails = prev + 1
                self._cb_fail[name] = fails
                if fails >= self._CB_FAILS and name not in self._cb_open:
                    self._cb_open[name] = time.time() + self._CB_COOLDOWN
                    self.log.warn(
                        f"DoH {name}: failed {fails}× in a row — paused "
                        f"for {self._CB_COOLDOWN // 60} min (auto-retries; "
                        "other resolvers keep serving)")

    def _cb_skip(self, name):
        """True when this resolver is in cooldown AND at least one other
        resolver is currently usable — a total outage skips nobody."""
        with self._lock:
            until = self._cb_open.get(name)
            if not until or time.time() >= until:
                return False            # not cooling
            for other in RESOLVERS:
                on = other[0]
                if on == name:
                    continue
                o = self._cb_open.get(on)
                if not o or time.time() >= o:
                    return True         # someone else is usable — sit out
            return False                # everyone cooling — keep trying

    def _note_latency(self, name, dt, ok=True):
        """Exponential moving average so slow resolvers (e.g. ~1s AdGuard)
        automatically drop to the back of the rotation."""
        with self._lock:
            prev = self._lat.get(name)
            if prev is None:
                self._lat[name] = max(0.01, dt)
            elif ok:
                self._lat[name] = 0.7 * prev + 0.3 * dt
            else:
                self._lat[name] = min(10.0, prev * 1.2 + 0.1)

    def _via_doh(self, host, qtype):
        n = len(RESOLVERS)
        with self._lock:
            order = [RESOLVERS[(self._start_idx + i) % n] for i in range(n)]
            self._start_idx = (self._start_idx + 1) % n
        # fastest first — measured latency beats fixed rotation
        order.sort(key=lambda r: self._lat.get(r[0], 1.0))
        # circuit breaker: cooling resolvers drop to the BACK of the order.
        # They are demoted, never skipped outright — a total outage still
        # reaches them, and they keep getting occasional probes so recovery
        # is detected without waiting out the full cooldown.
        order.sort(key=lambda r: 1 if self._cb_skip(r[0]) else 0)
        query = dnsmsg.encode_query(host, qtype)
        rec = "AAAA" if qtype == dnsmsg.TYPE_AAAA else "A"

        # HEDGED execution: at most 2 resolver attempts in flight. The 2nd
        # launches 0.4 s after the 1st if it has not answered (if DoH IPs
        # are blocked, the old strict sequence burned ~14 s before TCP
        # fallback). First usable answer wins; the rest are abandoned (their
        # connections release/drop inside _doh_attempt, which runs to
        # completion in its worker thread regardless).
        holders = {}                      # idx -> [attempt result]
        ready = set()                     # completed attempt indices
        inflight = []                     # running attempt indices (launch order)
        done_cv = threading.Condition()   # workers notify on completion —
        # the old loop polled thread.is_alive() every 20 ms, waking the
        # calling thread ~50x/s during EVERY lookup: a real CPU cost on
        # 2-core machines with many parallel connections (and it added up
        # to 20 ms of latency per lookup). The condition wake is instant.
        state = {"next": 0, "hedge_deadline": None}

        def _launch(i):
            name, dns_host, ip = order[i]
            holders[i] = []

            def run():
                try:
                    holders[i].append(
                        self._doh_attempt(name, dns_host, ip, host, qtype, query))
                finally:
                    with done_cv:
                        ready.add(i)
                        done_cv.notify_all()

            try:
                threading.Thread(target=run, daemon=True).start()
            except RuntimeError:
                # cannot start a thread (thread budget exhausted on a loaded
                # low-end machine) — run the attempt INLINE instead of losing
                # the whole lookup; the finally above still signals done_cv
                run()
            inflight.append(i)

        result = None            # ('pos', ips, ttl) winner
        verified = None          # CNAME-path VerifiedNegative message
        nx_votes = []            # resolver names that voted NXDOMAIN
        nodata = []
        last_err = None
        if n:
            _launch(0)
            state["next"] = 1
            state["hedge_deadline"] = time.time() + 0.4
        while result is None and verified is None and (inflight or state["next"] < n):
            # keep up to 2 attempts in flight (2nd hedges 0.4 s behind the 1st)
            # (the deadline is None only before the first launch, when the
            # inflight check already short-circuits — made explicit here so
            # that is provable, not just true)
            deadline = state["hedge_deadline"]
            if (len(inflight) < 2 and state["next"] < n
                    and (len(inflight) == 0
                         or (deadline is not None and time.time() >= deadline))):
                _launch(state["next"])
                state["next"] += 1
                state["hedge_deadline"] = time.time() + 0.4
                continue
            if not inflight:
                break
            # event-driven wait: workers notify the moment an attempt
            # finishes; the timeout only bounds the hedge-deadline checks
            if not ready:
                timeout = 0.05
                if state["hedge_deadline"] is not None:
                    timeout = max(0.01, min(timeout,
                                            state["hedge_deadline"] - time.time()))
                with done_cv:
                    if not ready:
                        done_cv.wait(timeout)
            if not ready:
                continue          # hedge deadline may have passed — loop
            done_idx = next((i for i in inflight if i in ready), None)
            if done_idx is None:
                continue
            ready.discard(done_idx)
            inflight.remove(done_idx)
            res = holders[done_idx][0] if holders[done_idx] else (
                "err", f"{done_idx}: no result", None)
            kind = res[0]
            if kind == "pos":
                result = res
                break
            if kind == "verified_neg":
                verified = res[1]
                break
            if kind == "nx":
                nx_votes.append(res[1])
            elif kind == "nodata":
                nodata.append(res[1])
            else:
                last_err = res[1]
        if verified:
            raise VerifiedNegative(verified)
        if result:
            return result[1], result[2], None

        # NXDOMAIN is a VOTE, not an immediate verdict: one filtering
        # resolver (AdGuard, ControlD) can NXDOMAIN a name the others
        # resolve. Positive answers already won above; two DIFFERENT
        # resolvers agreeing is a verified negative; a single vote stays
        # unconfirmed and lets _via_tcp_dns act as the second opinion.
        note = None
        if len(set(nx_votes)) >= 2:
            raise VerifiedNegative(
                f"{host}: NXDOMAIN (verified via DoH {', '.join(nx_votes)})")
        if nodata:
            # at least one resolver answered authoritatively: the name has no
            # usable address record right now — this is a real verdict, not a
            # resolver outage (the old code reported the LAST resolver's
            # SERVFAIL as the reason and WARNed, then poisoned the negative
            # cache with 'NXDOMAIN')
            note = (f"no {rec} records (NODATA, verified via DoH "
                    f"{', '.join(nodata)})")
            self.log.debug(f"DoH verdict for {host}: {note} "
                           f"(other resolvers: {last_err})")
        elif nx_votes:
            note = "NXDOMAIN (unconfirmed, single resolver)"
            self.log.debug(f"DoH verdict for {host}: {note} "
                           f"(other resolvers: {last_err})")
        elif last_err:
            # policy verdicts (sinkhole/empty) are expected for ad domains —
            # DEBUG keeps the detail without spamming WARN on every retry
            level = "debug" if ("sinkhole" in last_err or "rcode 0" in last_err
                                or "no answer" in last_err) else "warn"
            getattr(self.log, level)(f"DoH failed for {host}: {last_err}")
        return [], 120, note

    def _doh_attempt(self, name, dns_host, ip, host, qtype, query):
        """One resolver attempt, fully self-contained (checkout, retries,
        release). Returns ('pos', ips, ttl) | ('nx', name) | ('nodata', name)
        | ('verified_neg', msg) | ('err', msg). Never raises (except nothing
        escapes — failures come back as results)."""
        conn = None
        t0 = time.time()
        try:
            conn = self._doh_session(name, dns_host, ip)
            try:
                resp = conn.request(dns_host, query)
            except (OSError, ResolveError, ssl.SSLError, ValueError) as exc:
                # pooled session died (idle timeout, RST) — one fresh retry.
                # Release the checkout BEFORE dropping so a waiter on the
                # dying connection's lock is freed instead of stalling.
                self._release_doh(conn)
                self._drop_doh_session(name, conn)
                conn = None
                self.log.debug(f"DoH {name}: session dropped ({exc}), reconnecting")
                conn = self._doh_session(name, dns_host, ip)
                resp = conn.request(dns_host, query)
            if not resp:
                raise ResolveError("empty response")
            rcode, answers = dnsmsg.parse_response(resp, qname=host)
            dt = time.time() - t0
            self._note_latency(name, dt, ok=True)
            self._cb_note(name, ok=True)   # reachable and answering → reset
            self.log.debug(f"DoH {name}: {host} rcode={rcode} in {dt:.2f}s")
            if rcode == 3:
                self._cb_note(name, ok=True)  # spoke authoritatively → reset
                return ("nx", name, None)
            if rcode != 0:
                return ("err", f"{name}: rcode {rcode}", None)
            ips = dnsmsg.extract_ips(answers, qtype)
            ttl = _min_ttl(answers) or 120
            blocked = [ip2 for ip2 in ips if is_sinkhole(ip2)]
            if blocked:
                ips = [ip2 for ip2 in ips if not is_sinkhole(ip2)]
                self.log.debug(
                    f"DoH {name}: {host} returned a sinkhole/blocked answer "
                    f"({', '.join(blocked)}) — "
                    + ("trying next resolver" if not ips else "using remaining addresses"))
                if not ips:
                    return ("err", f"{name}: blocked (sinkhole)", None)
            if not ips and answers:
                # CNAME chain: follow the final alias on the same pooled session
                for (_n, t, _ttl, v) in answers:
                    if t == 5:
                        follow = dnsmsg.encode_query(v, qtype)
                        try:
                            resp2 = conn.request(dns_host, follow)
                        except (OSError, ResolveError, ssl.SSLError, ValueError):
                            self._release_doh(conn)
                            self._drop_doh_session(name, conn)
                            conn = None     # FIX: cleared BEFORE reconnecting so
                            # a reconnect failure can never double-release via
                            # the finally below (the first retry path does this)
                            conn = self._doh_session(name, dns_host, ip)
                            resp2 = conn.request(dns_host, follow)
                        _rc, ans2 = dnsmsg.parse_response(resp2, qname=v)
                        if _rc == 3:
                            # the alias target does not exist — one resolver's
                            # word is a VOTE, not a verdict: a policy/filtering
                            # resolver can NX a legit name. Count it like the
                            # direct-query vote instead of raising a
                            # single-resolver VerifiedNegative.
                            self._release_doh(conn)
                            return ("nx", name, None)
                        if _rc != 0:
                            # SERVFAIL/REFUSED on the follow-up is NOT NODATA
                            # (the old code fell through and treated it as an
                            # authoritative empty answer)
                            self._release_doh(conn)
                            return ("err", f"{name}: rcode {_rc} on CNAME follow-up", None)
                        ips = dnsmsg.extract_ips(ans2, qtype)
                        ttl = _min_ttl(ans2) or ttl
                        break
            with self._lock:
                self.verbose_stats[name] = self.verbose_stats.get(name, 0) + 1
            if ips:
                return ("pos", ips, ttl)
            # rcode 0 with no usable records: the name exists but has no
            # address records right now (NODATA) — a TRUSTED verdict from
            # this resolver (it spoke authoritatively over DoH)
            return ("nodata", name, None)
        except VerifiedNegative as exc:
            return ("verified_neg", str(exc), None)
        except (OSError, ResolveError, ValueError, ssl.SSLError) as exc:
            self._note_latency(name, time.time() - t0, ok=False)
            self._cb_note(name, ok=False)     # transport failure → breaker
            self.log.debug(f"DoH {name} failed: {exc}")
            return ("err", f"{name}: {exc}", None)
        finally:
            if conn is not None:
                self._release_doh(conn)

    def _via_tcp_dns(self, host, qtype, doh_nx_vote=False):
        """Plaintext DNS-over-TCP fallback. NXDOMAIN here is trusted only
        as a SECOND OPINION: it confirms an existing DoH NXDOMAIN vote,
        or (DoH disabled / unreachable, doh_nx_vote False) requires TWO
        TCP servers to agree — a single plaintext port-53 answer is too
        easy to inject."""
        query = dnsmsg.encode_query(host, qtype)
        nx_seen = []
        for ip in TCP_DNS_FALLBACKS:
            try:
                with socket.create_connection((ip, 53), timeout=4) as s:
                    s.sendall(struct.pack(">H", len(query)) + query)
                    ln = s.recv(2)
                    if len(ln) < 2:
                        continue
                    need = int.from_bytes(ln, "big")
                    resp = b""
                    while len(resp) < need:
                        part = s.recv(4096)
                        if not part:
                            break
                        resp += part
                rcode, answers = dnsmsg.parse_response(resp, qname=host)
                if rcode == 3:
                    nx_seen.append(ip)
                    if doh_nx_vote:
                        # agrees with the DoH vote — confirmed
                        raise VerifiedNegative(
                            f"{host}: NXDOMAIN (verified via DoH + TCP DNS {ip})")
                    if len(nx_seen) >= 2:
                        raise VerifiedNegative(
                            f"{host}: NXDOMAIN (verified via TCP DNS "
                            f"{nx_seen[0]} + {nx_seen[1]})")
                    continue
                ips = dnsmsg.extract_ips(answers, qtype)
                if ips:
                    self.log.debug(f"TCP DNS {ip}: {host} -> {ips[0]}")
                    return ips, (_min_ttl(answers) or 120)
            except (OSError, ValueError) as exc:
                self.log.debug(f"TCP DNS {ip} failed: {exc}")
        return [], 120

    def _via_udp_dns(self, host, qtype):
        query = dnsmsg.encode_query(host, qtype)
        qid = query[:2]                     # transaction ID echoed by replies
        for ip in UDP_DNS_LAST_RESORT:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(3)
                # connect() so the kernel filters datagrams from other
                # sources — the old recvfrom accepted a reply from ANYONE
                s.connect((ip, 53))
                s.send(query)
                resp = s.recv(4096)
            except OSError as exc:
                # FIX: the old version leaked one UDP socket per timeout/error
                # (close() was only on the success path)
                s.close()
                self.log.debug(f"UDP DNS {ip} failed: {exc}")
                continue
            s.close()
            if resp[:2] != qid:
                # wrong transaction ID: injected/garbage reply — ignore
                self.log.debug(f"UDP DNS {ip}: reply transaction ID mismatch — ignored")
                continue
            try:
                rcode, answers = dnsmsg.parse_response(resp, qname=host)
                # NXDOMAIN over plaintext UDP is NOT trusted (may be injected)
                if rcode != 0:
                    continue
                ips = dnsmsg.extract_ips(answers, qtype)
                if ips:
                    self.log.debug(f"UDP DNS {ip}: {host} -> {ips[0]}")
                    return ips, (_min_ttl(answers) or 120)
            except ValueError as exc:
                self.log.debug(f"UDP DNS {ip}: unparseable response ({exc})")
        return [], 120

    def _via_system(self, host, qtype):
        try:
            family = socket.AF_INET6 if qtype == dnsmsg.TYPE_AAAA else socket.AF_INET
            infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
            seen = []
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    seen.append(ip)
            return seen, 60
        except OSError:
            return [], 120

    def cache_stats(self):
        """(positive entries, negative/NXDOMAIN entries) currently held."""
        with self._lock:
            now = time.time()
            pos = sum(1 for e in self._cache.values() if e[0] > now)
            neg = sum(1 for e in self._neg_cache.values() if e[0] > now)
        return pos, neg

    def cache_hosts(self):
        with self._lock:
            return list(self._cache.keys())

    def clear_cache(self):
        with self._lock:
            self._cache.clear()
            self._neg_cache.clear()
        with self._pool_lock:
            for pool in self._pool.values():
                for conn in pool:
                    conn.close()
            self._pool.clear()


def _min_ttl(answers):
    """Smallest TTL among A/AAAA records in a parsed answer set."""
    ttls = [ttl for (_n, t, ttl, _v) in answers if t in (dnsmsg.TYPE_A, dnsmsg.TYPE_AAAA)]
    return min(ttls) if ttls else None


def _is_ip(host):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (OSError, ValueError):
            continue
    return False

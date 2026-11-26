"""DNS resolution: DNS-over-HTTPS with a hand-driven, fragmented TLS
handshake (so DoH itself cannot be SNI-blocked), falling back to
DNS-over-TCP, DNS-over-UDP and finally the system resolver."""
import socket
import ssl
import struct
import threading
import time

from . import dnsmsg

RESOLVERS = [
    ("Cloudflare", "cloudflare-dns.com", "1.1.1.1"),
    ("Google", "dns.google", "8.8.8.8"),
    ("AdGuard", "dns.adguard-dns.com", "94.140.14.14"),
    ("Quad9", "dns.quad9.net", "9.9.9.9"),
]
TCP_DNS_FALLBACKS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
UDP_DNS_LAST_RESORT = ["1.1.1.1", "8.8.8.8"]

SINKHOLE_ADDRESSES = {"0.0.0.0", "::"}


def is_sinkhole(ip):
    """Ad/tracker-blocking resolvers answer blocked names with a sinkhole
    address (0.0.0.0, ::) — treat those as 'no answer', not as a real
    destination. Canonicalizes first so every textual form of :: or 0.0.0.0
    is caught (e.g. 0:0:0:0:0:0:0:0)."""
    try:
        import socket as _s
        if ":" in ip:
            return _s.inet_pton(_s.AF_INET6, ip) == _s.inet_pton(_s.AF_INET6, "::")
        return _s.inet_pton(_s.AF_INET, ip) == _s.inet_pton(_s.AF_INET, "0.0.0.0")
    except (OSError, ValueError):
        pass
    return ip in SINKHOLE_ADDRESSES or ip.startswith("127.") or ip == "::1"


class ResolveError(Exception):
    pass


class VerifiedNegative(ResolveError):
    """NXDOMAIN confirmed over a trusted channel (DoH / DNS-over-TCP).
    Falling back to plaintext/system DNS would risk serving poisoned data."""
    pass


class _DoHConn:
    """A DoH HTTPS connection with a fragmented ClientHello.
    Supports HTTP/1.1 keep-alive so one connection can serve many queries."""

    def __init__(self, ip, host, timeout=3.5, chunk=2, keepalive=False):
        self.ip = ip
        self.host = host
        self.sock = socket.create_connection((ip, 443), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        self._bio_in = ssl.MemoryBIO()
        self._bio_out = ssl.MemoryBIO()
        self.ssl = ctx.wrap_bio(self._bio_in, self._bio_out, server_hostname=host)
        self._handshake(chunk)
        self.keepalive = keepalive
        self.alive = True
        self.used = time.time()
        self._reqlock = threading.Lock()   # one query at a time on this conn

    def _frag_send(self, data, chunk):
        if chunk <= 1:
            self.sock.sendall(data)
            return
        i = 0
        while i < len(data):
            size = min(chunk, len(data) - i)
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
                # responses, e.g. Google DoH)
                body += chunk
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
        self._neg_cache = {}                  # name -> expiry
        self._lock = threading.Lock()
        self._start_idx = 0
        self._lat = {}                          # resolver name -> EMA latency (s)
        self._inflight = {}                     # host -> Event (lookup coalescing)
        self._inflight_lock = threading.Lock()
        self.verbose_stats = {}               # resolver -> success count
        self._pool = {}                       # resolver name -> [_DoHConn, ...]
        self._pool_lock = threading.Lock()
        self._pool_max = 3                    # conns per resolver (parallel lookups)

    def _doh_session(self, name, dns_host, ip):
        """Check out a pooled keep-alive connection with its per-connection
        lock HELD (release it after request() finishes via _release_doh).
        Parallel lookups to different hosts use different connections in the
        pool instead of serializing behind one TLS session; a new connection
        is created while slots are free."""
        while True:
            new_conn = None
            with self._pool_lock:
                conns = [c for c in self._pool.get(name, []) if c.healthy()]
                # drop dead entries
                for c in self._pool.get(name, []):
                    if c not in conns:
                        c.close()
                self._pool[name] = conns
                for conn in conns:
                    if conn._reqlock.acquire(blocking=False):
                        return conn
                if len(conns) < self._pool_max:
                    need_new = True
                else:
                    need_new = False
            # CONFLICT FIX: connection setup (TCP+TLS, up to ~3.5 s) must NOT
            # happen while holding _pool_lock — every other resolver's checkout
            # would stall behind it. Create outside, register after.
            if need_new:
                try:
                    new_conn = _DoHConn(ip, dns_host,
                                        chunk=max(1, self.chunk), keepalive=True)
                except (OSError, ResolveError, ssl.SSLError):
                    raise
                if new_conn._reqlock.acquire(blocking=False):
                    with self._pool_lock:
                        self._pool.setdefault(name, []).append(new_conn)
                    return new_conn
                new_conn.close()      # someone else filled the slot meanwhile
                continue
            # all slots busy and pool full — wait for the first conn
            with self._pool_lock:
                conns = self._pool.get(name, [])
                fallback = conns[0] if conns else None
            if fallback is None or not fallback._reqlock.acquire(timeout=4):
                continue          # race: slot freed or conn died — re-scan
            if not fallback.healthy():
                fallback._reqlock.release()
                self._drop_doh_session(name, fallback)
                continue
            return fallback

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
            if neg and neg > now:
                raise ResolveError(f"{host}: cached NXDOMAIN")
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
                if neg and neg > now:
                    raise ResolveError(f"{host}: cached NXDOMAIN")
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

    def _lookup_uncached(self, host, qtype, now):
        """Full resolver chain (DoH → TCP → UDP → system) with caching.
        Called at most once per host at a time (in-flight coalescing)."""
        ips = []
        ttl = 120
        verified_neg = None
        try:
            if self.cfg.doh_enabled:
                ips, ttl = self._via_doh(host, qtype)
            if not ips:
                ips, ttl = self._via_tcp_dns(host, qtype)
        except VerifiedNegative as exc:
            verified_neg = str(exc)
            ips, ttl = [], ttl
        if not ips and not verified_neg:
            ips, ttl = self._via_udp_dns(host, qtype)
        if not ips and not verified_neg:
            ips, ttl = self._via_system(host, qtype)
        if not ips:
            neg_ttl = 300 if verified_neg else 120
            with self._lock:
                self._neg_cache[host] = now + neg_ttl
            if not verified_neg and self.cfg.doh_enabled:
                # IPv6-only host? one AAAA pass before giving up — connecting
                # through the tunnel to an IPv6 address works fine
                try:
                    ips, ttl = self._via_doh(host, dnsmsg.TYPE_AAAA)
                    if ips:
                        ips = [ip for ip in ips if not is_sinkhole(ip)]
                        # the negative mark above is WRONG now (the name has
                        # AAAA records) — clear it or resolve() would report
                        # 'cached NXDOMAIN' for the next 120s while a working
                        # address sits in the positive cache
                        with self._lock:
                            self._neg_cache.pop(host, None)
                except (ResolveError, OSError):
                    ips = []
                if not ips:
                    try:
                        ips, ttl = self._via_tcp_dns(host, dnsmsg.TYPE_AAAA)
                        if ips:
                            ips = [ip for ip in ips if not is_sinkhole(ip)]
                            with self._lock:
                                self._neg_cache.pop(host, None)
                    except (ResolveError, OSError):
                        ips = []
            if not ips:
                raise ResolveError(verified_neg or
                                   f"no addresses for {host} (DNS unreachable or dead domain)")

        blocked = [ip for ip in ips if is_sinkhole(ip)]
        if blocked:
            ips = [ip for ip in ips if not is_sinkhole(ip)]
            self.log.debug(f"resolve {host}: dropped sinkhole answer(s) {', '.join(blocked)}")
            if not ips:
                with self._lock:
                    self._neg_cache[host] = now + 120
                raise ResolveError(f"no addresses for {host} (all resolvers returned a sinkhole)")

        ttl = min(300, max(10, int(ttl)))
        with self._lock:
            if len(self._cache) > 4096:
                # marathon sessions: drop expired entries first, then the
                # oldest — the cache must never grow without bound
                now2 = time.time()
                alive = {h: e for h, e in self._cache.items() if e[0] > now2}
                if len(alive) > 4096:
                    alive = dict(sorted(alive.items(), key=lambda kv: kv[1][0])[:2048])
                self._cache = alive
            if len(self._neg_cache) > 2048:
                now2 = time.time()
                self._neg_cache = {h: e for h, e in self._neg_cache.items() if e > now2}
            self._cache[host] = (now + ttl, list(ips))
        self.log.debug(f"resolve {host} -> {', '.join(ips[:4])} (ttl {ttl}s)")
        return list(ips)

    # -- strategies ------------------------------------------------------
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
        order = [RESOLVERS[(self._start_idx + i) % n] for i in range(n)]
        self._start_idx = (self._start_idx + 1) % n
        # fastest first — measured latency beats fixed rotation
        order.sort(key=lambda r: self._lat.get(r[0], 1.0))
        query = dnsmsg.encode_query(host, qtype)
        last_err = None
        for name, dns_host, ip in order:
            conn = None
            try:
                t0 = time.time()
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
                rcode, answers = dnsmsg.parse_response(resp)
                dt = time.time() - t0
                self._note_latency(name, dt, ok=True)
                self.log.debug(f"DoH {name}: {host} rcode={rcode} in {dt:.2f}s")
                if rcode == 3:
                    raise VerifiedNegative(f"{host}: NXDOMAIN (verified via DoH {name})")
                if rcode != 0:
                    last_err = f"{name}: rcode {rcode}"
                    continue
                ips = dnsmsg.extract_ips(answers, qtype)
                ttl = _min_ttl(answers) or 120
                blocked = [ip for ip in ips if is_sinkhole(ip)]
                if blocked:
                    ips = [ip for ip in ips if not is_sinkhole(ip)]
                    self.log.debug(
                        f"DoH {name}: {host} returned a sinkhole/blocked answer "
                        f"({', '.join(blocked)}) — "
                        + ("trying next resolver" if not ips else "using remaining addresses"))
                    if not ips:
                        last_err = f"{name}: blocked (sinkhole)"
                        continue
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
                                conn = self._doh_session(name, dns_host, ip)
                                resp2 = conn.request(dns_host, follow)
                            _rc, ans2 = dnsmsg.parse_response(resp2)
                            if _rc == 3:
                                raise VerifiedNegative(f"{host}: NXDOMAIN (verified via DoH {name})")
                            ips = dnsmsg.extract_ips(ans2, qtype)
                            ttl = _min_ttl(ans2) or ttl
                            break
                with self._lock:
                    self.verbose_stats[name] = self.verbose_stats.get(name, 0) + 1
                if ips:
                    return ips, ttl
            except VerifiedNegative:
                raise
            except (OSError, ResolveError, ValueError, ssl.SSLError) as exc:
                self._note_latency(name, time.time() - t0, ok=False)
                last_err = f"{name}: {exc}"
                self.log.debug(f"DoH {name} failed: {exc}")
            finally:
                if conn is not None:
                    self._release_doh(conn)
        if last_err:
            # policy verdicts (sinkhole/empty) are expected for ad domains —
            # DEBUG keeps the detail without spamming WARN on every retry
            level = "debug" if ("sinkhole" in last_err or "rcode 0" in last_err
                                or "no answer" in last_err) else "warn"
            getattr(self.log, level)(f"DoH failed for {host}: {last_err}")
        return [], 120

    def _via_tcp_dns(self, host, qtype):
        query = dnsmsg.encode_query(host, qtype)
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
                rcode, answers = dnsmsg.parse_response(resp)
                if rcode == 3:
                    raise VerifiedNegative(f"{host}: NXDOMAIN (verified via TCP DNS {ip})")
                ips = dnsmsg.extract_ips(answers, qtype)
                if ips:
                    self.log.debug(f"TCP DNS {ip}: {host} -> {ips[0]}")
                    return ips, (_min_ttl(answers) or 120)
            except (OSError, ValueError) as exc:
                self.log.debug(f"TCP DNS {ip} failed: {exc}")
        return [], 120

    def _via_udp_dns(self, host, qtype):
        query = dnsmsg.encode_query(host, qtype)
        for ip in UDP_DNS_LAST_RESORT:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(3)
                s.sendto(query, (ip, 53))
                resp, _ = s.recvfrom(4096)
            except OSError as exc:
                # FIX: the old version leaked one UDP socket per timeout/error
                # (close() was only on the success path)
                s.close()
                self.log.debug(f"UDP DNS {ip} failed: {exc}")
                continue
            s.close()
            try:
                rcode, answers = dnsmsg.parse_response(resp)
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
            neg = sum(1 for e in self._neg_cache.values() if e > now)
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

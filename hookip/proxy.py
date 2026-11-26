"""HookIP local proxy: CONNECT tunnelling with fragmented TLS ClientHello,
plain-HTTP forwarding, PAC serving and live statistics."""
import fnmatch
import select
import socket
import threading
import time
from collections import deque

from . import tlsfrag
from .doh import Resolver, ResolveError

MAX_CONNECTIONS = 256


class ClientAbortError(OSError):
    """Client opened a connection but sent nothing / hung up early.
    Browsers do this constantly (speculative preconnects) — it is NOT a
    proxy failure and must not be counted or alarmed as one."""


class UpstreamDied(OSError):
    """The upstream server accepted the connection but died before ever
    sending anything back (mid-handshake reset after our 1.5s probe window).
    Retrying with a different fragmentation strategy can defeat it."""


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_conns = 0
        self.active = 0
        self.failed = 0
        self.blocked = 0
        self.up = 0
        self.down = 0
        self.domains = {}          # host -> [conns, up, down]
        self.samples = deque(maxlen=180)   # (up/s, down/s)
        self._last_up = 0
        self._last_down = 0
        self._t = time.time()

    def conn_open(self, host):
        with self.lock:
            self.total_conns += 1
            self.active += 1
            d = self.domains.setdefault(host, [0, 0, 0])
            d[0] += 1

    def conn_close(self, failed=False, blocked=False):
        with self.lock:
            self.active = max(0, self.active - 1)
            if blocked:
                self.blocked += 1
            elif failed:
                self.failed += 1

    def add(self, host, up=0, down=0):
        with self.lock:
            self.up += up
            self.down += down
            d = self.domains.get(host)
            if d:
                d[1] += up
                d[2] += down

    def tick(self):
        now = time.time()
        with self.lock:
            dt = max(0.001, now - self._t)
            self.samples.append(((self.up - self._last_up) / dt,
                                 (self.down - self._last_down) / dt))
            self._last_up, self._last_down, self._t = self.up, self.down, now

    def top_domains(self, k=15):
        with self.lock:
            if len(self.domains) > 600:
                # long sessions meet thousands of unique hosts; keeping every
                # one grows memory and makes this sort (2×/s) grind. Drop the
                # least-trafficked half when the table gets fat.
                keep = sorted(self.domains.items(),
                              key=lambda kv: -(kv[1][1] + kv[1][2]))[:300]
                self.domains = dict(keep)
            items = sorted(self.domains.items(), key=lambda kv: -(kv[1][1] + kv[1][2]))
            return [(h, c, u, d) for h, (c, u, d) in items[:k]]

    def totals(self):
        with self.lock:
            return (self.total_conns, self.active, self.up, self.down,
                    self.failed, self.blocked)

    def reset(self):
        with self.lock:
            self.total_conns = self.active = self.failed = self.blocked = 0
            self.up = self.down = 0
            self.domains.clear()
            self.samples.clear()
            self._last_up = self._last_down = 0
            self._t = time.time()


def is_excluded(host, patterns):
    host = host.lower().strip()
    for pat in patterns:
        pat = pat.strip().lower()
        if not pat:
            continue
        if fnmatch.fnmatch(host, pat) or fnmatch.fnmatch(host + ".", pat + "."):
            return True
    return False


def _set_keepalive(sock, idle=30, interval=5):
    """Aggressive TCP keepalive so a silently-dropped connection (NAT/DPI)
    surfaces as an error instead of a zombie relay."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, idle * 1000, interval * 1000))
    except OSError:
        pass


class ProxyServer:
    """Threaded proxy on 127.0.0.1:<port>."""

    def __init__(self, cfg, log, stats, pac_token):
        self.cfg = cfg
        self.log = log
        self.stats = stats
        self.pac_token = pac_token
        self.resolver = Resolver(cfg, log, chunk=cfg.fragment_size)
        self._strat_pref = {}                 # host -> strategy that last worked
        self._strat_cap = 512                 # keep the memory map bounded
        self.on_accept_death = None           # app hook: emergency restore
        self._blocked_seen = {}               # host -> last 'blocked/dead' log ts
        self._lsock = None
        self._accept_thread = None
        self._ticker = None
        self._conns = set()
        self._fails = {}                      # host -> expiry (recent full-failure)
        self._fails_lock = threading.Lock()
        self._tunnel_detail = {}              # host -> (strategy, dns_ms, conn_ms, segs, total_ms)
        self._detail_lock = threading.Lock()
        self._cut_seen = {}                   # host -> ts (mid-transfer cut dedupe)
        self._conns_lock = threading.Lock()
        self._conn_limit = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.running = False

    # ------------------------------------------------------------------
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Exclusive bind: WITHOUT this, Windows lets a second process bind the
        # same port and a stale/zombie listener silently steals the traffic
        # (clients connect to the old socket and hang or get dropped).
        # SO_REUSEADDR must NOT be used here for that reason.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except (AttributeError, OSError):
            pass
        try:
            sock.bind(("127.0.0.1", self.cfg.port))
        except OSError as exc:
            sock.close()
            raise OSError(
                f"port {self.cfg.port} is already in use by another program "
                f"({exc}) — change the port in Settings or close the other app") from exc
        sock.listen(128)
        self._lsock = sock
        self.running = True
        self._accept_thread = threading.Thread(target=self._accept_loop, name="hookip-accept", daemon=True)
        self._accept_thread.start()
        self._ticker = threading.Thread(target=self._tick_loop, name="hookip-tick", daemon=True)
        self._ticker.start()
        self.log.ok(f"Proxy listening on 127.0.0.1:{self.cfg.port}")

    def stop(self):
        self.running = False
        if self._lsock:
            try:
                self._lsock.close()
            except OSError:
                pass
        with self._conns_lock:
            conns = list(self._conns)
        for s in conns:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
        with self._conns_lock:
            self._conns.clear()
        self.log.info("Proxy stopped.")

    # ------------------------------------------------------------------
    def _accept_loop(self):
        # HARDENED: the listener dying silently is the worst failure mode —
        # Windows keeps pointing traffic at a port nobody serves and the
        # user's internet breaks while the app looks 'Running'. Per-connection
        # errors are contained; anything that kills the loop anyway triggers
        # the emergency callback so the system proxy is restored at once.
        try:
            while self.running:
                try:
                    csock, _addr = self._lsock.accept()
                except OSError:
                    # transient errors (e.g. a client resetting mid-connect)
                    # must not kill the accept loop; only stop when we closed
                    # the listener
                    if self.running and self._lsock and self._lsock.fileno() != -1:
                        time.sleep(0.05)
                        continue
                    break
                try:
                    with self._conns_lock:
                        self._conns.add(csock)
                    if not self._conn_limit.acquire(blocking=False):
                        with self._conns_lock:
                            self._conns.discard(csock)
                        try:
                            csock.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                          b"Connection: close\r\n\r\n")
                        except OSError:
                            pass
                        try:
                            csock.close()
                        except OSError:
                            pass
                        continue
                    threading.Thread(target=self._handle, args=(csock,),
                                     daemon=True).start()
                except Exception as exc:      # noqa: BLE001 — never kill the loop
                    self.log.error(f"connection accept failed: {exc}")
                    with self._conns_lock:
                        self._conns.discard(csock)
                    try:
                        csock.close()
                    except OSError:
                        pass
        finally:
            if self.running and self.on_accept_death:
                try:
                    self.on_accept_death()
                except Exception:
                    pass

    def _tick_loop(self):
        while self.running:
            self.stats.tick()
            time.sleep(1.0)

    def _note_fail(self, host, dpi=False):
        """Remember a fully-failed host so repeat connections skip the
        3-strategy retry storm. Infrastructural failures (timeout/refused/DNS
        blocked/client gone) cap immediately; a DPI reset gets ONE more full
        cycle (fragmentation may defeat it) before capping."""
        with self._fails_lock:
            prev = self._fails.get(host)
            count = prev[1] + 1 if (prev and prev[0] > time.time()) else 1
            capped = (not dpi) or count >= 2
            if len(self._fails) > 256:
                now = time.time()
                for h, entry in list(self._fails.items()):
                    if entry[0] < now:
                        del self._fails[h]
            self._fails[host] = (time.time() + 60, count, capped)
        if capped:
            self.log.debug(f"{host}: marked as repeat-failure — "
                           "next connections will try a single strategy")

    def _recent_fail(self, host):
        with self._fails_lock:
            entry = self._fails.get(host)
            return bool(entry and entry[0] > time.time() and entry[2])

    def _forget(self, csock):
        with self._conns_lock:
            self._conns.discard(csock)

    # ------------------------------------------------------------------
    def _handle(self, csock):
        ssock = None
        host = ""
        failed = False
        blocked = False
        opened = False
        try:
            csock.settimeout(30)
            head, complete = self._read_head(csock)
            if not complete:
                if len(head) >= 262144:
                    # headers too big to be a legitimate request — tell the
                    # client instead of silently closing (which looks like a
                    # dead proxy to apps like Steam)
                    try:
                        csock.sendall(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                                      b"Connection: close\r\n\r\n")
                    except OSError:
                        pass
                return   # empty or timed-out preconnect — normal, stay silent
            method, target, headers = self._parse_head(head)
            if method is None:
                return

            # PAC file served by ourselves, URL is random per session
            if method == "GET" and self.pac_token in target and target.lower().endswith(".pac"):
                self._serve_pac(csock)
                return

            if method == "CONNECT":
                hostport = target
                if ":" in hostport.rpartition(":")[0] or hostport.count(":") >= 1:
                    host, _, port_s = hostport.rpartition(":")
                    port = int(port_s) if port_s.isdigit() else 443
                else:
                    host, port = hostport, 443
                host = host.strip("[]").lower()
                opened = True
                ssock = self._tunnel(csock, host, port)
            elif method in ("GET", "POST", "HEAD", "OPTIONS"):
                opened = True
                ssock = self._plain_http(csock, head, method, target, headers)
            else:
                csock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
        except ClientAbortError as exc:
            # normal browser behaviour — inform, don't alarm, don't count
            self.log.info(f"{exc}")
        except (OSError, ResolveError, ValueError) as exc:
            msg = f"{exc}"
            if ("NXDOMAIN" in msg or "sinkhole" in msg or "rcode 2" in msg):
                # VERIFIED dead: resolvers confirm the name does not exist or
                # is deliberately sunk — a feature working, not a proxy failure
                blocked = True
                key = host or msg[:80]
                now_s = time.time()
                if len(self._blocked_seen) > 500:
                    self._blocked_seen.clear()
                if now_s - self._blocked_seen.get(key, 0) > 10:
                    self._blocked_seen[key] = now_s
                    self.log.info(f"{msg} — blocked/dead upstream, not a HookIP failure")
                else:
                    # parallel connections to the same dead host: log once
                    self.log.debug(f"{msg} — blocked/dead upstream (repeat within 10s, suppressed)")
            elif "no addresses for" in msg:
                # UNVERIFIED: no resolver even answered NXDOMAIN — this is a
                # network/DNS outage, not a dead domain. Never dress it up
                # as 'blocked upstream' (that would be a false positive).
                blocked = True
                self.log.warn(f"{msg} — DNS could not resolve this name "
                              "(network or DNS problem, or a very new domain)")
            elif isinstance(exc, ValueError):
                failed = True
                self.log.warn(f"Malformed request from client: {exc or 'unparseable target'}")
            else:
                failed = True
                self.log.warn(msg)   # messages are host:port-complete by design
        finally:
            if opened:
                self.stats.conn_close(failed, blocked)
            self._forget(csock)
            self._conn_limit.release()
            for s in (csock, ssock):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    # ------------------------------------------------------------------
    @staticmethod
    def _read_head(csock):
        """Read one HTTP request head. Returns (data, complete).

        The cap must be generous: Steam-style clients ship several KB of
        session cookies on EVERY request, and cookie-heavy browsers push a
        single request head well past 32 KB. The old 32 KB cap silently
        truncated such requests (no terminator, parsed anyway, upstream saw
        garbage) — that was the 'Steam sometimes refuses to connect' bug."""
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 262144:
                part = csock.recv(16384)
                if not part:
                    return (data, b"\r\n\r\n" in data)
                data += part
        except socket.timeout:
            return (data, False)
        return (data, b"\r\n\r\n" in data)

    @staticmethod
    def _parse_head(data):
        try:
            text = data.decode("latin1", "replace")
            line, _, rest = text.partition("\r\n")
            method, target, _ver = (line.split(" ") + ["", ""])[:3]
            headers = {}
            for hl in rest.split("\r\n"):
                if ":" in hl:
                    k, _, v = hl.partition(":")
                    k = k.strip().lower()
                    v = v.strip()
                    # duplicate headers are LEGAL and meaningful: two Cookie:
                    # lines carry different auth cookies (Steam does this) —
                    # overwriting the first silently logged people out
                    if k in headers:
                        sep = "; " if k in ("cookie", "authorization") else ", "
                        headers[k] = headers[k] + sep + v
                    else:
                        headers[k] = v
            return method.upper(), target, headers
        except ValueError:
            return None, "", {}

    def _serve_pac(self, csock):
        # direct (bypass) rules: local ranges plus the user's excluded list,
        # so domains HookIP would not touch never even enter the proxy
        rules = ["isPlainHostName(host)", "shExpMatch(host,'localhost')",
                 "shExpMatch(host,'127.*')", "shExpMatch(host,'10.*')",
                 "shExpMatch(host,'192.168.*')",
                 "shExpMatch(host,'172.16.*')", "shExpMatch(host,'172.17.*')",
                 "shExpMatch(host,'172.18.*')", "shExpMatch(host,'172.19.*')",
                 "shExpMatch(host,'172.20.*')", "shExpMatch(host,'172.21.*')",
                 "shExpMatch(host,'172.22.*')", "shExpMatch(host,'172.23.*')",
                 "shExpMatch(host,'172.24.*')", "shExpMatch(host,'172.25.*')",
                 "shExpMatch(host,'172.26.*')", "shExpMatch(host,'172.27.*')",
                 "shExpMatch(host,'172.28.*')", "shExpMatch(host,'172.29.*')",
                 "shExpMatch(host,'172.30.*')", "shExpMatch(host,'172.31.*')"]

        def esc(p):
            return p.replace("\\", "\\\\").replace("'", "\\'")

        # On restricted networks (network proxy required) DIRECT is blocked,
        # so user exclusions are deliberately NOT served as DIRECT —
        # everything must go through the chain or it breaks.
        net_up = str(getattr(self.cfg, "upstream_proxy", "") or "").strip()
        for pat in (() if net_up else (self.cfg.excluded or [])):
            pat = esc(str(pat).strip().lower())
            if not pat:
                continue
            if pat.startswith("*."):
                host = pat[2:]
                rules.append(f"shExpMatch(host,'*.{host}')")
                rules.append(f"dnsDomainIs(host, '{host}')")   # bare domain too
            elif "." in pat:
                rules.append(f"dnsDomainIs(host, '{pat}')")
                rules.append(f"host == '{pat}'")
            else:
                rules.append(f"shExpMatch(host,'{pat}')")
        pac = (
            "function FindProxyForURL(url, host) {\n"
            "  host = host.toLowerCase();\n"
            f"  if ({' || '.join(rules)}) return 'DIRECT';\n"
            "  return 'PROXY 127.0.0.1:%d; DIRECT';\n"
            "}\n" % self.cfg.port
        ).encode()
        csock.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n"
            b"Content-Length: " + str(len(pac)).encode() + b"\r\nConnection: close\r\n\r\n" + pac
        )

    # ------------------------------------------------------------------
    def _tunnel(self, csock, host, port):
        self.stats.conn_open(host)
        excl = is_excluded(host, self.cfg.excluded)
        # order: remembered winner for this host first, then the configured
        # default, then the rest — connections after a DPI fight start with
        # what actually worked last time
        pref = self._strat_pref.get(host)
        strategies = [s for s in (pref, self.cfg.strategy) if s]
        for alt in ("smart", "chunk", "random"):
            if alt not in strategies:
                strategies.append(alt)
        if excl:
            strategies = [strategies[0]]   # excluded hosts: single attempt, no retry noise
        elif self._recent_fail(host):
            # this host failed everything moments ago — one attempt instead of
            # re-burning 3 full strategy cycles on every new connection
            strategies = [strategies[0]]

        try:
            csock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError as exc:
            # client hung up before we could even acknowledge — WinError
            # 10053/10054 here used to be miscounted as a proxy failure
            raise ClientAbortError(
                f"{host}:{port} client aborted (gone before connect)") from exc
        csock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Sniff the client's first flight (normally the TLS ClientHello) ONCE.
        # Strategy retries reuse this captured data — the client cannot resend.
        csock.settimeout(10)
        first = b""
        while True:
            try:
                part = csock.recv(65536)
            except socket.timeout:
                break
            except OSError as exc:
                raise ClientAbortError(
                    f"{host}:{port} client aborted during handshake ({exc})") from exc
            if not part:
                break
            first += part
            if tlsfrag.hello_needed(first) == 0:
                break
        csock.settimeout(None)
        if not first:
            # client connected but sent nothing — normal browser preconnect,
            # not a proxy failure (do not count it in the Failed stat)
            raise ClientAbortError(f"{host}:{port} client sent no data (browser preconnect)")

        last_err = None
        attempt_errors = []
        for attempt, strategy in enumerate(strategies):
            try:
                ssock = self._tunnel_once(csock, host, port, strategy, first, excl)
                if len(self._strat_pref) >= self._strat_cap and host not in self._strat_pref:
                    # bounded memory: drop an arbitrary entry when full
                    self._strat_pref.pop(next(iter(self._strat_pref)), None)
                self._strat_pref[host] = strategy
                return ssock
            except ResolveError as exc:
                # DNS-level failure (NXDOMAIN / SERVFAIL / sinkhole-only):
                # re-fragmenting the ClientHello cannot make a name resolve,
                # so retrying strategies is pure waste — stop after one
                last_err = exc
                attempt_errors.append(f"{strategy}: {exc}")
                self.log.debug(f"{host}: attempt {attempt+1} ({strategy}) failed: {exc}")
                break
            except (OSError, ResolveError) as exc:
                last_err = exc
                attempt_errors.append(f"{strategy}: {exc}")
                self.log.debug(f"{host}: attempt {attempt+1} ({strategy}) failed: {exc}")
                if excl:
                    break
        # Only cap retries for infrastructural failures (timeout/refused/DNS
        # blocked/client gone). A DPI reset is exactly what fragmentation is
        # meant to defeat — keep full strategy retries for those.
        if "ClientHello" not in str(last_err):
            self._note_fail(host, dpi=False)
        else:
            self._note_fail(host, dpi=True)
        if isinstance(last_err, ResolveError):
            # DNS-level failure — strategies are irrelevant; surface the
            # resolver's own verdict (classified as blocked/dead upstream)
            raise last_err
        raise OSError(
            f"{host}:{port} failed — all {len(strategies)} strategies tried "
            f"({'; '.join(attempt_errors)})")

    def _connect_parallel(self, ips, port, timeout=3.0):
        """Happy Eyeballs (RFC 8305-style) with STAGGERED attempts: the first
        address connects immediately, further candidates launch 150 ms apart.
        The old version fired up to 6 SYNs at once, which CDN anti-flood
        (Cloudflare & co.) sometimes answers with resets — Steam-style apps
        then 'sometimes refuse to connect'."""
        socks = []
        errors = []
        lock = threading.Lock()
        won = threading.Event()

        def attempt(ip):
            try:
                s = socket.create_connection((ip, port), timeout=timeout)
                with lock:
                    if won.is_set():
                        s.close()
                        return
                    socks.append(s)
                    won.set()
            except OSError as exc:
                with lock:
                    errors.append(exc)

        candidates = ips[:6]
        threads = []
        deadline = time.time() + timeout + 0.5
        for i, ip in enumerate(candidates):
            with lock:
                if won.is_set():
                    break
            t = threading.Thread(target=attempt, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            if i < len(candidates) - 1:
                time.sleep(0.15)   # stagger: no SYN burst
        while not won.is_set() and time.time() < deadline:
            time.sleep(0.02)
            if not any(t.is_alive() for t in threads) and not socks:
                break
        won.set()
        if socks:
            # winner found — do NOT wait for losing attempts to finish; a hung
            # connect on a dead IP would otherwise delay the return (measured 2s)
            return socks[0]
        for t in threads:
            t.join(timeout=0.5)
        last = errors[-1] if errors else "timeout"
        raise OSError(f"all {len(candidates)} addresses failed ({last})")

    def _via_upstream_plain(self):
        """Open a connection to the network's own proxy for a plain-HTTP
        request (the request itself carries the absolute-URI target)."""
        up = str(getattr(self.cfg, "upstream_proxy", "") or "").strip()
        phost, _, pport = up.rpartition(":")
        pport_i = int(pport) if pport.isdigit() else 8080
        phost = phost.strip("[]")
        try:
            infos = socket.getaddrinfo(phost, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(dict.fromkeys(i[4][0] for i in infos))[:4]
        except OSError:
            ips = [phost]
        server = self._connect_parallel(ips, pport_i, timeout=5.0)
        self.log.debug(f"plain HTTP through network proxy {up}")
        return server

    def _via_upstream(self, host, port, timeout=5.0):
        """Restricted networks (offices/hotels/campuses) block direct internet
        and require every connection to go through the network's own proxy.
        Chain through it: CONNECT to the LAN proxy, then fragment our
        ClientHello INSIDE that tunnel — the LAN proxy sees only a TLS
        handshake to the target, its filtering cannot read the SNI either."""
        up = str(getattr(self.cfg, "upstream_proxy", "") or "").strip()
        phost, _, pport = up.rpartition(":")
        pport_i = int(pport) if pport.isdigit() else 8080
        phost = phost.strip("[]")
        try:
            infos = socket.getaddrinfo(phost, None, socket.AF_INET, socket.SOCK_STREAM)
            ips = list(dict.fromkeys(i[4][0] for i in infos))[:4]
        except OSError:
            ips = [phost]
        server = self._connect_parallel(ips, pport_i, timeout=timeout)
        try:
            server.settimeout(timeout)
            server.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp and len(resp) < 16384:
                part = server.recv(4096)
                if not part:
                    raise OSError("network proxy closed during CONNECT")
                resp += part
            line = resp.split(b"\r\n", 1)[0]
            if b" 200 " not in line:
                raise OSError(f"network proxy refused CONNECT to {host}:{port} "
                              f"({line.decode(errors='replace')[:80]})")
            server.settimeout(None)
            self.log.debug(f"{host}:{port} chained through network proxy {up}")
            return server
        except OSError:
            try:
                server.close()
            except OSError:
                pass
            raise

    def _tunnel_once(self, csock, host, port, strategy, first, exclude_frag=False):
        t0 = time.time()
        try:
            ips = self.resolver.resolve(host)
        except ResolveError:
            # re-raise unwrapped: DNS-level failures cannot be fixed by
            # re-fragmenting, so _tunnel must see them to skip the retries
            raise
        dns_ms = (time.time() - t0) * 1000
        t1 = time.time()
        upstream = str(getattr(self.cfg, "upstream_proxy", "") or "").strip()
        if upstream:
            try:
                server = self._via_upstream(host, port)
            except OSError as exc:
                raise OSError(f"{host}:{port} through network proxy {upstream}: {exc}") from exc
        else:
            try:
                server = self._connect_parallel(ips, port, timeout=3.0)
            except OSError as exc:
                kind = "timed out" if "timed out" in str(exc) else "refused/unreachable"
                raise OSError(
                    f"{host}:{port} could not connect ({len(ips)} address(es) tried, {kind})") from exc
        conn_ms = (time.time() - t1) * 1000
        server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            frag = (first[:1] == b"\x16") and not exclude_frag
            if frag:
                chunks = tlsfrag.fragment(first, strategy, self.cfg.fragment_size)
            elif first:
                chunks = [first]
            else:
                chunks = []
            t2 = time.time()
            for chunk in chunks:
                server.sendall(chunk)

            if first:
                # Detect immediate RST/close (DPI kill) → propagate to caller
                # so the outer loop can retry with a different strategy.
                # (Any error here propagates — swallowing it would relay on a
                # dead socket instead of retrying.)
                r, _, _ = select.select([server], [], [], 1.5)
                probe_ms = (time.time() - t2) * 1000
                if r:
                    probe = server.recv(1, socket.MSG_PEEK)
                    if probe == b"":
                        raise OSError(
                            f"{host}:{port} server closed right after ClientHello "
                            f"(possible DPI reset)")
            else:
                probe_ms = 0.0
        except OSError:
            try:
                server.close()
            except OSError:
                pass
            raise
        # detailed per-connection tunnel record (DEBUG + diagnostics)
        total_ms = (time.time() - t0) * 1000
        nseg = len(chunks) if frag else 0
        self.log.debug(
            f"{host}:{port} tunnel up via {strategy} in {total_ms:.0f}ms "
            f"(dns {dns_ms:.0f}ms · connect {conn_ms:.0f}ms · "
            f"{nseg} fragment{'s' if nseg != 1 else ''} · "
            f"hello-probe {probe_ms:.0f}ms)")
        with self._detail_lock:
            if len(self._tunnel_detail) > 256:
                self._tunnel_detail.clear()
            self._tunnel_detail[host] = (strategy, dns_ms, conn_ms, nseg, total_ms)
        self._relay(csock, server, host)
        return server

    def _relay(self, csock, server, host):
        up = down = 0
        started = time.time()
        sockets = [csock, server]
        _set_keepalive(csock)
        _set_keepalive(server)
        outcome = "ok"
        try:
            while self.running:
                r, _, _ = select.select(sockets, [], [], 30)
                if not r:
                    continue
                stop = False
                for s in r:
                    peer = server if s is csock else csock
                    try:
                        data = s.recv(65536)
                    except (OSError, ConnectionError):
                        # upstream dying here is a real failure; the client
                        # quitting is the client's own choice
                        outcome = "server" if s is server else "client"
                        stop = True
                        break
                    if not data:
                        if s is server:
                            # request sent but zero bytes ever came back and
                            # the upstream closed → died mid-handshake;
                            # anything else is a normal end of stream
                            outcome = "server" if (up and not down) else "ok"
                        else:
                            outcome = "client"
                        stop = True
                        break
                    try:
                        peer.sendall(data)
                    except OSError:
                        outcome = "client" if peer is csock else "server"
                        stop = True
                        break
                    if s is csock:
                        up += len(data)
                    else:
                        down += len(data)
                if stop:
                    break
        finally:
            self.stats.add(host, up=up, down=down)
            self.log.debug(
                f"{host} relay closed after {time.time()-started:.1f}s "
                f"({up} B up, {down} B down) [{outcome}]")
        if outcome == "server" and not down:
            # let the strategy loop retry — a mid-HANDSHAKE reset can be
            # defeated by a different fragmentation pattern. (A mid-transfer
            # death must NOT be retried: requests may already have been
            # processed upstream and a retry would duplicate them.)
            raise UpstreamDied(
                f"{host} upstream died mid-connection "
                f"({up} B sent, {down} B received back)")
        if outcome == "server":
            key = host
            now_s = time.time()
            if len(self._cut_seen) > 500:
                self._cut_seen.clear()
            if now_s - self._cut_seen.get(key, 0) > 30:
                self._cut_seen[key] = now_s
                self.log.warn(f"{host} upstream cut the connection mid-transfer "
                              f"({down} B received before the cut)")
            else:
                self.log.debug(f"{host} upstream cut mid-transfer "
                               f"({down} B) — repeat within 30s, suppressed")
        return outcome

    # ------------------------------------------------------------------
    def _plain_http(self, csock, head, method, target, headers):
        # absolute-URI form: http://host/path
        rest = target.split("://", 1)
        if len(rest) != 2:
            # count it so conn_close() stays balanced (otherwise 'Active now'
            # would drift negative on malformed requests)
            self.stats.conn_open("(malformed request)")
            csock.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            raise ValueError(f"non-absolute URI target: {target[:80]}")
        hostport = rest[1].split("/", 1)[0]
        if ":" in hostport:
            host, _, port_s = hostport.rpartition(":")
            port = int(port_s) if port_s.isdigit() else 80
        else:
            host, port = hostport, 80
        host = host.strip("[]").lower()
        self.stats.conn_open(host)
        path = "/" + (rest[1].split("/", 1)[1] if "/" in rest[1] else "")
        upstream = str(getattr(self.cfg, "upstream_proxy", "") or "").strip()
        if upstream:
            # plain HTTP through the network's own proxy: a proxy request IS
            # the original absolute-URI head — forward it verbatim
            try:
                server = self._via_upstream_plain()
            except OSError:
                try:
                    csock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                raise
            server.settimeout(30)
            out = [l for l in head.split(b"\r\n")
                   if l and not l.lower().startswith((b"proxy-connection:",
                                                      b"proxy-authorization:"))]
            payload = b"\r\n".join(out)
            sep = head.find(b"\r\n\r\n") + 4
            body = head[sep:]
            if headers.get("content-length"):
                try:
                    need = int(headers["content-length"]) - len(body)
                    while need > 0:
                        part = csock.recv(min(65536, need))
                        if not part:
                            break
                        body += part
                        need -= len(part)
                except (socket.timeout, OSError):
                    pass
            server.sendall(payload + b"\r\n\r\n" + body)
        else:
            ips = self.resolver.resolve(host)
            try:
                server = self._connect_parallel(ips, port, timeout=3.0)
            except OSError:
                try:
                    csock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                raise
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            server.settimeout(30)
            # rebuild request without proxy headers
            out = [f"{method} {path} HTTP/1.1"]
            for k, v in headers.items():
                if k in ("proxy-connection", "proxy-authorization"):
                    continue
                if k == "connection":
                    continue
                out.append(f"{k}: {v}")
            out.append("Connection: close")
            payload = head
            # forward already-buffered remainder + any body that follows
            sep = payload.find(b"\r\n\r\n") + 4
            body = payload[sep:]
            if headers.get("content-length"):
                try:
                    need = int(headers["content-length"]) - len(body)
                    while need > 0:
                        part = csock.recv(min(65536, need))
                        if not part:
                            break
                        body += part
                        need -= len(part)
                except (socket.timeout, OSError):
                    pass
            server.sendall(("\r\n".join(out) + "\r\n\r\n").encode("latin1") + body)
        # relay response until close
        up = down = 0
        try:
            while True:
                r, _, _ = select.select([server, csock], [], [], 30)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return server
                    other = csock if s is server else server
                    other.sendall(data)
                    if s is server:
                        down += len(data)
                    else:
                        up += len(data)
        finally:
            self.stats.add(host, up=up, down=down)
            try:
                server.close()
            except OSError:
                pass
        return server

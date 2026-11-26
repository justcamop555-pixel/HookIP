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


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_conns = 0
        self.active = 0
        self.failed = 0
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

    def conn_close(self, failed=False):
        with self.lock:
            self.active = max(0, self.active - 1)
            if failed:
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
            items = sorted(self.domains.items(), key=lambda kv: -(kv[1][1] + kv[1][2]))
            return [(h, c, u, d) for h, (c, u, d) in items[:k]]

    def totals(self):
        with self.lock:
            return (self.total_conns, self.active, self.up, self.down, self.failed)

    def reset(self):
        with self.lock:
            self.total_conns = self.active = self.failed = 0
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
        self._lsock = None
        self._accept_thread = None
        self._ticker = None
        self._conns = set()
        self._conns_lock = threading.Lock()
        self._conn_limit = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.running = False

    # ------------------------------------------------------------------
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.cfg.port))
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
        while self.running:
            try:
                csock, _addr = self._lsock.accept()
            except OSError:
                # transient errors (e.g. a client resetting mid-connect) must
                # not kill the accept loop; only stop when we closed the listener
                if self.running and self._lsock and self._lsock.fileno() != -1:
                    time.sleep(0.05)
                    continue
                break
            with self._conns_lock:
                self._conns.add(csock)
            if not self._conn_limit.acquire(blocking=False):
                with self._conns_lock:
                    self._conns.discard(csock)
                try:
                    csock.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
                try:
                    csock.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._handle, args=(csock,), daemon=True).start()

    def _tick_loop(self):
        while self.running:
            self.stats.tick()
            time.sleep(1.0)

    def _forget(self, csock):
        with self._conns_lock:
            self._conns.discard(csock)

    # ------------------------------------------------------------------
    def _handle(self, csock):
        ssock = None
        host = ""
        failed = False
        opened = False
        try:
            csock.settimeout(30)
            head = self._read_head(csock)
            if head is None:
                return
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
        except (OSError, ResolveError, ValueError) as exc:
            failed = True
            if host:
                self.log.warn(f"{host}: {exc}")
        finally:
            if opened:
                self.stats.conn_close(failed)
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
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 32768:
                part = csock.recv(8192)
                if not part:
                    return None
                data += part
        except socket.timeout:
            return None
        return data

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
                    headers[k.strip().lower()] = v.strip()
            return method.upper(), target, headers
        except ValueError:
            return None, "", {}

    def _serve_pac(self, csock):
        pac = (
            "function FindProxyForURL(url, host) {\n"
            "  if (isPlainHostName(host) || shExpMatch(host,'localhost') || shExpMatch(host,'127.*')) return 'DIRECT';\n"
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
        strategies = [self.cfg.strategy]
        for alt in ("smart", "chunk", "random"):
            if alt not in strategies:
                strategies.append(alt)
        if excl:
            strategies = [strategies[0]]   # excluded hosts: single attempt, no retry noise

        csock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
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
            if not part:
                break
            first += part
            if tlsfrag.hello_needed(first) == 0:
                break
        csock.settimeout(None)
        if not first:
            # client connected but sent nothing — close instead of relaying air
            raise OSError("client sent no data")

        last_err = None
        for attempt, strategy in enumerate(strategies):
            try:
                return self._tunnel_once(csock, host, port, strategy, first, excl)
            except (OSError, ResolveError) as exc:
                last_err = exc
                self.log.debug(f"{host}: attempt {attempt+1} ({strategy}) failed: {exc}")
                if excl or not first:
                    break
        raise OSError(f"{host}: tunnel failed ({last_err})")

    def _connect_parallel(self, ips, port, timeout=3.0):
        """Race connection attempts to several addresses at once (Happy
        Eyeballs). An unreachable first IP no longer costs its full serial
        timeout — the fastest reachable address wins."""
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

        candidates = ips[:4]
        threads = [threading.Thread(target=attempt, args=(ip,), daemon=True) for ip in candidates]
        for t in threads:
            t.start()
        deadline = time.time() + timeout + 0.5
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

    def _tunnel_once(self, csock, host, port, strategy, first, exclude_frag=False):
        ips = self.resolver.resolve(host)
        server = self._connect_parallel(ips, port, timeout=3.0)
        server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            frag = (first[:1] == b"\x16") and not exclude_frag
            if frag:
                chunks = tlsfrag.fragment(first, strategy, self.cfg.fragment_size)
                self.log.debug(f"{host}: {strategy} fragment, {len(chunks)} segments")
            elif first:
                chunks = [first]
            else:
                chunks = []
            for chunk in chunks:
                server.sendall(chunk)

            if first:
                # Detect immediate RST/close (DPI kill) → propagate to caller
                # so the outer loop can retry with a different strategy.
                # (Any error here propagates — swallowing it would relay on a
                # dead socket instead of retrying.)
                r, _, _ = select.select([server], [], [], 1.5)
                if r:
                    probe = server.recv(1, socket.MSG_PEEK)
                    if probe == b"":
                        raise OSError(f"{host}: server closed after ClientHello")
        except OSError:
            try:
                server.close()
            except OSError:
                pass
            raise

        self._relay(csock, server, host)
        return server

    def _relay(self, csock, server, host):
        up = down = 0
        started = time.time()
        sockets = [csock, server]
        _set_keepalive(csock)
        _set_keepalive(server)
        try:
            while self.running:
                r, _, _ = select.select(sockets, [], [], 30)
                if not r:
                    continue
                for s in r:
                    try:
                        data = s.recv(65536)
                    except (OSError, ConnectionError):
                        return
                    if not data:
                        return
                    other = server if s is csock else csock
                    try:
                        other.sendall(data)
                    except OSError:
                        return
                    if s is csock:
                        up += len(data)
                    else:
                        down += len(data)
        finally:
            self.stats.add(host, up=up, down=down)
            self.log.debug(
                f"{host} relay closed after {time.time()-started:.1f}s "
                f"({up} B up, {down} B down)")

    # ------------------------------------------------------------------
    def _plain_http(self, csock, head, method, target, headers):
        # absolute-URI form: http://host/path
        rest = target.split("://", 1)
        if len(rest) != 2:
            csock.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return None
        hostport = rest[1].split("/", 1)[0]
        if ":" in hostport:
            host, _, port_s = hostport.rpartition(":")
            port = int(port_s) if port_s.isdigit() else 80
        else:
            host, port = hostport, 80
        host = host.strip("[]").lower()
        self.stats.conn_open(host)
        path = "/" + (rest[1].split("/", 1)[1] if "/" in rest[1] else "")
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

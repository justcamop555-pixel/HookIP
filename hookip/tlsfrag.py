"""TLS ClientHello parsing and fragmentation strategies."""
import random
import struct


def parse_client_hello(data):
    """Parse the first TLS record if it is a ClientHello.

    Returns dict(total, sni_start, sni_end, host) with byte offsets absolute
    in *data*, or None when the payload is not a complete ClientHello record.
    """
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        reclen = int.from_bytes(data[3:5], "big")
        total = 5 + reclen
        if len(data) < total:
            return None
        body = data[5:total]
        if body[0] != 0x01:
            return None
        p = 4                    # past handshake header
        p += 2                   # client version
        p += 32                  # random
        if p + 1 > len(body):
            return None
        slen = body[p]           # session id length (1 byte)
        p += 1 + slen
        if p + 2 > len(body):
            return None
        clen = int.from_bytes(body[p:p + 2], "big")
        p += 2 + clen
        if p + 1 > len(body):
            return None
        comp = body[p]
        p += 1 + comp
        if p + 2 > len(body):
            return None
        ext_total = int.from_bytes(body[p:p + 2], "big")
        p += 2
        ext_end = min(p + ext_total, len(body))
        sni_start = sni_end = None
        host = None
        while p + 4 <= ext_end:
            etype, elen = struct.unpack(">HH", body[p:p + 4])
            p += 4
            if etype == 0 and elen >= 5 and p + elen <= len(body):
                # server_name_list: listlen(2) entrytype(1) namelen(2) name
                nlen = int.from_bytes(body[p + 3:p + 5], "big")
                sni_start = 5 + p + 5
                sni_end = sni_start + nlen
                host = body[p + 5:p + 5 + nlen].decode("ascii", "replace").lower()
            p += elen
        return {"total": total, "sni_start": sni_start, "sni_end": sni_end, "host": host}
    except (IndexError, ValueError, struct.error):
        return None


def hello_needed(data):
    """How many more bytes are needed for a complete first TLS record.
    0 = complete (or not TLS at all); None = cannot tell yet."""
    if not data:
        return 1
    if data[0] != 0x16:
        return 0
    if len(data) < 5:
        return 5 - len(data)
    reclen = int.from_bytes(data[3:5], "big")
    total = 5 + reclen
    if total > 17000:
        return 0
    return max(0, total - len(data))


def fragment(data, strategy="smart", chunk_size=2):
    """Split *data* (the sniffed ClientHello + any extra bytes) into TCP
    segments so that a DPI filter cannot reassemble the SNI in one piece.

    Returns a list of byte chunks to sendall() in order.
    """
    info = parse_client_hello(data)
    n = max(1, int(chunk_size))
    if info is None:
        return [data[i:i + 4096] for i in range(0, len(data), 4096)] or [b""]

    head = data[:info["total"]]
    rest = data[info["total"]:]

    if strategy == "chunk":
        parts = [head[i:i + n] for i in range(0, len(head), n)]
    elif strategy == "random":
        parts = []
        i = 0
        while i < len(head):
            limit = len(head) // 2 if info["sni_start"] is not None else len(head)
            if i < limit:
                size = random.randint(1, max(2, n))
            else:
                size = 1400
            parts.append(head[i:i + size])
            i += size
    else:  # "smart": keep everything before the SNI hostname intact,
        # then send the hostname itself in tiny segments.
        s, e = info["sni_start"], info["sni_end"]
        if s is None:
            parts = [head[i:i + n] for i in range(0, len(head), n)]
        else:
            parts = [head[:s]] if s else []
            for i in range(s, e, n):
                parts.append(head[i:min(i + n, e)])
            if e < len(head):
                parts.append(head[e:])
    if rest:
        parts.append(rest)
    return [p for p in parts if p]

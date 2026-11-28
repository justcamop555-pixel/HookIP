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
        # degenerate or oversized records are not real client hellos —
        # reject so fragment() falls back to the 4096-byte split instead
        # of slicing nonsense offsets (hello_needed already stops waiting
        # past 17000, so a record claiming more is garbage/truncated)
        if reclen == 0 or total > 17000:
            return None
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
                if p + 5 + nlen <= len(body):
                    sni_start = 5 + p + 5
                    sni_end = sni_start + nlen
                    host = body[p + 5:p + 5 + nlen].decode("ascii", "replace").lower()
                else:
                    # malformed name length (would read past the record):
                    # treat as no SNI rather than producing a short host
                    # with an out-of-range sni_end; keep parsing
                    sni_start = sni_end = None
                    host = None
            p += elen
        return {"total": total, "sni_start": sni_start, "sni_end": sni_end, "host": host}
    except (IndexError, ValueError, struct.error):
        return None


def hello_needed(data):
    """How many more bytes are needed for a complete first TLS record.

    Returns a positive int (at least that many more bytes needed) or
    0 (the record is complete, the data is not TLS at all, or the
    declared record length is oversized garbage — stop waiting).
    It never returns None."""
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
    try:
        n = min(255, max(1, int(chunk_size)))   # 255 = config ceiling: an
        # unbounded size (hand-edited settings, a buggy caller) would send
        # the whole head in ONE segment — silently disabling the bypass
    except (TypeError, ValueError):
        n = 2
    if info is None:
        return [data[i:i + 4096] for i in range(0, len(data), 4096)] or [b""]

    head = data[:info["total"]]
    rest = data[info["total"]:]
    has_sni = info["sni_start"] is not None

    if not has_sni:
        # nothing to hide (IP-literal hosts, ECH-only edge cases): every
        # strategy sends the record whole — chopping an SNI-less hello
        # into hundreds of tiny segments only adds latency
        parts = [head]
    elif strategy == "chunk":
        parts = [head[i:i + n] for i in range(0, len(head), n)]
    elif strategy == "random":
        # random small sizes from offset 0 THROUGH the whole SNI (the
        # hostname can sit in the second half of the record — Chrome
        # randomizes extension order), then big segments for the rest.
        # The old limit len(head)//2 missed an SNI placed late.
        parts = []
        s, e = info["sni_start"], info["sni_end"]
        i = 0
        while i < e:
            size = min(random.randint(1, max(2, n)), e - i)
            parts.append(head[i:i + size])
            i += size
        while i < len(head):
            size = min(1400, len(head) - i)
            parts.append(head[i:i + size])
            i += size
    else:  # "smart": keep everything before the SNI hostname intact,
        # then send the hostname itself in tiny segments. Sizes vary per
        # connection (1..n bytes) so consecutive connections do not share
        # one identical segment fingerprint.
        s, e = info["sni_start"], info["sni_end"]
        parts = [head[:s]] if s else []
        i = s
        while i < e:
            size = random.randint(1, n) if n > 1 else 1
            parts.append(head[i:min(i + size, e)])
            i += size
        if e < len(head):
            parts.append(head[e:])
    if rest:
        parts.append(rest)
    return [p for p in parts if p]

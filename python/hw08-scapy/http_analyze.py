"""
Parse HTTP requests and responses from a pcap file.

Prints method, URL, selected headers and body preview.
Decompresses gzip/deflate response bodies when Content-Encoding is set.
Optional --needle searches for a substring in message bodies.
"""

from __future__ import annotations

import argparse
import gzip
import re
import zlib
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, Raw, rdpcap

HTTP_REQ = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/1\.[01]")
HTTP_RESP = re.compile(rb"^HTTP/1\.[01]\s+(\d{3})")


def split_headers_body(blob: bytes) -> tuple[dict[str, str], bytes]:
    if b"\r\n\r\n" in blob:
        head, body = blob.split(b"\r\n\r\n", 1)
    elif b"\n\n" in blob:
        head, body = blob.split(b"\n\n", 1)
    else:
        return {}, blob

    headers: dict[str, str] = {}
    lines = head.split(b"\r\n" if b"\r\n" in head else b"\n")
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1", "replace").strip().lower()] = value.decode(
            "latin-1", "replace"
        ).strip()
    return headers, body


def decompress_body(headers: dict[str, str], body: bytes) -> bytes:
    encoding = headers.get("content-encoding", "").lower()
    if not body:
        return body
    try:
        if "gzip" in encoding:
            return gzip.decompress(body)
        if "deflate" in encoding:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except OSError:
        return body
    return body


def flow_key(pkt) -> tuple:
    return (pkt[IP].src, int(pkt[TCP].sport), pkt[IP].dst, int(pkt[TCP].dport))


def reassemble_streams(packets):
    buckets: dict[tuple, list] = defaultdict(list)
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        buckets[flow_key(pkt)].append(pkt)

    streams = []
    for key, pkts in buckets.items():
        pkts.sort(key=lambda p: int(p[TCP].seq))
        data = b"".join(bytes(p[Raw].load) for p in pkts)
        streams.append((key, data))
    return streams


def iter_http_messages(data: bytes):
    parts = re.split(
        rb"(?=(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|HTTP/1\.[01]) )",
        data,
    )
    for part in parts:
        part = part.lstrip()
        if part:
            yield part


def analyze(path: Path, needle: str | None = None) -> None:
    packets = rdpcap(str(path))
    print(f"File: {path}")
    print(f"Packets: {len(packets)}")
    streams = reassemble_streams(packets)
    print(f"TCP streams with payload: {len(streams)}\n")

    needle_b = needle.encode("utf-8", "replace") if needle else None
    index = 0

    for key, data in streams:
        src, sport, dst, dport = key
        for msg in iter_http_messages(data):
            req = HTTP_REQ.match(msg)
            resp = HTTP_RESP.match(msg)
            headers, body = split_headers_body(msg)
            body = decompress_body(headers, body)

            index += 1
            print("=" * 72)
            print(f"#{index}  {src}:{sport} -> {dst}:{dport}")

            if req:
                method = req.group(1).decode()
                target = req.group(2).decode("latin-1", "replace")
                print(f"REQUEST  {method} {target}")
                if "?" in target:
                    path_part, query = target.split("?", 1)
                    print(f"  path:  {path_part}")
                    print(f"  query: {query}")
            elif resp:
                print(f"RESPONSE status={resp.group(1).decode()}")
            else:
                print("Unrecognized HTTP start line")

            for name in (
                "host",
                "content-type",
                "content-encoding",
                "content-length",
                "cookie",
                "set-cookie",
                "location",
                "user-agent",
                "referer",
            ):
                if name in headers:
                    print(f"  {name}: {headers[name]}")

            preview = body[:500]
            text = preview.decode("utf-8", "replace")
            print(f"  body_len={len(body)}")
            print(f"  body_preview:\n{text!r}\n")

            if needle_b and needle_b in body:
                pos = body.find(needle_b)
                ctx = body[max(0, pos - 40) : pos + len(needle_b) + 40]
                print(f"  needle {needle!r} found")
                print(f"  context: {ctx!r}")

    if index == 0:
        print("No HTTP messages found. Check that the pcap contains plaintext HTTP.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze HTTP from a pcap file")
    parser.add_argument("pcap", type=Path, help="Path to pcap/pcapng")
    parser.add_argument("--needle", default=None, help="Substring to search in bodies")
    args = parser.parse_args()
    if not args.pcap.exists():
        raise SystemExit(f"File not found: {args.pcap}")
    analyze(args.pcap, args.needle)


if __name__ == "__main__":
    main()

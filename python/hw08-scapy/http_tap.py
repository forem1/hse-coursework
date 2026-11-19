"""
Local HTTP tap for lab use.

Browser -> 127.0.0.1:8080 -> Gruyere on 127.0.0.1:8008

Stores plaintext HTTP request/response payloads in a pcap file so that
http_analyze.py can inspect them. Needed on Windows when loopback sniffing
does not capture localhost traffic reliably.

Stop by creating a sibling .stop file next to the pcap, or with Ctrl+C.
"""

from __future__ import annotations

import argparse
import atexit
import socket
import threading
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

SEQ = {"c": 1000, "s": 5000}
LOCK = threading.Lock()
PACKETS = []
OUT_PCAP: Path | None = None


def save_pcap() -> None:
    if OUT_PCAP is None:
        return
    with LOCK:
        packets = list(PACKETS)
    wrpcap(str(OUT_PCAP), packets)
    print(f"Saved {len(packets)} records to {OUT_PCAP.resolve()}")


def add_record(src: str, sport: int, dst: str, dport: int, payload: bytes, who: str) -> None:
    with LOCK:
        if who == "c":
            seq = SEQ["c"]
            SEQ["c"] += max(len(payload), 1)
            ack = SEQ["s"]
        else:
            seq = SEQ["s"]
            SEQ["s"] += max(len(payload), 1)
            ack = SEQ["c"]
        packet = (
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack)
            / Raw(load=payload)
        )
        PACKETS.append(packet)


def recv_http(conn: socket.socket) -> bytes:
    data = b""
    conn.settimeout(2.0)
    while True:
        try:
            chunk = conn.recv(65535)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" not in data:
            continue
        headers, body = data.split(b"\r\n\r\n", 1)
        content_length = 0
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip() or 0)
        while len(body) < content_length:
            more = conn.recv(65535)
            if not more:
                break
            body += more
        return headers + b"\r\n\r\n" + body
    return data


def handle(client: socket.socket, addr, upstream_host: str, upstream_port: int) -> None:
    try:
        request = recv_http(client)
        if not request:
            return

        lines = request.split(b"\r\n")
        rebuilt = []
        for line in lines:
            if line.lower().startswith(b"host:"):
                rebuilt.append(f"Host: {upstream_host}:{upstream_port}".encode())
            else:
                rebuilt.append(line)
        request = b"\r\n".join(rebuilt)

        add_record("127.0.0.1", addr[1], "127.0.0.1", upstream_port, request, "c")

        upstream = socket.create_connection((upstream_host, upstream_port), timeout=5)
        upstream.sendall(request)
        upstream.settimeout(3.0)
        response = b""
        while True:
            try:
                chunk = upstream.recv(65535)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
        upstream.close()

        if response:
            add_record("127.0.0.1", upstream_port, "127.0.0.1", addr[1], response, "s")
            client.sendall(response)
    except Exception as exc:
        try:
            client.sendall(f"HTTP/1.0 502 Bad Gateway\r\n\r\n{exc}".encode())
        except Exception:
            pass
    finally:
        client.close()


def main() -> None:
    global OUT_PCAP

    parser = argparse.ArgumentParser(description="HTTP tap to Gruyere with pcap output")
    parser.add_argument("--listen", type=int, default=8080)
    parser.add_argument("--upstream-port", type=int, default=8008)
    parser.add_argument("--pcap", default="HW08_tap.pcap")
    args = parser.parse_args()

    OUT_PCAP = Path(args.pcap)
    stop_file = OUT_PCAP.with_suffix(".stop")
    if stop_file.exists():
        stop_file.unlink()
    atexit.register(save_pcap)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.listen))
    server.listen(20)
    server.settimeout(1.0)

    print(f"Listening on http://127.0.0.1:{args.listen}/")
    print(f"Upstream 127.0.0.1:{args.upstream_port}")
    print(f"Writing {OUT_PCAP}")
    print(f"Stop: create {stop_file.name} or press Ctrl+C")

    try:
        while True:
            if stop_file.exists():
                print("Stop file found")
                break
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            threading.Thread(
                target=handle,
                args=(client, addr, "127.0.0.1", args.upstream_port),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("Interrupted")
    finally:
        server.close()
        save_pcap()
        if stop_file.exists():
            stop_file.unlink()


if __name__ == "__main__":
    main()

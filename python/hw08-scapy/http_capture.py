"""
Capture TCP traffic with Scapy and save it to a pcap file.

Run as Administrator on Windows (Npcap required).
Use a BPF filter that matches the HTTP port of the target (for local Gruyere: 8008 or 8080).
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP, Raw, sniff, wrpcap


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture TCP traffic to a pcap file")
    parser.add_argument("-i", "--iface", default=None, help="Network interface name")
    parser.add_argument(
        "-f",
        "--filter",
        default="tcp port 80 or tcp port 8008 or tcp port 8080",
        help="BPF capture filter",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop after N packets (0 means until Ctrl+C)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output pcap path",
    )
    args = parser.parse_args()

    out = Path(args.output or f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
    packets = []

    def on_packet(pkt) -> None:
        packets.append(pkt)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            print(
                f"{src} {pkt[TCP].sport}->{pkt[TCP].dport} "
                f"{len(pkt[Raw].load)} bytes"
            )

    print(f"Listening filter={args.filter!r} iface={args.iface!r}")
    print("Press Ctrl+C to stop")
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=on_packet,
            store=False,
            count=args.count,
        )
    except KeyboardInterrupt:
        print("Stopped")

    if not packets:
        print("No packets captured")
        return

    wrpcap(str(out), packets)
    print(f"Saved {len(packets)} packets to {out.resolve()}")


if __name__ == "__main__":
    main()

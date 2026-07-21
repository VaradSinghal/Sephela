#!/usr/bin/env python3
"""Convert PCAP to structured NetworkTrace JSON for the dynamic engine.

Usage: python3 pcap_to_json.py <input.pcap> <output.json>

Uses dpkt (if available) or falls back to a basic binary parser for
common protocols. For production, Suricata EVE JSON is the preferred
input format (bypasses this script entirely).
"""

from __future__ import annotations

import json
import socket
import struct
import sys
from typing import Any


def parse_pcap_basic(pcap_bytes: bytes) -> dict[str, Any]:
    """Minimal PCAP parser — extracts IP src/dst and ports.

    This is a fallback for environments without dpkt/scapy.
    For production use, feed Suricata EVE JSON directly to the engine.

    Args:
        pcap_bytes: Raw PCAP file contents.

    Returns:
        A NetworkTrace-compatible dict.
    """
    connections: list[dict[str, Any]] = []
    dns_queries: list[dict[str, Any]] = []
    total_sent = 0
    total_recv = 0

    # PCAP global header: 24 bytes
    if len(pcap_bytes) < 24:
        return _empty_trace()

    magic = struct.unpack("<I", pcap_bytes[:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        return _empty_trace()  # not a PCAP

    offset = 24
    pkt_num = 0

    while offset + 16 <= len(pcap_bytes):
        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{endian}IIII", pcap_bytes[offset : offset + 16]
        )
        offset += 16
        pkt_data = pcap_bytes[offset : offset + incl_len]
        offset += incl_len
        pkt_num += 1

        # Skip if too small for Ethernet + IP
        if len(pkt_data) < 34:
            continue

        # Ethernet header (14 bytes) → IP header
        eth_type = struct.unpack("!H", pkt_data[12:14])[0]
        if eth_type != 0x0800:  # IPv4 only
            continue

        ip_header = pkt_data[14:]
        ihl = (ip_header[0] & 0x0F) * 4
        protocol = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])

        src_port = 0
        dst_port = 0
        proto_name = "tcp"

        if protocol == 6 and len(ip_header) >= ihl + 4:  # TCP
            src_port, dst_port = struct.unpack("!HH", ip_header[ihl : ihl + 4])
            proto_name = "tcp"
            total_sent += orig_len
        elif protocol == 17 and len(ip_header) >= ihl + 4:  # UDP
            src_port, dst_port = struct.unpack("!HH", ip_header[ihl : ihl + 4])
            proto_name = "udp"

            # Basic DNS detection
            if dst_port == 53 and len(ip_header) > ihl + 12:
                dns_queries.append({
                    "timestamp_ms": ts_sec * 1000 + ts_usec // 1000,
                    "query": f"dns_query_{pkt_num}",
                    "query_type": "A",
                    "response_ips": [],
                })
        else:
            continue

        connections.append({
            "timestamp_ms": ts_sec * 1000 + ts_usec // 1000,
            "protocol": proto_name,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "dst_hostname": None,
            "bytes_sent": orig_len,
            "bytes_recv": 0,
            "metadata": {},
        })

    return {
        "version": "1.0",
        "connections": connections,
        "dns_queries": dns_queries,
        "http_requests": [],
        "tls_handshakes": [],
        "total_bytes_sent": total_sent,
        "total_bytes_recv": total_recv,
    }


def _empty_trace() -> dict[str, Any]:
    return {
        "version": "1.0",
        "connections": [],
        "dns_queries": [],
        "http_requests": [],
        "tls_handshakes": [],
        "total_bytes_sent": 0,
        "total_bytes_recv": 0,
    }


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.pcap> <output.json>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        pcap_bytes = f.read()

    result = parse_pcap_basic(pcap_bytes)

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"Parsed {len(result['connections'])} connections → {sys.argv[2]}")


if __name__ == "__main__":
    main()

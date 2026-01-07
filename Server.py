#!/usr/bin/env python3
"""
Blackjack Server (Dealer) - partial implementation (~25%)

What is implemented:
- UDP offer broadcast (every 1 second) on port 13122 (broadcast)
- TCP server accept loop
- Request message parsing + validation (magic cookie, message type, rounds, team name)
- Session scaffolding (TODO: game logic + payload exchange)

Protocol constants (from assignment):
Offer (UDP):   cookie(4) type(1=0x2) tcp_port(2) server_name(32)
Request (TCP): cookie(4) type(1=0x3) rounds(1)    team_name(32)
Payload (TCP): cookie(4) type(1=0x4) decision(5)  result(1) rank(2) suit(1)
"""

import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

MAGIC_COOKIE = 0xabcddcba

MSG_OFFER   = 0x2
MSG_REQUEST = 0x3
MSG_PAYLOAD = 0x4

UDP_DISCOVERY_PORT = 13122
OFFER_INTERVAL_SEC = 1.0

# Network byte order (big-endian) formats
OFFER_FMT   = "!IBH32s"    # cookie(u32) type(u8) tcp_port(u16) server_name(32 bytes)
REQUEST_FMT = "!IBB32s"    # cookie(u32) type(u8) rounds(u8)    team_name(32 bytes)
PAYLOAD_FMT = "!IB5sBHB"   # cookie(u32) type(u8) decision(5) result(u8) rank(u16) suit(u8)

OFFER_SIZE   = struct.calcsize(OFFER_FMT)    # 39
REQUEST_SIZE = struct.calcsize(REQUEST_FMT)  # 38
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FMT)  # 14


@dataclass
class ClientRequest:
    rounds: int
    team_name: str


def _pad_32_ascii(s: str) -> bytes:
    raw = (s or "").encode("ascii", errors="ignore")[:32]
    return raw.ljust(32, b"\x00")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a TCP socket or raise ConnectionError."""
    chunks = []
    remaining = n
    while remaining > 0:
        data = sock.recv(remaining)
        if not data:
            raise ConnectionError("Client disconnected while receiving data.")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def parse_request(data: bytes) -> ClientRequest:
    if len(data) != REQUEST_SIZE:
        raise ValueError(f"Bad request length: got {len(data)}, expected {REQUEST_SIZE}")

    cookie, mtype, rounds, team_raw = struct.unpack(REQUEST_FMT, data)

    if cookie != MAGIC_COOKIE:
        raise ValueError(f"Bad magic cookie: {cookie:#x}")
    if mtype != MSG_REQUEST:
        raise ValueError(f"Bad message type: {mtype:#x}")
    if rounds < 1:
        raise ValueError("Rounds must be >= 1")

    team_name = team_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
    if not team_name:
        team_name = "UnknownTeam"

    return ClientRequest(rounds=rounds, team_name=team_name)


def build_offer(tcp_port: int, server_name: str) -> bytes:
    return struct.pack(
        OFFER_FMT,
        MAGIC_COOKIE,
        MSG_OFFER,
        tcp_port,
        _pad_32_ascii(server_name),
    )


def offer_broadcaster(stop_event: threading.Event, tcp_port: int, server_name: str) -> None:
    """
    Broadcasts offer packets via UDP once per second.
    """
    offer = build_offer(tcp_port, server_name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        dest = ("<broadcast>", UDP_DISCOVERY_PORT)
        while not stop_event.is_set():
            try:
                sock.sendto(offer, dest)
                # Keep prints simple (your assignment likely wants runtime logs)
                print(f"[UDP] Sent offer (tcp_port={tcp_port}) to {dest}")
            except OSError as e:
                print(f"[UDP] Broadcast error: {e}")
            stop_event.wait(OFFER_INTERVAL_SEC)
    finally:
        sock.close()


def send_payload(conn: socket.socket, decision5: bytes, result: int, rank: int, suit: int) -> None:
    """
    Sends a payload message (TCP).
    decision5 must be exactly 5 bytes (b"Hittt" or b"Stand" per spec, but server may echo).
    result: 0=not over, 1=tie, 2=loss, 3=win
    rank: 1..13 (in 2 bytes)
    suit: 0..3 (H D C S ordering per spec)
    """
    if len(decision5) != 5:
        raise ValueError("decision5 must be exactly 5 bytes")
    msg = struct.pack(PAYLOAD_FMT, MAGIC_COOKIE, MSG_PAYLOAD, decision5, result, rank, suit)
    conn.sendall(msg)


def handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    """
    Handles a single client session (partial).
    """
    print(f"[TCP] Client connected: {addr}")

    try:
        # 1) Read client request
        req_raw = recv_exact(conn, REQUEST_SIZE)
        req = parse_request(req_raw)
        print(f"[TCP] Request: team='{req.team_name}', rounds={req.rounds}")

        # 2) TODO: Full blackjack game loop.
        # For now, just demonstrate we can respond with *a valid payload* and then close.
        #
        # NOTE: This payload is a placeholder.
        # We set result=0 (not over), and send a dummy card (rank=1, suit=0).
        # A real implementation will:
        # - shuffle deck
        # - deal player/dealer cards
        # - exchange Hit/Stand decisions
        # - compute result and update stats
        send_payload(conn, b"Stand", 0x0, rank=1, suit=0)
        print("[TCP] Sent placeholder payload. (Game logic not implemented yet)")

    except (ValueError, ConnectionError, OSError) as e:
        print(f"[TCP] Session error with {addr}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        print(f"[TCP] Client disconnected: {addr}")


def run_server(host: str = "0.0.0.0", tcp_port: int = 0, server_name: str = "BlackjackServer") -> None:
    """
    Starts TCP server + UDP broadcaster.
    If tcp_port=0, OS chooses an ephemeral port (still broadcasted correctly).
    """
    # TCP listening socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((host, tcp_port))
    listen_sock.listen(5)

    actual_port = listen_sock.getsockname()[1]
    print(f"[TCP] Listening on {host}:{actual_port}")

    # UDP offer broadcaster thread
    stop_event = threading.Event()
    t = threading.Thread(
        target=offer_broadcaster,
        args=(stop_event, actual_port, server_name),
        daemon=True,
    )
    t.start()
    print(f"[UDP] Broadcasting offers as '{server_name}' on port {UDP_DISCOVERY_PORT}")

    try:
        while True:
            conn, addr = listen_sock.accept()
            # Simple approach: handle sequentially.
            # TODO: For multi-client support, spawn a thread per connection.
            handle_client(conn, addr)
    except KeyboardInterrupt:
        print("\n[SYS] Shutting down...")
    finally:
        stop_event.set()
        try:
            listen_sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    # TODO: choose a name that matches your team / assignment guidelines
    run_server(server_name="TeamDealer")

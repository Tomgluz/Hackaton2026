"""
Blackjack Server (Dealer) - continued implementation

Implements:
- UDP offer broadcast every 1 second (port 13122)
- TCP accept loop (threaded per client)
- Request parsing/validation
- Blackjack round loop (deal -> player Hit/Stand -> dealer play -> outcome)
- TCP payload exchange using the given binary formats

Protocol (per assignment):
Offer (UDP):   cookie(4) type(1=0x2) tcp_port(2) server_name(32)
Request (TCP): cookie(4) type(1=0x3) rounds(1)    team_name(32)
Payload (TCP): cookie(4) type(1=0x4) decision(5)  result(1) rank(2) suit(1)

Notes:
- decision field in server->client payload is used as a small "tag" (5 bytes),
  while client->server must send decision "Hittt" or "Stand".
- Ace is treated as 11 only (per your instructions document).
"""

import random
import socket
import struct
import threading
from dataclasses import dataclass
from typing import List, Tuple

MAGIC_COOKIE = 0xabcddcba

MSG_OFFER = 0x2
MSG_REQUEST = 0x3
MSG_PAYLOAD = 0x4

UDP_DISCOVERY_PORT = 13122
OFFER_INTERVAL_SEC = 1.0

# Network byte order (big-endian)
OFFER_FMT = "!IBH32s"      # cookie(u32) type(u8) tcp_port(u16) server_name(32)
REQUEST_FMT = "!IBB32s"    # cookie(u32) type(u8) rounds(u8)    team_name(32)
PAYLOAD_FMT = "!IB5sBHB"   # cookie(u32) type(u8) decision(5) result(u8) rank(u16) suit(u8)

OFFER_SIZE = struct.calcsize(OFFER_FMT)      # 39
REQUEST_SIZE = struct.calcsize(REQUEST_FMT)  # 38
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FMT)  # 14

# Result codes (server round result)
RES_NOT_OVER = 0x0
RES_TIE = 0x1
RES_LOSS = 0x2
RES_WIN = 0x3

# Card suits order per spec: H D C S -> 0,1,2,3
SUITS = [0, 1, 2, 3]
RANKS = list(range(1, 14))  # 1..13


@dataclass(frozen=True)
class Card:
    rank: int  # 1..13
    suit: int  # 0..3


@dataclass
class ClientRequest:
    rounds: int
    team_name: str


def _pad_32_ascii(s: str) -> bytes:
    raw = (s or "").encode("ascii", errors="ignore")[:32]
    return raw.ljust(32, b"\x00")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a TCP socket or raise ConnectionError."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Client disconnected while receiving data.")
        buf += chunk
    return buf


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

    return ClientRequest(rounds=int(rounds), team_name=team_name)


def build_offer(tcp_port: int, server_name: str) -> bytes:
    return struct.pack(
        OFFER_FMT,
        MAGIC_COOKIE,
        MSG_OFFER,
        tcp_port,
        _pad_32_ascii(server_name),
    )


def offer_broadcaster(stop_event: threading.Event, tcp_port: int, server_name: str) -> None:
    """Broadcast offer packets via UDP every second."""
    offer = build_offer(tcp_port, server_name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        dest = ("<broadcast>", UDP_DISCOVERY_PORT)
        while not stop_event.is_set():
            try:
                sock.sendto(offer, dest)
                print(f"[UDP] Sent offer (tcp_port={tcp_port})")
            except OSError as e:
                print(f"[UDP] Broadcast error: {e}")
            stop_event.wait(OFFER_INTERVAL_SEC)
    finally:
        sock.close()


def send_payload(conn: socket.socket, tag5: bytes, result: int, card: Card) -> None:
    """
    Sends a payload message (TCP).
    tag5: exactly 5 bytes (a small tag; client->server uses "Hittt"/"Stand")
    result: 0=not over, 1=tie, 2=loss, 3=win
    card: card rank/suit for this message
    """
    if len(tag5) != 5:
        raise ValueError("tag5 must be exactly 5 bytes")
    msg = struct.pack(PAYLOAD_FMT, MAGIC_COOKIE, MSG_PAYLOAD, tag5, result, card.rank, card.suit)
    conn.sendall(msg)


def recv_client_decision(conn: socket.socket) -> str:
    """
    Receives a client payload and returns decision string ("Hittt" or "Stand").
    Ignores other fields.
    """
    raw = recv_exact(conn, PAYLOAD_SIZE)
    cookie, mtype, decision5, _result, _rank, _suit = struct.unpack(PAYLOAD_FMT, raw)

    if cookie != MAGIC_COOKIE:
        raise ValueError(f"Bad magic cookie in payload: {cookie:#x}")
    if mtype != MSG_PAYLOAD:
        raise ValueError(f"Bad payload message type: {mtype:#x}")

    decision = decision5.decode("ascii", errors="ignore")
    return decision


# -----------------------------
# Blackjack logic
# -----------------------------

def new_shuffled_deck() -> List[Card]:
    deck = [Card(rank=r, suit=s) for s in SUITS for r in RANKS]
    random.shuffle(deck)
    return deck


def card_value(rank: int) -> int:
    if rank == 1:
        return 11  # Ace as 11 (per spec in your doc)
    if 2 <= rank <= 10:
        return rank
    return 10  # J/Q/K


def hand_total(hand: List[Card]) -> int:
    return sum(card_value(c.rank) for c in hand)


def deal_one(deck: List[Card]) -> Card:
    if not deck:
        # Safety: reshuffle if empty (unlikely in single-round usage)
        deck.extend(new_shuffled_deck())
    return deck.pop()


def determine_outcome(player_total: int, dealer_total: int) -> int:
    # Called after both have finished; busts handled outside too, but safe anyway.
    if player_total > 21:
        return RES_LOSS
    if dealer_total > 21:
        return RES_WIN
    if player_total == dealer_total:
        return RES_TIE
    return RES_WIN if player_total > dealer_total else RES_LOSS


def play_round(conn: socket.socket) -> int:
    """
    Plays one full round and returns result code (tie/loss/win).
    Communication flow:
      Server sends: player card1, player card2, dealer upcard
      Loop: client sends "Hittt" or "Stand"
        - on Hit: server sends new player card (result=0)
        - on Stand: server reveals dealer hidden card, dealer draws (each sent),
                    then server sends final outcome in a final payload.
    """

    deck = new_shuffled_deck()

    player: List[Card] = []
    dealer: List[Card] = []

    # Initial deal
    player.append(deal_one(deck))
    send_payload(conn, b"Dealt", RES_NOT_OVER, player[-1])

    player.append(deal_one(deck))
    send_payload(conn, b"Dealt", RES_NOT_OVER, player[-1])

    dealer.append(deal_one(deck))  # upcard
    send_payload(conn, b"Upcrd", RES_NOT_OVER, dealer[-1])

    dealer.append(deal_one(deck))  # hidden card (not sent yet)

    # Player turn
    while True:
        p_total = hand_total(player)
        if p_total > 21:
            # Player busts: send final loss (use last player card)
            send_payload(conn, b"Over!", RES_LOSS, player[-1])
            return RES_LOSS

        decision = recv_client_decision(conn)

        if decision == "Hittt":
            player.append(deal_one(deck))
            send_payload(conn, b"Hittt", RES_NOT_OVER, player[-1])
            continue

        if decision == "Stand":
            break

        # Invalid decision: treat as Stand (robustness)
        print(f"[WARN] Invalid decision '{decision}', treating as Stand.")
        break

    # Dealer turn: reveal hidden card
    send_payload(conn, b"Reval", RES_NOT_OVER, dealer[1])

    # Dealer hits until total >= 17
    while hand_total(dealer) < 17:
        dealer.append(deal_one(deck))
        send_payload(conn, b"Dealr", RES_NOT_OVER, dealer[-1])

    # Determine final outcome
    p_total = hand_total(player)
    d_total = hand_total(dealer)

    outcome = determine_outcome(p_total, d_total)

    # Final message (attach dealer last card for context)
    last_card = dealer[-1] if dealer else player[-1]
    send_payload(conn, b"Over!", outcome, last_card)
    return outcome


# -----------------------------
# Server session + networking
# -----------------------------

def handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    print(f"[TCP] Client connected: {addr}")

    try:
        conn.settimeout(60.0)  # avoid hanging forever

        req_raw = recv_exact(conn, REQUEST_SIZE)
        req = parse_request(req_raw)
        print(f"[TCP] Request from '{req.team_name}', rounds={req.rounds}")

        wins = losses = ties = 0

        for i in range(1, req.rounds + 1):
            print(f"[GAME] Round {i}/{req.rounds} for {req.team_name}")
            result = play_round(conn)

            if result == RES_WIN:
                wins += 1
            elif result == RES_LOSS:
                losses += 1
            else:
                ties += 1

        played = wins + losses + ties
        win_rate = (wins / played) if played else 0.0
        print(f"[GAME] Finished {played} rounds for {req.team_name} | W={wins} L={losses} T={ties} | win_rate={win_rate:.3f}")

        # After rounds complete, close connection.
        # Client should return to listening for offers.

    except socket.timeout:
        print(f"[TCP] Timeout with {addr} (no activity).")
    except (ValueError, ConnectionError, OSError) as e:
        print(f"[TCP] Session error with {addr}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        print(f"[TCP] Client disconnected: {addr}")


def run_server(host: str = "0.0.0.0", tcp_port: int = 0, server_name: str = "TeamDealer") -> None:
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((host, tcp_port))
    listen_sock.listen(20)

    actual_port = listen_sock.getsockname()[1]
    print(f"[TCP] Listening on {host}:{actual_port}")

    stop_event = threading.Event()
    t = threading.Thread(target=offer_broadcaster, args=(stop_event, actual_port, server_name), daemon=True)
    t.start()
    print(f"[UDP] Broadcasting offers as '{server_name}' on UDP port {UDP_DISCOVERY_PORT}")

    try:
        while True:
            conn, addr = listen_sock.accept()
            # Thread per client so server can handle multiple clients concurrently
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SYS] Shutting down...")
    finally:
        stop_event.set()
        try:
            listen_sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    run_server(server_name="TeamDealer")

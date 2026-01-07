#!/usr/bin/env python3
import socket
import struct
from dataclasses import dataclass
from typing import List, Tuple, Optional

# ---- Protocol constants ----
MAGIC_COOKIE = 0xabcddcba

MSG_OFFER = 0x2
MSG_REQUEST = 0x3
MSG_PAYLOAD = 0x4

UDP_DISCOVERY_PORT = 13122

OFFER_SIZE = 4 + 1 + 2 + 32
REQUEST_SIZE = 4 + 1 + 1 + 32
PAYLOAD_SIZE = 4 + 1 + 5 + 1 + 2 + 1

# Result codes (from server)
RES_NOT_OVER = 0x0
RES_TIE = 0x1
RES_LOSS = 0x2
RES_WIN = 0x3

SUIT_MAP = {0: "H", 1: "D", 2: "C", 3: "S"}  # per spec: HDCS


@dataclass(frozen=True)
class Card:
    rank: int  # 1..13
    suit: int  # 0..3


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Server disconnected.")
        data += chunk
    return data


def pad_32_ascii(s: str) -> bytes:
    raw = (s or "").encode("ascii", errors="ignore")[:32]
    return raw.ljust(32, b"\x00")


# ---------------------------
# Offer / Request / Payload parsing
# ---------------------------

def unpack_offer(raw: bytes) -> Tuple[int, str]:
    """
    Returns (tcp_port, server_name).
    Offer: cookie(4) type(1) tcp_port(2) server_name(32)
    """
    if len(raw) != OFFER_SIZE:
        raise ValueError(f"Bad offer length: {len(raw)}")

    cookie = struct.unpack("!I", raw[0:4])[0]
    mtype = struct.unpack("!B", raw[4:5])[0]
    tcp_port = struct.unpack("!H", raw[5:7])[0]
    name_raw = raw[7:39]

    if cookie != MAGIC_COOKIE:
        raise ValueError("Bad offer cookie")
    if mtype != MSG_OFFER:
        raise ValueError("Bad offer type")

    server_name = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
    if not server_name:
        server_name = "UnknownServer"

    return tcp_port, server_name


def pack_request(rounds: int, team_name: str) -> bytes:
    """
    Request: cookie(4) type(1=0x3) rounds(1) team_name(32)
    """
    if not (1 <= rounds <= 255):
        raise ValueError("Rounds must be 1..255")

    b = b""
    b += struct.pack("!I", MAGIC_COOKIE)
    b += struct.pack("!B", MSG_REQUEST)
    b += struct.pack("!B", rounds & 0xFF)
    b += pad_32_ascii(team_name)
    return b


def unpack_payload(raw: bytes) -> Tuple[str, int, Card]:
    """
    Payload: cookie(4) type(1=0x4) decision(5) result(1) rank(2) suit(1)
    Returns: (tag5, result, Card)
    """
    if len(raw) != PAYLOAD_SIZE:
        raise ValueError(f"Bad payload length: {len(raw)}")

    cookie = struct.unpack("!I", raw[0:4])[0]
    mtype = struct.unpack("!B", raw[4:5])[0]
    decision5 = raw[5:10]
    result = struct.unpack("!B", raw[10:11])[0]
    rank = struct.unpack("!H", raw[11:13])[0]
    suit = struct.unpack("!B", raw[13:14])[0]

    if cookie != MAGIC_COOKIE:
        raise ValueError("Bad payload cookie")
    if mtype != MSG_PAYLOAD:
        raise ValueError("Bad payload type")

    tag = decision5.decode("ascii", errors="ignore")
    card = Card(rank=int(rank), suit=int(suit))
    return tag, int(result), card


def pack_client_decision(decision: str) -> bytes:
    """
    Client sends a PAYLOAD too.
    decision must be exactly "Hittt" or "Stand" (5 bytes).
    We'll put dummy values in card fields (rank=1 suit=0) since server ignores them.
    """
    if decision not in ("Hittt", "Stand"):
        raise ValueError("Decision must be 'Hittt' or 'Stand'")

    b = b""
    b += struct.pack("!I", MAGIC_COOKIE)
    b += struct.pack("!B", MSG_PAYLOAD)
    b += decision.encode("ascii")  # already 5 bytes
    b += struct.pack("!B", RES_NOT_OVER)
    b += struct.pack("!H", 1)  # dummy rank
    b += struct.pack("!B", 0)  # dummy suit
    return b


# ---------------------------
# Blackjack helpers
# ---------------------------

def card_value(rank: int) -> int:
    if rank == 1:
        return 11  # Ace as 11 per assignment phrasing
    if 2 <= rank <= 10:
        return rank
    return 10  # J/Q/K


def hand_total(hand: List[Card]) -> int:
    return sum(card_value(c.rank) for c in hand)


def fmt_card(c: Card) -> str:
    r = c.rank
    if r == 1:
        rs = "A"
    elif 2 <= r <= 10:
        rs = str(r)
    elif r == 11:
        rs = "J"
    elif r == 12:
        rs = "Q"
    else:
        rs = "K"
    ss = SUIT_MAP.get(c.suit, "?")
    return f"{rs}{ss}"


# ---------------------------
# Round flow (matches our server)
# ---------------------------

def play_one_round(conn: socket.socket, interactive: bool = False) -> int:
    """
    Reads server payloads and sends decisions until the round ends.
    Returns result code RES_WIN/RES_LOSS/RES_TIE.
    """

    player: List[Card] = []
    dealer: List[Card] = []

    # Initial 3 payloads: player, player, dealer upcard
    for i in range(3):
        tag, result, card = unpack_payload(recv_exact(conn, PAYLOAD_SIZE))
        if i < 2:
            player.append(card)
            print(f"  [S] {tag} -> Player gets {fmt_card(card)} (total={hand_total(player)})")
        else:
            dealer.append(card)
            print(f"  [S] {tag} -> Dealer upcard {fmt_card(card)}")

        # Should not end here, but handle anyway
        if result in (RES_WIN, RES_LOSS, RES_TIE):
            return result

    # Decision loop
    while True:
        p_total = hand_total(player)
        if p_total > 21:
            # Server should send Over! without needing another decision from client
            tag, result, card = unpack_payload(recv_exact(conn, PAYLOAD_SIZE))
            print(f"  [S] {tag} -> {fmt_card(card)} | RESULT={result}")
            return result if result != RES_NOT_OVER else RES_LOSS

        # Choose decision
        if interactive:
            while True:
                ans = input("  Your move (H=hit, S=stand): ").strip().lower()
                if ans in ("h", "hit"):
                    decision = "Hittt"
                    break
                if ans in ("s", "stand"):
                    decision = "Stand"
                    break
                print("  Please enter H or S.")
        else:
            decision = "Hittt" if p_total < 17 else "Stand"

        print(f"  [C] Decision: {decision} (player_total={p_total})")
        conn.sendall(pack_client_decision(decision))

        # After we send a decision, server may send:
        # - If Hit: a single "Hittt" payload with a new player card, possibly followed by Over! if bust
        # - If Stand: "Reval", then 0+ "Dealr", then final "Over!" with outcome
        while True:
            tag, result, card = unpack_payload(recv_exact(conn, PAYLOAD_SIZE))

            # If server is giving player a card
            if tag == "Hittt":
                player.append(card)
                print(f"  [S] {tag} -> Player gets {fmt_card(card)} (total={hand_total(player)})")
                # If bust, server will send Over! next without reading more client input
                if hand_total(player) > 21:
                    tag2, result2, card2 = unpack_payload(recv_exact(conn, PAYLOAD_SIZE))
                    print(f"  [S] {tag2} -> {fmt_card(card2)} | RESULT={result2}")
                    return result2 if result2 != RES_NOT_OVER else RES_LOSS
                # Otherwise, go back to decision loop
                break

            # Dealer reveal / dealer hits
            if tag in ("Reval", "Dealr"):
                dealer.append(card)
                print(f"  [S] {tag} -> Dealer gets {fmt_card(card)} (dealer_total={hand_total(dealer)})")
                # Keep reading until Over!
                continue

            # Final message (or any result != 0)
            if tag == "Over!" or result in (RES_WIN, RES_LOSS, RES_TIE):
                # card here is "last card" context; we print totals as we know them
                print(
                    f"  [S] {tag} -> {fmt_card(card)} | "
                    f"FINAL: player_total={hand_total(player)}, dealer_total={hand_total(dealer)} | RESULT={result}"
                )
                return result

            # Unknown tag: be robust; if result ends round, return; else keep reading
            print(f"  [S] {tag} -> {fmt_card(card)} (result={result})")
            if result in (RES_WIN, RES_LOSS, RES_TIE):
                return result


def result_to_text(res: int) -> str:
    if res == RES_WIN:
        return "WIN"
    if res == RES_LOSS:
        return "LOSS"
    if res == RES_TIE:
        return "TIE"
    return f"UNKNOWN({res})"


# ---------------------------
# Main loop
# ---------------------------

def listen_for_offer(timeout: Optional[float] = None) -> Tuple[str, int, str]:
    """
    Listens for a valid offer.
    Returns (server_ip, tcp_port, server_name).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", UDP_DISCOVERY_PORT))
    if timeout is not None:
        sock.settimeout(timeout)

    print(f"[UDP] Listening for offers on port {UDP_DISCOVERY_PORT}...")

    try:
        while True:
            raw, (ip, _port) = sock.recvfrom(2048)
            try:
                tcp_port, server_name = unpack_offer(raw[:OFFER_SIZE])
                print(f"[UDP] Offer from {ip} | server='{server_name}' | tcp_port={tcp_port}")
                return ip, tcp_port, server_name
            except ValueError:
                # Ignore junk packets quietly
                continue
    finally:
        sock.close()


def run_client(team_name: str, rounds: int, interactive: bool = False) -> None:
    while True:
        server_ip, tcp_port, server_name = listen_for_offer()

        # Connect TCP
        print(f"[TCP] Connecting to {server_ip}:{tcp_port} ...")
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(60.0)

        try:
            conn.connect((server_ip, tcp_port))
            print(f"[TCP] Connected to '{server_name}' ({server_ip}:{tcp_port})")

            # Send request
            req = pack_request(rounds, team_name)
            conn.sendall(req)
            print(f"[TCP] Sent request: team='{team_name}', rounds={rounds}")

            wins = losses = ties = 0

            for r in range(1, rounds + 1):
                print(f"\n[GAME] Round {r}/{rounds}")
                res = play_one_round(conn, interactive=interactive)
                print(f"[GAME] Round {r} result: {result_to_text(res)}")

                if res == RES_WIN:
                    wins += 1
                elif res == RES_LOSS:
                    losses += 1
                elif res == RES_TIE:
                    ties += 1

            played = wins + losses + ties
            win_rate = (wins / played) if played else 0.0
            print(f"\n[SUMMARY] Finished playing {played} rounds. W={wins} L={losses} T={ties} win_rate={win_rate:.3f}")

        except (socket.timeout, ConnectionError, OSError, ValueError) as e:
            print(f"[ERR] Session failed: {e}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

        print("\n[UDP] Returning to offer listening...\n")


if __name__ == "__main__":
    # Change these as you like
    TEAM_NAME = "Portland Trail Blazers"
    ROUNDS = 5
    INTERACTIVE = False  # set True if you want manual H/S input

    run_client(team_name=TEAM_NAME, rounds=ROUNDS, interactive=INTERACTIVE)

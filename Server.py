import random
import socket
import struct
import threading
from dataclasses import dataclass
from typing import List, Tuple

# protocol constants
MAGIC_COOKIE = 0xabcddcba  # fixed magic cookie value
MSG_OFFER = 0x2  # message type OFFER
MSG_REQUEST = 0x3  # message type REQUEST
MSG_PAYLOAD = 0x4  # message type PAYLOAD
UDP_PORT = 13122
BROADCAST_INTERVAL = 1.0

# message sizes
OFFER_SIZE = 4 + 1 + 2 + 32
REQUEST_SIZE = 4 + 1 + 1 + 32
PAYLOAD_SIZE = 4 + 1 + 5 + 1 + 2 + 1

# game results
NOT_OVER = 0x0
TIE = 0x1
LOSS = 0x2
WIN = 0x3

SUITS = [0, 1, 2, 3]  # hearts, diamonds, clubs, spades
RANKS = list(range(1, 14))  # 1-13 (Ace to King)


# data classes

@dataclass(frozen=True)
class Card:
    rank: int
    suit: int


@dataclass
class ClientRequest:
    rounds: int
    team_name: str


"""pad string to 32 bytes with null bytes - as needed"""


def pad_string(s: str) -> bytes:
    """pad to 32 bytes"""
    raw = (s or "").encode("ascii", errors="ignore")[:32]
    return raw.ljust(32, b"\x00")


"""receive exactly n bytes from socket - blocking I/O, no busy-waiting"""


def recv_all(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))  # blocking call - waits for data
        if not chunk:
            raise ConnectionError("Peer disconnected.")
        data += chunk
    return data


def pack_offer(tcp_port: int, server_name: str) -> bytes:
    # cookie + type + tcp_port + server_name
    b = b""
    b += struct.pack("!I", MAGIC_COOKIE)
    b += struct.pack("!B", MSG_OFFER)
    b += struct.pack("!H", tcp_port & 0xFFFF)
    b += pad_string(server_name)
    return b


"""unpack offer and return (tcp_port, server_name)"""


def unpack_request(raw: bytes) -> ClientRequest:
    if len(raw) != REQUEST_SIZE:
        raise ValueError(f"Bad request length: got {len(raw)}, expected {REQUEST_SIZE}")

    cookie = struct.unpack("!I", raw[0:4])[0]
    mtype = struct.unpack("!B", raw[4:5])[0]
    rounds = struct.unpack("!B", raw[5:6])[0]
    team_raw = raw[6:38]

    if cookie != MAGIC_COOKIE:
        raise ValueError(f"Bad cookie in request: {cookie:#x}")
    if mtype != MSG_REQUEST:
        raise ValueError(f"Bad request type: {mtype:#x}")
    if rounds < 1:
        raise ValueError("Rounds must be >= 1")

    team_name = team_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
    if not team_name:
        team_name = "UnknownTeam"

    return ClientRequest(rounds=int(rounds), team_name=team_name)


"""pack payload from (decision, result, rank, suit)"""


def pack_payload(decision5: bytes, result: int, rank: int, suit: int) -> bytes:
    if len(decision5) != 5:
        raise ValueError("decision must be exactly 5 bytes")
    if not (0 <= result <= 3):
        raise ValueError("result must be 0..3")
    if not (1 <= rank <= 13):
        raise ValueError("rank must be 1..13")
    if not (0 <= suit <= 3):
        raise ValueError("suit must be 0..3")

    b = b""
    b += struct.pack("!I", MAGIC_COOKIE)
    b += struct.pack("!B", MSG_PAYLOAD)
    b += decision5
    b += struct.pack("!B", result & 0xFF)
    b += struct.pack("!H", rank & 0xFFFF)
    b += struct.pack("!B", suit & 0xFF)
    return b


"""unpack payload and return (decision, result, rank, suit)"""


def unpack_payload(raw: bytes) -> Tuple[str, int, int, int]:
    if len(raw) != PAYLOAD_SIZE:
        raise ValueError(f"Bad payload length: got {len(raw)}, expected {PAYLOAD_SIZE}")

    cookie = struct.unpack("!I", raw[0:4])[0]
    mtype = struct.unpack("!B", raw[4:5])[0]
    decision5 = raw[5:10]
    result = struct.unpack("!B", raw[10:11])[0]
    rank = struct.unpack("!H", raw[11:13])[0]
    suit = struct.unpack("!B", raw[13:14])[0]

    if cookie != MAGIC_COOKIE:
        raise ValueError(f"Bad cookie in payload: {cookie:#x}")
    if mtype != MSG_PAYLOAD:
        raise ValueError(f"Bad payload type: {mtype:#x}")

    decision = decision5.decode("ascii", errors="ignore")
    return decision, result, rank, suit


def send_payload(conn: socket.socket, tag5: bytes, result: int, card: Card) -> None:
    conn.sendall(pack_payload(tag5, result, card.rank, card.suit))


def recv_client_decision(conn: socket.socket) -> str:
    raw = recv_all(conn, PAYLOAD_SIZE)
    decision, _result, _rank, _suit = unpack_payload(raw)
    return decision


##########################################################################################################


# blackjack stuff - simplified rules
def new_shuffled_deck() -> List[Card]:
    deck = [Card(rank=r, suit=s) for s in SUITS for r in RANKS]
    random.shuffle(deck)
    return deck


# get card value for blackjack


def card_value(rank: int) -> int:
    if rank == 1:
        return 11  # ace
    if 2 <= rank <= 10:
        return rank
    return 10  # face cards


# compute total value of hand


def hand_total(hand: List[Card]) -> int:
    return sum(card_value(c.rank) for c in hand)


def deal_one(deck: List[Card]) -> Card:
    if not deck:
        deck.extend(new_shuffled_deck())
    return deck.pop()


def determine_outcome(player_total: int, dealer_total: int) -> int:
    if player_total > 21:
        return LOSS
    if dealer_total > 21:
        return WIN
    if player_total == dealer_total:
        return TIE
    return WIN if player_total > dealer_total else LOSS


# play a single round of blackjack


def play_round(conn: socket.socket) -> int:
    # deals cards and handles a blackjack round
    # player gets 2 cards, dealer gets 1 shown + 1 hidden
    # player can hit or stand
    deck = new_shuffled_deck()

    player: List[Card] = []
    dealer: List[Card] = []

    # deal initial cards to player
    player.append(deal_one(deck))
    send_payload(conn, b"Dealt", NOT_OVER, player[-1])

    player.append(deal_one(deck))
    send_payload(conn, b"Dealt", NOT_OVER, player[-1])

    # dealer visible card
    dealer.append(deal_one(deck))
    send_payload(conn, b"Upcrd", NOT_OVER, dealer[-1])

    # dealer hidden card - don't show yet
    dealer.append(deal_one(deck))

    # let player make decisions
    while True:
        p_total = hand_total(player)
        if p_total > 21:
            send_payload(conn, b"Over!", LOSS, player[-1])
            return LOSS

        decision = recv_client_decision(conn)

        if decision == "Hittt":
            player.append(deal_one(deck))
            send_payload(conn, b"Hittt", NOT_OVER, player[-1])
            continue

        if decision == "Stand":
            break

        # if they send something weird just treat it as stand
        print(f"[WARN] Invalid decision '{decision}' -> Stand")
        break

    # now reveal dealer's hidden card
    send_payload(conn, b"Reval", NOT_OVER, dealer[1])

    # dealer must hit until 17 or higher
    while hand_total(dealer) < 17:
        dealer.append(deal_one(deck))
        send_payload(conn, b"Dealr", NOT_OVER, dealer[-1])

    # figure out who won
    outcome = determine_outcome(hand_total(player), hand_total(dealer))
    last = dealer[-1] if dealer else player[-1]
    send_payload(conn, b"Over!", outcome, last)
    return outcome


##########################################################################################################
# server main functions


def offer_broadcaster(stop_event: threading.Event, tcp_port: int, server_name: str) -> None:
    offer = pack_offer(tcp_port, server_name)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        dest = ("<broadcast>", UDP_PORT)
        while not stop_event.is_set():
            try:
                sock.sendto(offer, dest)
                print(f"[UDP] Offer broadcast (tcp_port={tcp_port})")
            except OSError as e:
                print(f"[UDP] Broadcast error: {e}")
            # properly sleeps the thread, no busy-waiting
            stop_event.wait(BROADCAST_INTERVAL)
    finally:
        sock.close()


# handle a single client connection


def handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    print(f"[TCP] Connected: {addr}")

    try:
        conn.settimeout(60.0)

        req_raw = recv_all(conn, REQUEST_SIZE)
        req = unpack_request(req_raw)
        print(f"[TCP] Request: team='{req.team_name}', rounds={req.rounds}")

        wins = 0
        losses = 0
        ties = 0

        for r in range(1, req.rounds + 1):
            print(f"[GAME] {req.team_name} round {r}/{req.rounds}")
            res = play_round(conn)
            if res == WIN:
                wins += 1
            elif res == LOSS:
                losses += 1
            else:
                ties += 1

        played = wins + losses + ties
        win_rate = (wins / played) if played else 0.0
        print(f"[GAME] Done: team='{req.team_name}' W={wins} L={losses} T={ties} win_rate={win_rate:.3f}")

    except socket.timeout:
        print(f"[TCP] Timeout: {addr}")
    except (ValueError, ConnectionError, OSError) as e:
        print(f"[TCP] Error with {addr}: {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        print(f"[TCP] Disconnected: {addr}")


# main server loop


def run_server(host: str = "0.0.0.0", tcp_port: int = 0, server_name: str = "TeamDealer") -> None:
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((host, tcp_port))
    listen_sock.listen(20)

    actual_port = listen_sock.getsockname()[1]
    print(f"[TCP] Listening on {host}:{actual_port}")

    stop_event = threading.Event()
    threading.Thread(
        target=offer_broadcaster,
        args=(stop_event, actual_port, server_name),
        daemon=True,
    ).start()
    print(f"[UDP] Broadcasting as '{server_name}' on UDP port {UDP_PORT}")

    try:
        while True:
            # accept() blocks until a client connects - no busy-waiting
            conn, addr = listen_sock.accept()
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

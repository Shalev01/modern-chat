import base64
import hashlib
import os
import socket
import struct
from enum import IntEnum

__WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class OpCode(IntEnum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xa

class Frame:
    def __init__(self, opcode: OpCode, payload: bytes, fin: bool = True):
        self.opcode = opcode
        self.payload = payload
        self.fin = fin


def create_frame(opcode: OpCode, payload: bytes, is_masked: bool = True) -> bytes:
    frame = bytearray()
    frame.append(0x80 | opcode)

    payload_len = len(payload)
    mask_bit = 0x80 if is_masked else 0x00

    if payload_len < 126:
        frame.append(mask_bit | payload_len)
    elif payload_len < 65536:
        frame.append(mask_bit | 126)
        frame.extend(struct.pack('!H', payload_len))
    else:
        frame.append(mask_bit | 127)
        frame.extend(struct.pack('!Q', payload_len))

    if is_masked:
        mask, masked_payload = _mask_payload(payload)
        frame.extend(mask)
        frame.extend(masked_payload)
    else:
        frame.extend(payload)

    return bytes(frame)

def parse_frame(data: bytes) -> tuple[Frame, int]:
    if len(data) < 2:
        raise ValueError("Incomplete frame")

    byte1, byte2 = data[0], data[1]
    fin = bool(byte1 & 0x80)
    opcode = OpCode(byte1 & 0x0f)
    masked = bool(byte2 & 0x80)
    payload_len = byte2 & 0x7f

    offset = 2

    if payload_len == 126:
        if len(data) < offset + 2:
            raise ValueError("Incomplete frame")
        payload_len = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2
    elif payload_len == 127:
        if len(data) < offset + 8:
            raise ValueError("Incomplete frame")
        payload_len = struct.unpack('!Q', data[offset:offset + 8])[0]
        offset += 8

    mask = None
    if masked:
        if len(data) < offset + 4:
            raise ValueError("Incomplete frame")
        mask = data[offset:offset + 4]
        offset += 4

    if len(data) < offset + payload_len:
        raise ValueError("Incomplete frame")

    payload = data[offset:offset + payload_len]
    if masked and mask:
        payload = _unmask_payload(payload, mask)

    return Frame(opcode, payload, fin), offset + payload_len

def handshake_client(sock: socket.socket, host: str, path: str = "/") -> None:
    request, key = _create_client_request(host, path)
    sock.send(request.encode())
    response = sock.recv(4096).decode()

    if not _validate_client_response(response, key):
        raise ConnectionError("WebSocket handshake failed")


def handshake_server(client_sock: socket.socket) -> None:
    request_data = client_sock.recv(4096)
    response = _create_server_response(request_data)
    client_sock.send(response)


def _mask_payload(payload: bytes) -> tuple[bytes, bytes]:
    mask = os.urandom(4)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
    return mask, masked

def _unmask_payload(payload: bytes, mask: bytes) -> bytes:
    return bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))

def _create_client_request(host: str, path: str = "/") -> tuple[str, str]:
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    return request, key

def _validate_client_response(response: str, expected_key: str) -> bool:
    if "101 Switching Protocols" not in response:
        return False

    expected_accept = base64.b64encode(
        hashlib.sha1((expected_key + __WS_MAGIC).encode()).digest()
    ).decode()

    return f"Sec-WebSocket-Accept: {expected_accept}" in response

def _create_server_response(request_data: bytes) -> bytes:
    request = request_data.decode()
    headers = _parse_headers(request)

    if headers.get('upgrade', '').lower() != 'websocket':
        raise ValueError("Not a WebSocket upgrade request")

    ws_key = headers.get('sec-websocket-key')
    if not ws_key:
        raise ValueError("Missing WebSocket key")

    accept_key = base64.b64encode(
        hashlib.sha1((ws_key + __WS_MAGIC).encode()).digest()
    ).decode()

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )
    return response.encode()

def _parse_headers(request: str) -> dict[str, str]:
    lines = request.split('\r\n')
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()
    return headers

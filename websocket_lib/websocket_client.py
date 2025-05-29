import socket
import ssl
from urllib.parse import urlparse

from websocket_lib.protocol import handshake_client
from websocket_lib.websocket import WebSocket


def connect_client(url: str) -> WebSocket:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
    path = parsed.path or '/'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if parsed.scheme == 'wss':
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)

    try:
        sock.connect((host, port))
        handshake_client(sock, host, path)
        ws = WebSocket(sock, is_client=True)
        ws.start_threads()
        return ws

    except Exception:
        sock.close()
        raise


if __name__ == "__main__":
    client = connect_client("ws://localhost:8765")
    client.on_error = lambda e: print(e)
    client.on_close = lambda : print("closed")
    client.on_message = lambda data: print(data)
    client.send_text("hello")
    client.send_text("world")
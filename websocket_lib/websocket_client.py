import socket
import ssl
from urllib.parse import urlparse

from websocket_lib.protocol import handshake_client
from websocket_lib.websocket import WebSocket, WebSocketState


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


        return ws

    except Exception:
        sock.close()
        raise


if __name__ == "__main__":

    def input_reader(ws):

        while ws.state != WebSocketState.CLOSED:
            text = input("enter input: ")
            if text == "_close_":
                ws.close()
                break
            else:
                ws.send_text(text)

    def on_message(data: bytes | str, ws) -> None:
        print("client on message")
        print(data)

    def on_error(e, ws) -> None:
        print(f"on_error")
        print(e)

    def on_close(ws) -> None:
        print(f"on_close")


    client = connect_client("ws://localhost:8765")

    client.on_message = on_message
    client.on_close = on_close
    client.on_error = on_error

    client.start_threads()


    input_reader(client)


    # def on_message(message):
    #     print(message)
    #
    # client.send_text("hello")
    # client.send_text("world")

    # threading.Thread(target=input_reader, args=(client,), daemon=True).start()

    # while client.state != WebSocketState.CLOSED:
    #     pass

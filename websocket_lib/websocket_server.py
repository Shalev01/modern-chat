import socket
import threading
import time

from websocket_lib.protocol import handshake_server
from websocket_lib.websocket import WebSocket, WebSocketState


class WebSocketServer:
    def __init__(self, host = 'localhost', port = 8765):
        self.host = host
        self.port = port
        self.on_connection = None
        self._running = False

    def start(self) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)

        self._running = True
        print(f"WebSocket server listening on {self.host}:{self.port}")

        try:
            while self._running:
                try:
                    server_sock.settimeout(1.0)
                    client_sock, addr = server_sock.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
        finally:
            server_sock.close()

    def stop(self) -> None:
        self._running = False

    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        try:
            request_data = client_sock.recv(4096)

            handshake_server(client_sock, request_data)

            ws = WebSocket(client_sock, is_client=False)

            if self.on_connection:
                self.on_connection(ws)

            ws.start_threads()

            while ws.state != WebSocketState.CLOSED:
                time.sleep(0.1)

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            client_sock.close()

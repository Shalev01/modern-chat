import socket
import threading
import time
from typing import Optional, Callable

from websocket_lib.protocol import handshake_server
from websocket_lib.websocket import WebSocket, WebSocketState


class WebSocketServer:
    def __init__(self, host = 'localhost', port = 8765):
        self.host = host
        self.port = port
        self.on_connection: Optional[Callable[[WebSocket], None]] = None
        self._running = False

    def start(self) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)

        self._running = True

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

            handshake_server(client_sock)

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

if __name__ == "__main__":

    def on_message(data: bytes | str, ws: WebSocket) -> None:
        print(f"on_message {ws} {data}")

    def on_error(error: Exception, ws: WebSocket) -> None:
        print(f"on_error {ws} {error} ")


    def on_close(ws: WebSocket) -> None:
        print(f"on_close {ws}")


    def on_connection(ws: WebSocket) -> None:
        print(f"system message - on_connection. a client connected: {ws.sock.getpeername()}")
        ws.on_error = on_error
        ws.on_close = on_close
        ws.send_text("wellcome 1")
        ws.on_message = on_message
        ws.send_text("wellcome 2")




    server = WebSocketServer()
    server.on_connection = on_connection

    print('server starting at ' + server.host + ':' + str(server.port) )

    server.start()

#TODO - debug _on_connection func + try to implement a ping system on server
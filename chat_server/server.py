from websocket_lib.websocket import WebSocket
from websocket_lib.websocket_server import WebSocketServer

class ChatClient:
    websocket: WebSocket

    def __init__(self, websocket: WebSocket):
        self.websocket = websocket

class ChatServer:
    def __init__(self):

        self.websocket_server = WebSocketServer()
        self.clients: list[ChatClient] = []

        self.websocket_server.on_connection = self.on_connection


    def on_connection(self, websocket: WebSocket):
        self.clients.append(ChatClient(websocket))
        print(f"on_connection - new client conected")
        websocket.send_text("a socket has joined")

    def on_message(self, websocket: WebSocket):
        print(f)


    def start(self):
        self.websocket_server.start()

if __name__ == "__main__":
    # def on_message(data: bytes | str) -> None:
    #     print(data)
    #
    # def on_connection(ws: WebSocket) -> None:
    #     print(f"Client connected")
    #     ws.on_message = on_message

    server = ChatServer()

    server.start()
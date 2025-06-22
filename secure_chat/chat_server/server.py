import threading
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from typing import Dict, Optional
import logging

from websocket_lib.websocket_server import WebSocketServer
from websocket_lib.websocket import WebSocket

from secure_chat.chat_protocol.messages import (
    BaseSecureChatMessage, JoinMessage, LeaveMessage, PublicMessage,
    PrivateMessage, WelcomeMessage, AddUserMessage, RemoveUserMessage,
    RoutedPublicMessage, RoutedPrivateMessage, ErrorMessage, UserInfo
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def load_user_keys(keys_dir: str = "keys") -> Dict[str, object]:
    keys_path = Path(keys_dir)
    user_keys = {}

    for key_file in keys_path.glob("*.public.pem"):
        username = key_file.stem.replace('.public', '')
        try:
            with open(key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
                user_keys[username] = public_key
        except Exception as e:
            logger.error(f"Failed to load public key for {username}: {e}")

    logger.info(f"Loaded {len(user_keys)} user keys")
    return user_keys


class SecureChatServer:
    def __init__(self, user_keys: Dict[str, object]):
        self.user_keys = user_keys
        self.clients: Dict[WebSocket, Optional[str]] = {}  # websocket -> username
        self.users: Dict[str, WebSocket] = {}  # username -> websocket
        self.active_user_keys: Dict[str, object] = {}
        self.server = None
        self.lock = threading.RLock()  # Protects all shared state

    def validate_signature(self, message: JoinMessage, public_key) -> bool:
        try:
            message_dict = {"name": message.name}
            message_json = json.dumps(message_dict, sort_keys=True)
            signature_bytes = bytes.fromhex(message.signature)

            public_key.verify(
                signature_bytes,
                message_json.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except (InvalidSignature, Exception) as e:
            logger.error(f"Signature validation failed: {e}")
            return False

    def send_message(self, websocket: WebSocket, message: BaseSecureChatMessage):
        try:
            websocket.send_text(message.to_json())
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.handle_disconnect(websocket)

    def broadcast_to_others(self, sender_ws: WebSocket, message: BaseSecureChatMessage):
        with self.lock:
            clients_to_send = list(self.clients.items())

        for ws, username in clients_to_send:
            if ws != sender_ws and username is not None:
                self.send_message(ws, message)

    def handle_join(self, websocket: WebSocket, message: JoinMessage):
        with self.lock:
            if message.name in self.users:
                error = ErrorMessage(text="User already exists", ref_message_id=message.id)
                self.send_message(websocket, error)
                websocket.close()
                return

            public_key = self.user_keys.get(message.name)
            if public_key is None:
                error = ErrorMessage(text="No public key found for user", ref_message_id=message.id)
                self.send_message(websocket, error)
                websocket.close()
                return

            if not self.validate_signature(message, public_key):
                error = ErrorMessage(text="Invalid signature", ref_message_id=message.id)
                self.send_message(websocket, error)
                websocket.close()
                return

            self.clients[websocket] = message.name
            self.users[message.name] = websocket
            self.active_user_keys[message.name] = public_key

            user_list = [
                UserInfo(name=name, public_key=key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode())
                for name, key in self.active_user_keys.items()
            ]

            welcome = WelcomeMessage(users=user_list)
            self.send_message(websocket, welcome)

            add_user = AddUserMessage(
                name=message.name,
                public_key=public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            )
            self.broadcast_to_others(websocket, add_user)

    def handle_leave(self, websocket: WebSocket, message: LeaveMessage):
        with self.lock:
            username = self.clients.get(websocket)
            if username:
                self.clients[websocket] = None
                if username in self.users:
                    del self.users[username]
                if username in self.active_user_keys:
                    del self.active_user_keys[username]

                remove_user = RemoveUserMessage(name=username)
                self.broadcast_to_others(websocket, remove_user)

        websocket.close()

    def handle_public_message(self, websocket: WebSocket, message: PublicMessage):
        with self.lock:
            username = self.clients.get(websocket)
            if not username:
                error = ErrorMessage(text="User not authenticated", ref_message_id=message.id)
                self.send_message(websocket, error)
                return

            routed = RoutedPublicMessage(text=message.text, from_name=username)
            self.broadcast_to_others(websocket, routed)

    def handle_private_message(self, websocket: WebSocket, message: PrivateMessage):
        with self.lock:
            username = self.clients.get(websocket)
            if not username:
                error = ErrorMessage(text="User not authenticated", ref_message_id=message.id)
                self.send_message(websocket, error)
                return

            if message.to_name not in self.users:
                error = ErrorMessage(text="Unknown recipient", ref_message_id=message.id)
                self.send_message(websocket, error)
                return

            recipient_ws = self.users[message.to_name]
            routed = RoutedPrivateMessage(
                to_name=message.to_name,
                encrypted_text=message.encrypted_text,
                from_name=username
            )
            self.send_message(recipient_ws, routed)

    def handle_disconnect(self, websocket: WebSocket):
        with self.lock:
            username = self.clients.get(websocket)
            if username:
                if username in self.users:
                    del self.users[username]
                if username in self.active_user_keys:
                    del self.active_user_keys[username]

                remove_user = RemoveUserMessage(name=username)
                self.broadcast_to_others(websocket, remove_user)

            if websocket in self.clients:
                del self.clients[websocket]

    def on_message(self, data, websocket: WebSocket):
        try:
            message = BaseSecureChatMessage.from_json(data)
            username = self.clients.get(websocket, "_NEW_")
            logger.debug(f"{username}: {message}")

            if isinstance(message, JoinMessage):
                self.handle_join(websocket, message)
            elif self.clients.get(websocket) is None:
                error = ErrorMessage(text="Must join first")
                self.send_message(websocket, error)
                websocket.close()
            elif isinstance(message, LeaveMessage):
                self.handle_leave(websocket, message)
            elif isinstance(message, PublicMessage):
                self.handle_public_message(websocket, message)
            elif isinstance(message, PrivateMessage):
                self.handle_private_message(websocket, message)
            else:
                error = ErrorMessage(text="Unknown message type")
                self.send_message(websocket, error)

        except json.JSONDecodeError:
            error = ErrorMessage(text="Invalid JSON")
            self.send_message(websocket, error)
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            error = ErrorMessage(text="Internal server error")
            self.send_message(websocket, error)

    def on_error(self, error: Exception, websocket: WebSocket):
        logger.error(f"WebSocket error for {self.clients.get(websocket, 'unknown')}: {error}")
        self.handle_disconnect(websocket)

    def on_close(self, websocket: WebSocket):
        username = self.clients.get(websocket, "unknown")
        logger.info(f"Connection closed for {username}")
        self.handle_disconnect(websocket)

    def on_connection(self, websocket: WebSocket):
        logger.info(f"New connection from {websocket.sock.getpeername()}")

        with self.lock:
            self.clients[websocket] = None

        websocket.on_message = lambda data, ws: self.on_message(data, ws)
        websocket.on_error = lambda error, ws: self.on_error(error, ws)
        websocket.on_close = lambda ws: self.on_close(ws)

    def start_server(self, host: str = "localhost", port: int = 8765):
        logger.info(f"Starting server on {host}:{port}")

        self.server = WebSocketServer(host, port)
        self.server.on_connection = self.on_connection

        try:
            self.server.start()
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
            self.server.stop()


def main():
    keys_dir = sys.argv[1] if len(sys.argv) > 1 else "../../sample_keys"
    user_keys = load_user_keys(keys_dir)
    server = SecureChatServer(user_keys)
    server.start_server()


if __name__ == "__main__":
    main()
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
from websocket_lib.websocket import WebSocket, WebSocketState
from chat_protocol.messages import (
    BaseSecureChatMessage, JoinMessage, LeaveMessage, PublicMessage,
    PrivateMessage, WelcomeMessage, AddUserMessage, RemoveUserMessage,
    RoutedPublicMessage, RoutedPrivateMessage, ErrorMessage, UserInfo
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def load_user_keys(keys_dir: str = "keys") -> Dict[str, object]:
    """Load public keys for all users from the keys directory"""
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


class ThreadedSecureChatServer:
    def __init__(self, user_keys: Dict[str, object], host: str = "localhost", port: int = 8765):
        self.user_keys = user_keys
        self.host = host
        self.port = port

        # Thread-safe data structures
        self.clients_lock = threading.RLock()
        self.clients: Dict[WebSocket, Optional[str]] = {}  # websocket -> username
        self.users: Dict[str, WebSocket] = {}  # username -> websocket
        self.active_user_keys: Dict[str, object] = {}  # username -> public_key

        self.server = WebSocketServer(host, port)
        self.server.on_connection = self.handle_new_connection

    def validate_signature(self, message: JoinMessage, public_key) -> bool:
        """Validate the signature in a JoinMessage"""
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
        """Send a message to a specific websocket connection"""
        try:
            if websocket.state == WebSocketState.OPEN:
                websocket.send_text(message.to_json())
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.handle_disconnect(websocket)

    def broadcast_to_others(self, sender_ws: WebSocket, message: BaseSecureChatMessage):
        """Broadcast a message to all connected clients except the sender"""
        with self.clients_lock:
            for ws, username in self.clients.items():
                if ws != sender_ws and username is not None:
                    self.send_message(ws, message)

    def broadcast_to_all(self, message: BaseSecureChatMessage):
        """Broadcast a message to all connected clients"""
        with self.clients_lock:
            for ws, username in self.clients.items():
                if username is not None:
                    self.send_message(ws, message)

    def handle_join(self, websocket: WebSocket, message: JoinMessage):
        """Handle a JoinMessage from a client"""
        with self.clients_lock:
            # Check if user already exists
            if message.name in self.users:
                error = ErrorMessage(text="User already exists", ref_message_id=message.id)
                self.send_message(websocket, error)
                websocket.close()
                return

            # Check if we have the public key for this user
            public_key = self.user_keys.get(message.name)
            if public_key is None:
                error = ErrorMessage(text="No public key found for user", ref_message_id=message.id)
                self.send_message(websocket, error)
                websocket.close()
                return

            # Validate signature
            if not self.validate_signature(message, public_key):
                error = ErrorMessage(text="Invalid signature", ref_message_id=message.id)
                self.send_message(websocket, error)
                websocket.close()
                return

            # Add user to our data structures
            self.clients[websocket] = message.name
            self.users[message.name] = websocket
            self.active_user_keys[message.name] = public_key

            # Create user list for welcome message
            user_list = [
                UserInfo(
                    name=name,
                    public_key=key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode()
                )
                for name, key in self.active_user_keys.items()
            ]

            # Send welcome message to the new user
            welcome = WelcomeMessage(users=user_list)
            self.send_message(websocket, welcome)

            # Broadcast AddUserMessage to all other users
            add_user = AddUserMessage(
                name=message.name,
                public_key=public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            )
            self.broadcast_to_others(websocket, add_user)

        logger.info(f"User {message.name} joined the chat")

    def handle_leave(self, websocket: WebSocket, message: LeaveMessage):
        """Handle a LeaveMessage from a client"""
        with self.clients_lock:
            username = self.clients.get(websocket)
            if username:
                # Remove user from data structures
                self.clients[websocket] = None
                del self.users[username]
                del self.active_user_keys[username]

                # Broadcast RemoveUserMessage to all other users
                remove_user = RemoveUserMessage(name=username)
                self.broadcast_to_others(websocket, remove_user)

                logger.info(f"User {username} left the chat")

        websocket.close()

    def handle_public_message(self, websocket: WebSocket, message: PublicMessage):
        """Handle a PublicMessage from a client"""
        with self.clients_lock:
            username = self.clients.get(websocket)
            if not username:
                error = ErrorMessage(text="User not authenticated", ref_message_id=message.id)
                self.send_message(websocket, error)
                return

            # Create routed public message and broadcast to ALL users (including sender)
            routed = RoutedPublicMessage(text=message.text, from_name=username)
            self.broadcast_to_all(routed)

        logger.debug(f"Public message from {username}: {message.text}")

    def handle_private_message(self, websocket: WebSocket, message: PrivateMessage):
        """Handle a PrivateMessage from a client"""
        with self.clients_lock:
            username = self.clients.get(websocket)
            if not username:
                error = ErrorMessage(text="User not authenticated", ref_message_id=message.id)
                self.send_message(websocket, error)
                return

            # Check if recipient exists
            if message.to_name not in self.users:
                error = ErrorMessage(text="Unknown recipient", ref_message_id=message.id)
                self.send_message(websocket, error)
                return

            # Send routed private message to recipient
            recipient_ws = self.users[message.to_name]
            routed = RoutedPrivateMessage(
                to_name=message.to_name,
                encrypted_text=message.encrypted_text,
                from_name=username
            )
            self.send_message(recipient_ws, routed)

        logger.debug(f"Private message from {username} to {message.to_name}")

    def handle_disconnect(self, websocket: WebSocket):
        """Handle a client disconnection"""
        with self.clients_lock:
            username = self.clients.get(websocket)
            if username:
                # Remove user from data structures
                del self.users[username]
                if username in self.active_user_keys:
                    del self.active_user_keys[username]

                # Broadcast RemoveUserMessage to all other users
                remove_user = RemoveUserMessage(name=username)
                self.broadcast_to_others(websocket, remove_user)

                logger.info(f"User {username} disconnected")

            # Remove websocket from clients
            if websocket in self.clients:
                del self.clients[websocket]

    def handle_message(self, data, websocket: WebSocket):
        """Handle incoming messages from clients"""
        try:
            message = BaseSecureChatMessage.from_json(data)
            username = self.clients.get(websocket, "_NEW_")
            logger.debug(f"{username}: {message}")

            if isinstance(message, JoinMessage):
                self.handle_join(websocket, message)
            elif self.clients.get(websocket) is None:
                # Client must join first
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

    def handle_new_connection(self, websocket: WebSocket):
        """Handle a new WebSocket connection"""
        with self.clients_lock:
            self.clients[websocket] = None  # Not authenticated yet

        logger.info(f"New connection from {websocket.sock.getpeername()}")

        # Set up event handlers
        websocket.on_message = lambda data, ws: self.handle_message(data, ws)
        websocket.on_close = lambda ws: self.handle_disconnect(ws)
        websocket.on_error = lambda error, ws: logger.error(f"WebSocket error: {error}")

        # Start the websocket threads
        websocket.start_threads()

    def start(self):
        """Start the chat server"""
        logger.info(f"Starting Secure Chat Server on {self.host}:{self.port}")
        logger.info(f"Loaded keys for users: {list(self.user_keys.keys())}")

        try:
            self.server.start()
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the chat server"""
        logger.info("Stopping server...")

        # Close all client connections
        with self.clients_lock:
            for websocket in list(self.clients.keys()):
                try:
                    websocket.close()
                except:
                    pass
            self.clients.clear()
            self.users.clear()
            self.active_user_keys.clear()

        # Stop the server
        self.server.stop()


def main():
    """Main entry point"""
    keys_dir = sys.argv[1] if len(sys.argv) > 1 else "../sample_keys"
    host = sys.argv[2] if len(sys.argv) > 2 else "localhost"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8765

    user_keys = load_user_keys(keys_dir)
    if not user_keys:
        logger.error("No user keys loaded. Cannot start server.")
        return

    server = ThreadedSecureChatServer(user_keys, host, port)
    server.start()


if __name__ == "__main__":
    main()
import asyncio
import websockets
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from typing import Dict, Optional
import logging

from chat_protocol.messages import (
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
        self.clients: Dict[websockets.ServerConnection, Optional[str]] = {}
        self.users: Dict[str, websockets.ServerConnection] = {}
        self.active_user_keys: Dict[str, object] = {}

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

    async def send_message(self, websocket: websockets.ServerConnection, message: BaseSecureChatMessage):
        try:
            await websocket.send(message.to_json())
        except websockets.exceptions.ConnectionClosed:
            await self.handle_disconnect(websocket)

    async def broadcast_to_others(self, sender_ws: websockets.ServerConnection, message: BaseSecureChatMessage):
        for ws in self.clients:
            if ws != sender_ws and self.clients[ws] is not None:
                await self.send_message(ws, message)

    async def handle_join(self, websocket: websockets.ServerConnection, message: JoinMessage):
        if message.name in self.users:
            error = ErrorMessage(text="User already exists", ref_message_id=message.id)
            await self.send_message(websocket, error)
            await websocket.close()
            return

        public_key = self.user_keys.get(message.name)
        if public_key is None:
            error = ErrorMessage(text="No public key found for user", ref_message_id=message.id)
            await self.send_message(websocket, error)
            await websocket.close()
            return

        if not self.validate_signature(message, public_key):
            error = ErrorMessage(text="Invalid signature", ref_message_id=message.id)
            await self.send_message(websocket, error)
            await websocket.close()
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
        await self.send_message(websocket, welcome)

        add_user = AddUserMessage(
            name=message.name,
            public_key=public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        )
        await self.broadcast_to_others(websocket, add_user)

    async def handle_leave(self, websocket: websockets.ServerConnection, message: LeaveMessage):
        username = self.clients.get(websocket)
        if username:
            self.clients[websocket] = None
            del self.users[username]
            del self.active_user_keys[username]

            remove_user = RemoveUserMessage(name=username)
            await self.broadcast_to_others(websocket, remove_user)

        await websocket.close()

    async def handle_public_message(self, websocket: websockets.ServerConnection, message: PublicMessage):
        username = self.clients.get(websocket)
        if not username:
            error = ErrorMessage(text="User not authenticated", ref_message_id=message.id)
            await self.send_message(websocket, error)
            return

        routed = RoutedPublicMessage(text=message.text, from_name=username)
        await self.broadcast_to_others(websocket, routed)

    async def handle_private_message(self, websocket: websockets.ServerConnection, message: PrivateMessage):
        username = self.clients.get(websocket)
        if not username:
            error = ErrorMessage(text="User not authenticated", ref_message_id=message.id)
            await self.send_message(websocket, error)
            return

        if message.to_name not in self.users:
            error = ErrorMessage(text="Unknown recipient", ref_message_id=message.id)
            await self.send_message(websocket, error)
            return

        recipient_ws = self.users[message.to_name]
        routed = RoutedPrivateMessage(
            to_name=message.to_name,
            encrypted_text=message.encrypted_text,
            from_name=username
        )
        await self.send_message(recipient_ws, routed)

    async def handle_disconnect(self, websocket: websockets.ServerConnection):
        username = self.clients.get(websocket)
        if username:
            del self.users[username]
            if username in self.active_user_keys:
                del self.active_user_keys[username]

            remove_user = RemoveUserMessage(name=username)
            await self.broadcast_to_others(websocket, remove_user)

        if websocket in self.clients:
            del self.clients[websocket]

    async def handle_client(self, websocket: websockets.ServerConnection):
        self.clients[websocket] = None
        logger.info(f"New connection from {websocket.remote_address}")

        try:
            async for raw_message in websocket:
                try:
                    message = BaseSecureChatMessage.from_json(raw_message)
                    logger.debug(f"{self.clients[websocket] or '_NEW_'}: {message}")

                    if isinstance(message, JoinMessage):
                        await self.handle_join(websocket, message)
                    elif self.clients[websocket] is None:
                        error = ErrorMessage(text="Must join first")
                        await self.send_message(websocket, error)
                        await websocket.close()
                        break
                    elif isinstance(message, LeaveMessage):
                        await self.handle_leave(websocket, message)
                        break
                    elif isinstance(message, PublicMessage):
                        await self.handle_public_message(websocket, message)
                    elif isinstance(message, PrivateMessage):
                        await self.handle_private_message(websocket, message)
                    else:
                        error = ErrorMessage(text="Unknown message type")
                        await self.send_message(websocket, error)

                except json.JSONDecodeError:
                    error = ErrorMessage(text="Invalid JSON")
                    await self.send_message(websocket, error)
                except Exception as e:
                    logger.error(f"Error handling message: {e}")
                    error = ErrorMessage(text="Internal server error")
                    await self.send_message(websocket, error)

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.handle_disconnect(websocket)

    async def start_server(self, host: str = "localhost", port: int = 8765):
        logger.info(f"Starting server on {host}:{port}")
        async with websockets.serve(self.handle_client, host, port):
            await asyncio.Future()


async def main():
    keys_dir = sys.argv[1] if len(sys.argv) > 1 else "../sample_keys"
    user_keys = load_user_keys(keys_dir)
    server = SecureChatServer(user_keys)
    await server.start_server()


if __name__ == "__main__":
    asyncio.run(main())
import json
import sys
from dataclasses import dataclass
from selectors import SelectSelector
from typing import Optional, Union, Literal
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from secure_chat.chat_protocol.messages import BaseSecureChatMessage, WelcomeMessage, AddUserMessage, RemoveUserMessage, \
    PublicMessage, PrivateMessage, LeaveMessage, JoinMessage, UserInfo, RoutedPublicMessage, RoutedPrivateMessage, \
    ErrorMessage

from websocket_lib.websocket import WebSocket, WebSocketState

from websocket_lib.websocket_client import connect_client

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@dataclass
class Msg:
    text: str
    is_inbound: bool
    private_peer_name: Optional[str] = None

class ChatClient:

    users: list[UserInfo] = []
    messages: list[Msg] = []
    chat_state: Literal["disconnected", "connecting", "connected"] = "disconnected"
    websocket: WebSocket = None
    user_public_keys = {}

    def __init__(self, username: str, private_key_path: str, server_url: str = "ws://localhost:8765"):
        self.username = username
        self.private_key_path = private_key_path
        self.server_url = server_url

        with open(self.private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

    def _parse_user_input(self, user_input: str) -> PublicMessage | PrivateMessage | None:

        if not user_input:
            return None

        parts = user_input.strip().split()
        cmd = parts[0].lower()

        if cmd == 'users':
            count = int(parts[1]) if len(parts) > 1 else 5
            print([user.name for user in self.users[:count]])

        if cmd == 'messages':
            count = int(parts[1]) if len(parts) > 1 else 5
            print(self.messages[-count:])

        if cmd == 'public':
            if len(parts) < 2:
                return None
            text = ' '.join(parts[1:])
            return PublicMessage(text)

        if cmd == 'private':
            if len(parts) < 3:
                return None
            to_name = parts[1]
            text = ' '.join(parts[2:])
            public_key = self.user_public_keys[to_name]
            return PrivateMessage(to_name, self._encrypt_message(text, public_key))

        if cmd == '_close_':
            self.websocket.close()
            self.chat_state = "disconnected"

        return None


    def _handle_user_input(self):

        while self.chat_state != "disconnected":
            if self.chat_state == "connected":
                text = input("enter input: ")
                message = self._parse_user_input(text)
                if message:
                    self.websocket.send_text(message.to_json())
                    if isinstance(message, PrivateMessage):
                        message.encrypted_text = ' '.join(text.strip().split()[2:])
                    self.messages = [*self.messages, message]


    def run(self):

        self.chat_state = "connecting"

        try:
            self.websocket = connect_client(self.server_url)

            self.websocket.on_message = self._on_message
            self.websocket.on_error = self._on_error
            self.websocket._on_close = self._on_close

            self.websocket.start_threads()

            signature = self._sign_join_message()
            join_msg = JoinMessage(name=self.username, signature=signature)

            self.websocket.send_text(join_msg.to_json())

            # while client.chat_state != "disconnected":
            #     pass

            self._handle_user_input()

        except Exception as e:
            self.chat_state = "disconnected"
            logger.error(f"Connection failed: {e}")

    def _sign_join_message(self) -> str:
        message_dict = {"name": self.username}
        message_json = json.dumps(message_dict, sort_keys=True)
        signature = self.private_key.sign(
            message_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature.hex()

    def _on_message(self, data: bytes | str, ws: WebSocket) -> None:
        self._handle_server_message(str(data))


    def _on_error(self, e: Exception, ws: WebSocket) -> None:
        print(f"on_error")
        print(e)

    def _on_close(self, ws: WebSocket) -> None:
        print(f"on_close")

    def _handle_server_message(self, raw_message: str):
        try:
            message = BaseSecureChatMessage.from_json(raw_message)
            logger.debug(f"Received message: {message}")

            if isinstance(message, WelcomeMessage):
                if self.chat_state != "connecting":
                    raise(Exception(f"Welcome message received when state is {self.chat_state}: {raw_message}"))

                self.chat_state = "connected"
                self.users = [user for user in message.users if user.name != self.username]
                for user in message.users:
                    self.user_public_keys[user.name] = serialization.load_pem_public_key(
                        user.public_key.encode()
                    )


                logger.info(f"Connected as {self.username}")

            if self.chat_state != "connected":
                logger.warning(f"Chat state is {self.chat_state} - unexpected message {raw_message}" )
                return

            if isinstance(message, AddUserMessage):
                logger.info(f"Adding user {message.name}")
                user_info = UserInfo(name=message.name, public_key=message.public_key)
                self.users = [*self.users, user_info]
                self.user_public_keys[message.name] = serialization.load_pem_public_key(
                    message.public_key.encode()
                )

            elif isinstance(message, RemoveUserMessage):
                if self.chat_state != "connected":
                    return
                self.users = [user for user in self.users if user.name != message.name]
                if message.name in self.user_public_keys:
                    del self.user_public_keys[message.name]

            elif isinstance(message, RoutedPublicMessage):## add message if server sent us it
                new_msg = Msg(message.text, True)
                self.messages = [*self.messages, new_msg]

            elif isinstance(message, RoutedPrivateMessage):
                try:
                    decrypted_text = self._decrypt_message(message.encrypted_text)
                    new_msg = Msg(decrypted_text, True, message.from_name)
                    self.messages = [*self.messages, new_msg]
                except Exception as e:
                    error_msg = ErrorMessage(
                        text="Decryption failed",
                        ref_message_id=message.id
                    )
                    self.websocket.send_text(error_msg.to_json())

            elif isinstance(message, ErrorMessage):
                logger.warning(f"Error: {message.text}")

        except Exception as e:
            logger.error(f"Message handling error: {e}")

    def _decrypt_message(self, encrypted_text: str) -> str:
        encrypted_bytes = bytes.fromhex(encrypted_text)
        decrypted_bytes = self.private_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()
        )
        return decrypted_bytes.decode()

    @staticmethod
    def _encrypt_message(text: str, recipient_public_key) -> str:
        encrypted_bytes = recipient_public_key.encrypt(
            text.encode(),
            padding.PKCS1v15()
        )
        return encrypted_bytes.hex()


if __name__ == "__main__":
    import sys

    import sys

    username = sys.argv[1] if len(sys.argv) > 1 else "alice"
    private_key_path = sys.argv[2] if len(
        sys.argv) > 2 else r"C:\Users\User\PycharmProjects\modern-chat\sample_keys\alice.private.pem"

    client = ChatClient(username, private_key_path)

    client.run()
import asyncio
import logging

import websockets
import json
from dataclasses import dataclass
from typing import Optional, Literal
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Input, Select, Static, Button
from textual.reactive import reactive
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from secure_chat.chat_protocol.messages import (
    BaseSecureChatMessage, WelcomeMessage, AddUserMessage, RemoveUserMessage,
    PublicMessage, PrivateMessage, RoutedPublicMessage, RoutedPrivateMessage,
    JoinMessage, LeaveMessage, ErrorMessage, UserInfo
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@dataclass
class Msg:
    text: str
    is_inbound: bool
    private_peer_name: Optional[str] = None


class MessageBubble(Static):
    def __init__(self, msg: Msg, **kwargs):
        self.msg = msg
        content = self._format_message()
        super().__init__(content, **kwargs)
        self._update_styles()

    def _format_message(self) -> str:
        if self.msg.private_peer_name:
            direction = "From" if self.msg.is_inbound else "To"
            return f"{direction}: {self.msg.private_peer_name}\n{self.msg.text}"
        return self.msg.text

    def _update_styles(self):
        if self.msg.private_peer_name:
            self.add_class("private-message")
        else:
            self.add_class("public-message")


class MessageRow(Horizontal):
    def __init__(self, msg: Msg, **kwargs):
        super().__init__(**kwargs)
        self.msg = msg

    def compose(self) -> ComposeResult:
        if self.msg.is_inbound:
            yield MessageBubble(self.msg)
            yield Static("", classes="spacer")
        else:
            yield Static("", classes="spacer")
            yield MessageBubble(self.msg)


class ChatApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }

    #messages {
        height: 1fr;
        border: solid white;
        padding: 1;
    }

    #messages:focus {
        border: solid ansi_blue;
    }

    MessageRow {
        height: auto;
        margin: 1 0;
    }

    MessageBubble {
        padding: 0 2;
        border: round white;
        width: auto;
        max-width: 80%;
    }

    .private-message {
        background: red;
        color: white;
    }

    .public-message {
        background: green;
        color: white;
    }

    .spacer {
        width: 1fr;
    }

    #input_row {
        height: auto;
        min-height: 3;
        padding: 1;
        dock: bottom;
    }

    #target_select {
        width: 20;
    }

    #message_input {
        width: 1fr;
        margin-left: 1;
    }

    #send_button {
        width: 3;
        margin-left: 1;
    }

    #send_button:focus {
        border: solid ansi_blue;
    }
    """

    users: reactive[list[UserInfo]] = reactive([])
    messages: reactive[list[Msg]] = reactive([])
    chat_state: Literal["disconnected", "connecting", "connected"] = "disconnected"

    def __init__(self, username: str, private_key_path: str, server_url: str = "ws://localhost:8765"):
        super().__init__()
        self.username = username
        self.private_key_path = private_key_path
        self.server_url = server_url
        self.websocket = None
        self.private_key = None
        self.user_public_keys = {}

    async def on_mount(self):
        await self.load_private_key()
        await self.connect_to_server()
        self.query_one("#messages").focus()

    async def load_private_key(self):
        with open(self.private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)

    async def connect_to_server(self):
        self.chat_state = "connecting"
        try:
            self.websocket = await websockets.connect(self.server_url)

            signature = self.sign_join_message()
            join_msg = JoinMessage(name=self.username, signature=signature)
            await self.websocket.send(join_msg.to_json())

            asyncio.create_task(self.listen_for_messages())

        except Exception as e:
            self.chat_state = "disconnected"
            self.notify(f"Connection failed: {e}", severity="error")

    def sign_join_message(self) -> str:
        message_dict = {"name": self.username}
        message_json = json.dumps(message_dict, sort_keys=True)
        signature = self.private_key.sign(
            message_json.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature.hex()

    async def listen_for_messages(self):
        try:
            async for message in self.websocket:
                await self.handle_server_message(message)
        except websockets.exceptions.ConnectionClosed:
            self.chat_state = "disconnected"
            self.notify("Connection lost", severity="error")

    async def handle_server_message(self, raw_message: str):
        try:
            message = BaseSecureChatMessage.from_json(raw_message)
            logger.debug(f"Received message: {message}")
            if isinstance(message, WelcomeMessage):
                self.chat_state = "connected"
                self.users = message.users
                for user in message.users:
                    self.user_public_keys[user.name] = serialization.load_pem_public_key(
                        user.public_key.encode()
                    )
                self.notify(f"Connected as {self.username}")

            elif isinstance(message, AddUserMessage):
                if self.chat_state != "connected":
                    return
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

            elif isinstance(message, RoutedPublicMessage):
                if self.chat_state != "connected":
                    return
                new_msg = Msg(message.text, True)
                self.messages = [*self.messages, new_msg]

            elif isinstance(message, RoutedPrivateMessage):
                if self.chat_state != "connected":
                    return
                try:
                    decrypted_text = self.decrypt_message(message.encrypted_text)
                    new_msg = Msg(decrypted_text, True, message.from_name)
                    self.messages = [*self.messages, new_msg]
                except Exception as e:
                    error_msg = ErrorMessage(
                        text="Decryption failed",
                        ref_message_id=message.id
                    )
                    await self.websocket.send(error_msg.to_json())

            elif isinstance(message, ErrorMessage):
                self.notify(f"Error: {message.text}", severity="error")

        except Exception as e:
            self.notify(f"Message handling error: {e}", severity="error")

    def decrypt_message(self, encrypted_text: str) -> str:
        encrypted_bytes = bytes.fromhex(encrypted_text)
        decrypted_bytes = self.private_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()
        )
        return decrypted_bytes.decode()

    def encrypt_message(self, text: str, recipient_public_key) -> str:
        encrypted_bytes = recipient_public_key.encrypt(
            text.encode(),
            padding.PKCS1v15()
        )
        return encrypted_bytes.hex()

    def compose(self) -> ComposeResult:
        with Vertical():
            with ScrollableContainer(id="messages"):
                pass
            with Horizontal(id="input_row"):
                yield Select(
                    [("[green]ALL[/green]", "ALL")],
                    value="ALL",
                    id="target_select",
                    allow_blank=False
                )
                yield Input(placeholder="Type message...", id="message_input")
                yield Button("→", id="send_button", disabled=True)

    def watch_users(self, users: list[UserInfo]):
        select = self.query_one("#target_select", Select)
        options = [("[green]ALL[/green]", "ALL")] + [
            (f"[red]{user.name}[/red]", user.name) for user in users
            if user.name != self.username
        ]
        select.set_options(options)
        if select.value is Select.BLANK:
            select.value = "ALL"

    def watch_messages(self, messages: list[Msg]):
        messages_container = self.query_one("#messages")
        messages_container.remove_children()
        for msg in messages:
            messages_container.mount(MessageRow(msg))
        messages_container.scroll_end()

    async def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "message_input":
            await self._send_message()

    async def on_input_changed(self, event: Input.Changed):
        if event.input.id == "message_input":
            button = self.query_one("#send_button", Button)
            button.disabled = not event.value.strip()

    async def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "send_button":
            await self._send_message()

    async def _send_message(self):
        if self.chat_state != "connected":
            self.notify("Not connected", severity="error")
            return

        input_widget = self.query_one("#message_input", Input)
        text = input_widget.value.strip()
        if not text:
            return

        select = self.query_one("#target_select", Select)
        target = select.value

        try:
            if target == "ALL":
                message = PublicMessage(text=text)
                new_msg = Msg(text, False)
            else:
                recipient_key = self.user_public_keys.get(target)
                if not recipient_key:
                    self.notify(f"No public key for {target}", severity="error")
                    return

                encrypted_text = self.encrypt_message(text, recipient_key)
                message = PrivateMessage(to_name=target, encrypted_text=encrypted_text)
                new_msg = Msg(text, False, target)

            await self.websocket.send(message.to_json())
            self.messages = [*self.messages, new_msg]
            input_widget.clear()
            self.query_one("#messages").focus()

        except Exception as e:
            self.notify(f"Send error: {e}", severity="error")

    async def on_app_exit(self):
        if self.websocket and self.chat_state == "connected":
            leave_msg = LeaveMessage()
            await self.websocket.send(leave_msg.to_json())
            await self.websocket.close()


async def main():
    import sys
    if len(sys.argv) != 3:
        print("Usage: python client.py <username> <private_key_path>")
        return

    username = sys.argv[1]
    private_key_path = sys.argv[2]

    app = ChatApp(username, private_key_path)
    await app.run_async()


if __name__ == "__main__":
    asyncio.run(main())
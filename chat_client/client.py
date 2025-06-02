from dataclasses import dataclass
from typing import Optional, Union, Literal
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Input, Select, Static, Button
from textual.reactive import reactive
from textual.message import Message

from chat_protocol.messages import BaseSecureChatMessage, WelcomeMessage, AddUserMessage, RemoveUserMessage, \
    PublicMessage, PrivateMessage, LeaveMessage
from websocket_lib.websocket import WebSocket
from websocket_lib.websocket_client import connect_client


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
        self.styles.padding = (0, 2)
        self.styles.border = ("round", "white")
        self.styles.width = "auto"
        self.styles.max_width = "80%"

        if self.msg.private_peer_name:
            self.styles.background = "red"
            self.styles.color = "white"
        else:
            self.styles.background = "green"
            self.styles.color = "white"


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

    .spacer {
        width: 1fr;
    }

    #input_row {
        height: auto;
        min-height: 3;
        padding: 1;
        dock: bottom;
    }

    Select {
        width: 20;
    }

    Input {
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

    users: reactive[list[AddUserMessage]] = reactive([])
    messages: reactive[list[Msg]] = reactive([])

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

    def on_mount(self):
        self.users = ["Alice", "Bob", "Charlie"]
        # self.messages = [
        #     Msg("Hello everyone!", False),
        #     Msg("Hi there!", True),
        #     Msg("Secret message", True, "Alice"),
        #     Msg("Another secret", False, "Bob"),
        # ]
        self.query_one("#messages").focus()

    def watch_users(self, users: list[AddUserMessage]):
        select = self.query_one("#target_select", Select)
        options = [("[green]ALL[/green]", "ALL")] + [(f"[red]{user.name}[/red]", user.names) for user in users]
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
        input_widget = self.query_one("#message_input", Input)
        text = input_widget.value.strip()
        if not text:
            return

        select = self.query_one("#target_select", Select)
        target = select.value

        private_peer = None if target == "ALL" else target
        new_msg = Msg(text, False, private_peer)

        self.messages = [*self.messages, new_msg]
        input_widget.clear()
        self.query_one("#messages").focus()

        user = self._find_user(target) if target != "ALL" else None

        self.send_websocket_message(
            PrivateMessage(encrypted_text=user.public_key + text, name=user.name) if user
            else PublicMessage(text))

    chat_state: Literal[None, "connected", "disconnected"] = None

    def _find_user(self, name: str) -> Optional[AddUserMessage]:
        user = next((user for user in self.users if user.name == name), None)
        if not user:
            raise Exception(f"User {name} not found")
        return user

    def send_websocket_message(self, msg: Union[PublicMessage, PrivateMessage]):
        ws = self.query_one("WebSocketClient", WebSocket)
        ws.send_text(msg.to_json())

    def on_websocket_message(self, msg: str):
        message = BaseSecureChatMessage.from_json(msg)
        if isinstance(message, WelcomeMessage):
            if self.chat_state is not None:
                raise Exception("Chat state already set")
            self.chat_state = "connected"
        elif isinstance(msg, AddUserMessage):
            if self.chat_state is "disconnected":
                return
            # TODO: check duplicates, throw error or override
            self.users = self.users + [msg]
        elif isinstance(msg, RemoveUserMessage):
            if self.chat_state is "disconnected":
                return
            # TODO: check ex
            self.users = [user for user in self.users if user.name != msg.name]
        elif isinstance(message, PublicMessage):
            if self.chat_state is not "connected":
                raise Exception(f"Chat not connected {self.chat_state or 'None'}")
            new_msg = Msg(message.text, True)
            self.messages = [*self.messages, new_msg]
            self.query_one("#messages").scroll_end()  # TODO: should be done in listener
        elif isinstance(message, PrivateMessage):
            if self.chat_state is not "connected":
                raise Exception(f"Chat not connected - {self.chat_state or 'None'}")
            new_msg = Msg(message.encrypted_text, True, message.name)
            self.messages = [*self.messages, new_msg]
            self.query_one("#messages").scroll_end()  # TODO: should be done in listener
        elif isinstance(message, LeaveMessage):
            if self.chat_state is not "connected":
                raise Exception(f"Chat not connected - {self.chat_state or 'None'}")
            self.chat_state = "disconnected"
            self.users = []
            self.messages = []

    # def thread_loop(self):
    #     ws = connect_client("ws://localhost:8765")
    #     ws.on_message = self.on_websocket_message
    #     ws.on_error = lambda e: print(e)
    #     ws.on_close = lambda : print("closed")
    #     send hi


if __name__ == "__main__":
    app = ChatApp()
    app.run()

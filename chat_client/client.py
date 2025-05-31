from dataclasses import dataclass
from typing import Optional
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Input, Select, Static, Button
from textual.reactive import reactive
from textual.message import Message


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

    users: reactive[list[str]] = reactive([])
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
        self.messages = [
            Msg("Hello everyone!", False),
            Msg("Hi there!", True),
            Msg("Secret message", True, "Alice"),
            Msg("Another secret", False, "Bob"),
        ]
        self.query_one("#messages").focus()

    def watch_users(self, users: list[str]):
        select = self.query_one("#target_select", Select)
        options = [("[green]ALL[/green]", "ALL")] + [(f"[red]{user}[/red]", user) for user in users]
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


if __name__ == "__main__":
    app = ChatApp()
    app.run()
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, Select, Static, ListView, ListItem
from textual.reactive import reactive
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class Msg:
    is_inbound: bool
    text: str
    private_peer: Optional[str] = None


class MessageWidget(Static):
    def __init__(self, msg: Msg):
        super().__init__()
        # Set CSS classes for styling
        classes = ["message"]
        classes.append("inbound" if msg.is_inbound else "outbound")
        classes.append("private" if msg.private_peer else "public")
        self.add_class(" ".join(classes))

        # Format the message display
        header = f"{'From' if msg.is_inbound else 'To'} {msg.private_peer}" if msg.private_peer else ""
        content = f"{header}\n{msg.text}" if header else msg.text
        self.update(content)


class ChatApp(App):
    CSS_PATH = "client.tcss"

    # Properly declare reactive variable
    messages: reactive[List[Msg]] = reactive(list)

    def compose(self) -> ComposeResult:
        self.messages_view = ListView(id="messages")
        self.recipient_select = Select(
            options=[("ALL", "ALL"), ("Alice", "Alice"), ("Bob", "Bob")],
            value="ALL",
            id="recipient"
        )
        self.message_input = Input(placeholder="Type your message...", id="input")

        input_section = Horizontal(
            self.recipient_select,
            self.message_input,
            id="input_section"
        )

        yield Vertical(self.messages_view, input_section)

    def on_mount(self) -> None:
        self.message_input.focus()
        # Add some sample messages
        self.add_sample_messages()

    def add_sample_messages(self) -> None:
        """Add sample messages using reactive assignment"""
        sample_messages = [
            Msg(is_inbound=True, text="Hello everyone!", private_peer=None),
            Msg(is_inbound=False, text="Hi there!", private_peer=None),
            Msg(is_inbound=True, text="How are you doing?", private_peer="Alice"),
            Msg(is_inbound=False, text="I'm doing great, thanks!", private_peer="Alice"),
        ]

        # This triggers the watcher
        self.messages = sample_messages

    def watch_messages(self, messages: List[Msg]) -> None:
        """Reactive watcher - automatically called when messages changes"""
        self.messages_view.clear()
        for msg in messages:
            message_widget = MessageWidget(msg)
            self.messages_view.append(ListItem(message_widget))

        # Auto-scroll to bottom
        if messages:
            self.messages_view.scroll_end()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        content = event.value.strip()
        if not content:
            return

        recipient = self.recipient_select.value

        # Create the new message
        new_msg = Msg(
            is_inbound=False,
            text=content,
            private_peer=None if recipient == "ALL" else recipient
        )

        # Create new list to trigger reactive update
        # (Modifying the list in-place won't trigger the watcher)
        current_messages = list(self.messages)
        current_messages.append(new_msg)
        self.messages = current_messages

        # Clear input
        self.message_input.value = ""
        self.message_input.focus()

        # Simulate a response
        await self.simulate_response(recipient, content)

    async def simulate_response(self, recipient: str, original_message: str) -> None:
        """Simulate receiving a response message"""
        import asyncio
        await asyncio.sleep(1)

        responses = [
            "That's interesting!",
            "I see what you mean.",
            "Thanks for sharing!",
            "Good point!",
            "I agree with that."
        ]

        import random
        response_text = random.choice(responses)

        response_msg = Msg(
            is_inbound=True,
            text=response_text,
            private_peer=recipient if recipient != "ALL" else None
        )

        # Again, create new list to trigger reactive update
        current_messages = list(self.messages)
        current_messages.append(response_msg)
        self.messages = current_messages


if __name__ == "__main__":
    app = ChatApp()
    app.run()
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import queue
import json
from dataclasses import dataclass
from typing import Optional, Literal
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from secure_chat.chat_protocol.messages import BaseSecureChatMessage, WelcomeMessage, AddUserMessage, RemoveUserMessage, \
    PublicMessage, PrivateMessage, LeaveMessage, JoinMessage, UserInfo, RoutedPublicMessage, RoutedPrivateMessage, \
    ErrorMessage

from websocket_lib.websocket import WebSocket, WebSocketState
from websocket_lib.websocket_client import connect_client

# Configure appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@dataclass
class Msg:
    text: str
    is_inbound: bool
    private_peer_name: Optional[str] = None


class LoginFrame(ctk.CTkFrame):
    """Login screen for entering credentials"""

    def __init__(self, parent, on_connect_callback):
        super().__init__(parent)
        self.on_connect = on_connect_callback

        # Center container
        container = ctk.CTkFrame(self)
        container.place(relx=0.5, rely=0.5, anchor="center")

        # Title
        title = ctk.CTkLabel(container, text="Secure Chat Login",
                             font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=(20, 30))

        # Username input
        ctk.CTkLabel(container, text="Username:", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=20)
        self.username_entry = ctk.CTkEntry(container, width=250, placeholder_text="Enter username")
        self.username_entry.pack(padx=20, pady=(5, 15))

        # Key file input
        ctk.CTkLabel(container, text="Private Key File:", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=20)

        key_frame = ctk.CTkFrame(container, fg_color="transparent")
        key_frame.pack(padx=20, pady=(5, 20))

        self.key_entry = ctk.CTkEntry(key_frame, width=180, placeholder_text="Select key file...")
        self.key_entry.pack(side="left", padx=(0, 10))

        browse_btn = ctk.CTkButton(key_frame, text="Browse", width=50, command=self.browse_key)
        browse_btn.pack(side="left")

        # Server URL (optional, with default)
        ctk.CTkLabel(container, text="Server URL:", font=ctk.CTkFont(size=14)).pack(anchor="w", padx=20)
        self.server_entry = ctk.CTkEntry(container, width=250, placeholder_text="ws://localhost:8765")
        self.server_entry.insert(0, "ws://localhost:8765")
        self.server_entry.pack(padx=20, pady=(5, 20))

        # Connect button
        self.connect_btn = ctk.CTkButton(container, text="Connect", width=250, height=35,
                                         command=self.handle_connect)
        self.connect_btn.pack(padx=20, pady=(10, 20))

        # Status label
        self.status_label = ctk.CTkLabel(container, text="", font=ctk.CTkFont(size=12))
        self.status_label.pack(pady=(0, 10))

    def browse_key(self):
        filename = filedialog.askopenfilename(
            title="Select Private Key File",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            self.key_entry.delete(0, 'end')
            self.key_entry.insert(0, filename)

    def handle_connect(self):
        username = self.username_entry.get().strip()
        key_path = self.key_entry.get().strip()
        server_url = self.server_entry.get().strip()

        if not username or not key_path:
            self.status_label.configure(text="Please enter username and select key file",
                                        text_color="red")
            return

        self.connect_btn.configure(state="disabled", text="Connecting...")
        self.status_label.configure(text="Connecting...", text_color="orange")

        # Call the callback with credentials
        self.on_connect(username, key_path, server_url)

    def show_error(self, error_msg):
        self.connect_btn.configure(state="normal", text="Connect")
        self.status_label.configure(text=error_msg, text_color="red")

    def reset(self):
        self.connect_btn.configure(state="normal", text="Connect")
        self.status_label.configure(text="")


class ChatFrame(ctk.CTkFrame):
    """Main chat interface"""

    def __init__(self, parent, username, on_send_callback, on_disconnect_callback):
        super().__init__(parent)
        self.username = username
        self.on_send = on_send_callback
        self.on_disconnect = on_disconnect_callback

        # Header with disconnect button
        header = ctk.CTkFrame(self, height=50)
        header.pack(fill="x")
        header.pack_propagate(False)

        title = ctk.CTkLabel(header, text=f"Secure Chat - {username}",
                             font=ctk.CTkFont(size=16, weight="bold"))
        title.pack(side="left", padx=20)

        disconnect_btn = ctk.CTkButton(header, text="Disconnect", width=100,
                                       command=on_disconnect_callback)
        disconnect_btn.pack(side="right", padx=20, pady=10)

        # Main content area
        content = ctk.CTkFrame(self)
        content.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Left sidebar for users
        self.setup_sidebar(content)

        # Chat area
        self.setup_chat_area(content)

    def setup_sidebar(self, parent):
        sidebar = ctk.CTkFrame(parent, width=200)
        sidebar.pack(side="left", fill="y", padx=(0, 5))
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="Online Users",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)

        self.users_scroll = ctk.CTkScrollableFrame(sidebar)
        self.users_scroll.pack(fill="both", expand=True, padx=5, pady=5)

    def setup_chat_area(self, parent):
        chat_container = ctk.CTkFrame(parent)
        chat_container.pack(side="right", fill="both", expand=True)

        # Messages display
        self.messages_scroll = ctk.CTkScrollableFrame(chat_container)
        self.messages_scroll.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        # Input section
        input_frame = ctk.CTkFrame(chat_container)
        input_frame.pack(fill="x", padx=10, pady=(5, 10))

        # Message type selection
        type_frame = ctk.CTkFrame(input_frame)
        type_frame.pack(fill="x", padx=10, pady=(10, 5))

        self.message_type = ctk.StringVar(value="public")
        ctk.CTkRadioButton(type_frame, text="Public",
                           variable=self.message_type, value="public").pack(side="left", padx=(10, 20))

        ctk.CTkRadioButton(type_frame, text="Private to:",
                           variable=self.message_type, value="private").pack(side="left", padx=(0, 10))

        self.recipient_combo = ctk.CTkComboBox(type_frame, width=150, state="readonly")
        self.recipient_combo.pack(side="left")
        self.recipient_combo.set("Select user...")

        # Message input
        msg_frame = ctk.CTkFrame(input_frame)
        msg_frame.pack(fill="x", padx=10, pady=(5, 10))

        self.message_entry = ctk.CTkEntry(msg_frame, placeholder_text="Type your message...")
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)

        send_btn = ctk.CTkButton(msg_frame, text="Send", width=80, command=self.handle_send)
        send_btn.pack(side="right", padx=(5, 10), pady=10)

        self.message_entry.bind("<Return>", lambda e: self.handle_send())

    def handle_send(self):
        text = self.message_entry.get().strip()
        if not text:
            return

        msg_type = self.message_type.get()
        recipient = self.recipient_combo.get() if msg_type == "private" else None

        if msg_type == "private" and (not recipient or recipient == "Select user..."):
            messagebox.showwarning("Warning", "Please select a recipient for private message")
            return

        self.on_send(text, msg_type, recipient)
        self.message_entry.delete(0, 'end')

    def add_message(self, msg: Msg):
        """Add a message to the display"""
        msg_frame = ctk.CTkFrame(self.messages_scroll, fg_color="transparent")
        msg_frame.pack(fill="x", padx=5, pady=2)

        if msg.is_inbound:
            # Incoming messages - left aligned
            container = ctk.CTkFrame(msg_frame)
            container.pack(anchor="w", padx=(0, 50))

            if msg.private_peer_name:
                type_label = ctk.CTkLabel(container, text="[Private]",
                                          text_color="#FF6666", font=ctk.CTkFont(weight="bold"))
                type_label.pack(side="left", padx=(5, 2))

                sender_label = ctk.CTkLabel(container, text=f"{msg.private_peer_name}:",
                                            text_color="#FFAAAA")
                sender_label.pack(side="left", padx=(0, 5))
            else:
                type_label = ctk.CTkLabel(container, text="[Public]",
                                          text_color="#66B2FF", font=ctk.CTkFont(weight="bold"))
                type_label.pack(side="left", padx=(5, 5))
        else:
            # Outgoing messages - right aligned
            container = ctk.CTkFrame(msg_frame)
            container.pack(anchor="e", padx=(50, 0))

            you_label = ctk.CTkLabel(container, text="[You]", text_color="#90EE90")
            you_label.pack(side="left", padx=(5, 5))

            if msg.private_peer_name:
                type_label = ctk.CTkLabel(container, text="[Private]",
                                          text_color="#FF6666", font=ctk.CTkFont(weight="bold"))
                type_label.pack(side="left", padx=(0, 2))

                to_label = ctk.CTkLabel(container, text=f"to {msg.private_peer_name}:",
                                        text_color="#FFAAAA")
                to_label.pack(side="left", padx=(0, 5))
            else:
                type_label = ctk.CTkLabel(container, text="[Public]",
                                          text_color="#66B2FF", font=ctk.CTkFont(weight="bold"))
                type_label.pack(side="left", padx=(0, 5))

        msg_label = ctk.CTkLabel(container, text=msg.text, anchor="w", justify="left")
        msg_label.pack(side="left", padx=(0, 5))

        # Auto-scroll to bottom
        self.messages_scroll._parent_canvas.yview_moveto(1.0)

    def update_users(self, users: list[UserInfo]):
        """Update the users list"""
        # Clear existing
        for widget in self.users_scroll.winfo_children():
            widget.destroy()

        if not users:
            no_users = ctk.CTkLabel(self.users_scroll, text="No users online", text_color="gray")
            no_users.pack(pady=10)
            self.recipient_combo.configure(values=[])
            self.recipient_combo.set("Select user...")
        else:
            # Add users
            user_names = []
            for user in users:
                user_frame = ctk.CTkFrame(self.users_scroll)
                user_frame.pack(fill="x", pady=2, padx=5)

                user_label = ctk.CTkLabel(user_frame, text=f"● {user.name}",
                                          text_color="#90EE90", anchor="w")
                user_label.pack(fill="x", padx=10, pady=5)
                user_names.append(user.name)

            # Update combo
            self.recipient_combo.configure(values=user_names)
            if self.recipient_combo.get() not in user_names:
                self.recipient_combo.set("Select user...")


class SimpleChatGUI:
    def __init__(self):
        # Client state
        self.users: list[UserInfo] = []
        self.messages: list[Msg] = []
        self.chat_state: Literal["disconnected", "connecting", "connected"] = "disconnected"
        self.websocket: WebSocket = None
        self.user_public_keys = {}

        # Client settings
        self.username = ""
        self.private_key_path = ""
        self.server_url = "ws://localhost:8765"
        self.private_key = None

        # Thread-safe communication
        self.gui_queue = queue.Queue()

        # UI frames
        self.login_frame = None
        self.chat_frame = None

        self.setup_gui()
        self.check_queue()

    def setup_gui(self):
        self.root = ctk.CTk()
        self.root.title("Secure Chat")
        self.root.geometry("800x600")

        # Start with login screen
        self.show_login()

    def show_login(self):
        """Show the login screen"""
        if self.chat_frame:
            self.chat_frame.destroy()

        self.login_frame = LoginFrame(self.root, self.on_login_connect)
        self.login_frame.pack(fill="both", expand=True)

    def show_chat(self):
        """Show the chat screen"""
        if self.login_frame:
            self.login_frame.destroy()

        self.chat_frame = ChatFrame(self.root, self.username,
                                    self.on_chat_send, self.on_disconnect)
        self.chat_frame.pack(fill="both", expand=True)

        # Update users list if we have any
        if self.users:
            self.chat_frame.update_users(self.users)

        # Add existing messages
        for msg in self.messages:
            self.chat_frame.add_message(msg)

    def on_login_connect(self, username, key_path, server_url):
        """Handle connection from login screen"""
        self.username = username
        self.private_key_path = key_path
        self.server_url = server_url

        # Load private key
        try:
            with open(self.private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            self.login_frame.show_error(f"Failed to load key: {str(e)}")
            return

        # Start connection in background
        threading.Thread(target=self.run_client, daemon=True).start()

    def on_chat_send(self, text, msg_type, recipient):
        """Handle sending message from chat screen"""
        if msg_type == "public":
            self.send_public_message(text)
        else:
            self.send_private_message(text, recipient)

    def on_disconnect(self):
        """Handle disconnect button"""
        if self.websocket and self.websocket.state == WebSocketState.OPEN:
            self.websocket.close()

        self.chat_state = "disconnected"
        self.users.clear()
        self.messages.clear()
        self.user_public_keys.clear()

        self.show_login()

    def run_client(self):
        """Background thread for WebSocket connection"""
        self.chat_state = "connecting"

        try:
            self.websocket = connect_client(self.server_url)

            self.websocket.on_message = self._on_message
            self.websocket.on_error = self._on_error
            self.websocket.on_close = self._on_close

            self.websocket.start_threads()

            # Send join message
            signature = self._sign_join_message()
            join_msg = JoinMessage(name=self.username, signature=signature)
            self.websocket.send_text(join_msg.to_json())

        except Exception as e:
            self.gui_queue.put(("connection_error", str(e)))
            self.chat_state = "disconnected"

    def send_public_message(self, text: str):
        """Send public message"""
        message = PublicMessage(text)
        self.websocket.send_text(message.to_json())

        # Add to display
        self_msg = Msg(text, False)
        self.messages.append(self_msg)
        self.gui_queue.put(("new_message", self_msg))

    def send_private_message(self, text: str, recipient: str):
        """Send private message"""
        if recipient not in self.user_public_keys:
            messagebox.showerror("Error", f"No public key for {recipient}")
            return

        try:
            # Encrypt
            public_key = self.user_public_keys[recipient]
            encrypted_text = self._encrypt_message(text, public_key)

            # Send
            message = PrivateMessage(recipient, encrypted_text)
            self.websocket.send_text(message.to_json())

            # Add to display
            self_msg = Msg(text, False, recipient)
            self.messages.append(self_msg)
            self.gui_queue.put(("new_message", self_msg))

        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt: {e}")

    def check_queue(self):
        """Check for updates from background thread"""
        try:
            while True:
                event_type, data = self.gui_queue.get_nowait()

                if event_type == "connection_error":
                    if self.login_frame:
                        self.login_frame.show_error(f"Connection failed: {data}")

                elif event_type == "connected":
                    self.show_chat()

                elif event_type == "disconnected":
                    if self.chat_state == "connected":
                        messagebox.showinfo("Disconnected", "Connection to server lost")
                        self.on_disconnect()

                elif event_type == "new_message" and self.chat_frame:
                    self.chat_frame.add_message(data)

                elif event_type == "users_updated" and self.chat_frame:
                    self.chat_frame.update_users(self.users)

        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self.check_queue)

    # Original methods remain mostly the same

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
        logger.error(f"WebSocket error: {e}")
        self.gui_queue.put(("connection_error", str(e)))

    def _on_close(self, ws: WebSocket) -> None:
        # Only show disconnected message if we were actually connected
        if self.chat_state == "connected":
            self.gui_queue.put(("disconnected", None))
        elif self.chat_state == "connecting":
            # Connection failed during handshake
            self.gui_queue.put(("connection_error", "Connection closed by server"))
            self.chat_state = "disconnected"

    def _handle_server_message(self, raw_message: str):
        """Handle messages from server"""
        try:
            message = BaseSecureChatMessage.from_json(raw_message)
            logger.debug(f"Received: {message}")

            # Handle error messages during connection
            if isinstance(message, ErrorMessage) and self.chat_state == "connecting":
                # Connection failed - show error and reset
                self.gui_queue.put(("connection_error", message.text))
                self.chat_state = "disconnected"
                if self.websocket:
                    self.websocket.close()
                return

            if isinstance(message, WelcomeMessage):
                if self.chat_state != "connecting":
                    return

                self.chat_state = "connected"
                self.users = [user for user in message.users if user.name != self.username]

                for user in message.users:
                    self.user_public_keys[user.name] = serialization.load_pem_public_key(
                        user.public_key.encode()
                    )

                self.gui_queue.put(("connected", None))
                self.gui_queue.put(("users_updated", None))

            elif isinstance(message, AddUserMessage) and self.chat_state == "connected":
                user_info = UserInfo(name=message.name, public_key=message.public_key)
                self.users.append(user_info)
                self.user_public_keys[message.name] = serialization.load_pem_public_key(
                    message.public_key.encode()
                )
                self.gui_queue.put(("users_updated", None))

            elif isinstance(message, RemoveUserMessage) and self.chat_state == "connected":
                self.users = [u for u in self.users if u.name != message.name]
                if message.name in self.user_public_keys:
                    del self.user_public_keys[message.name]
                self.gui_queue.put(("users_updated", None))

            elif isinstance(message, RoutedPublicMessage) and self.chat_state == "connected":
                new_msg = Msg(f"{message.from_name}: {message.text}", True)
                self.messages.append(new_msg)
                self.gui_queue.put(("new_message", new_msg))

            elif isinstance(message, RoutedPrivateMessage) and self.chat_state == "connected":
                try:
                    decrypted = self._decrypt_message(message.encrypted_text)
                    new_msg = Msg(decrypted, True, message.from_name)
                    self.messages.append(new_msg)
                    self.gui_queue.put(("new_message", new_msg))
                except Exception as e:
                    error_msg = ErrorMessage(
                        text="Decryption failed",
                        ref_message_id=message.id
                    )
                    self.websocket.send_text(error_msg.to_json())

            elif isinstance(message, ErrorMessage):
                messagebox.showerror("Server Error", message.text)

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

    def run(self):
        """Start the GUI"""
        self.root.mainloop()


if __name__ == "__main__":
    app = SimpleChatGUI()
    app.run()
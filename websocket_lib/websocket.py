import socket
import struct
import threading
from enum import IntEnum
from queue import Empty, Queue
from typing import Optional, Callable, Union

from websocket_lib.protocol import OpCode, create_frame, parse_frame, Frame


class WebSocketState(IntEnum):
    # CONNECTING = 0
    OPEN = 1
    CLOSING = 2
    CLOSED = 3

class WebSocket:
    def __init__(self, sock: socket.socket, is_client: bool = True):
        self.sock = sock
        self.is_client = is_client
        self.state = WebSocketState.OPEN

        self.send_queue = Queue()
        self.send_lock = threading.Lock()
        self.running = True

        self._receive_thread: Optional[threading.Thread] = None
        self._send_thread: Optional[threading.Thread] = None

        self.on_message: Optional[Callable[[Union[str, bytes]], None]] = None
        self.on_close: Optional[Callable[[], None]] = None
        self.on_error: Optional[Callable[[Exception], None]] = None



    def start_threads(self) -> None:
        if self._receive_thread and self._receive_thread.is_alive():
            return

        self._receive_thread = threading.Thread(
            target=self._receive_loop,
            daemon=True
        )

        self._send_thread = threading.Thread(
            target=self._send_loop,
            daemon=True
        )

        self._receive_thread.start()
        self._send_thread.start()


    def close(self, code: int = 1000, reason: str = '') -> None:
        if self.state != WebSocketState.OPEN:
            return
        self.state = WebSocketState.CLOSING

        close_data = struct.pack('!H', code) + reason.encode('utf-8')
        self.send_queue.put((OpCode.CLOSE, close_data))

        self.running = False

        if self._receive_thread and self._receive_thread.is_alive():
            self._receive_thread.join(timeout=5.0)
        if self._send_thread and self._send_thread.is_alive():
            self._send_thread.join(timeout=5.0)

        self.sock.close()
        self.state = WebSocketState.CLOSED #socket is closed before executing the self.on close

        if self.on_close:
            self.on_close()


    def send_text(self, message: str) -> None:
        self._queue_frame(OpCode.TEXT, message.encode('utf-8'))

    def send_binary(self, data: bytes) -> None:
        self._queue_frame(OpCode.BINARY, data)

    def send_ping(self, data: bytes = b'') -> None:
        self._queue_frame(OpCode.PING, data)

    def send_pong(self, data: bytes = b'') -> None:
        self._queue_frame(OpCode.PONG, data)

    def _handle_receive_text(self, frame: Frame) -> None:
        print(f"handel text")
        if self.on_message:
            print(f"handel text exist. is client {self.is_client}")
            self.on_message(frame.payload.decode('utf-8'))
        else:
            print("handel text doesnt exist?")
            print(f"handel text exist. is client {self.is_client}")

    def _handle_receive_binary(self, frame: Frame) -> None:
        if self.on_message:
            self.on_message(frame.payload)

    def _handle_receive_ping(self, frame: Frame) -> None:
        self._queue_frame(OpCode.PONG, frame.payload)

    def _handle_receive_pong(self, frame: Frame) -> None:
        pass

    def _handle_receive_close(self, frame: Frame) -> None:
        if self.state == WebSocketState.OPEN:
            code = 1000
            if len(frame.payload) >= 2:
                code = struct.unpack('!H', frame.payload[:2])[0]
            self.close(code)

    def _queue_frame(self, opcode: OpCode, payload: bytes) -> None:
        if self.state != WebSocketState.OPEN:
            raise ConnectionError("WebSocket is not open")
        self.send_queue.put((opcode, payload))

    def _send_loop(self) -> None:
        try:
            while self.running or not self.send_queue.empty():
                try:
                    opcode, payload = self.send_queue.get(timeout=1.0)
                    frame_data = create_frame(opcode, payload, self.is_client)

                    with self.send_lock:
                        self.sock.sendall(frame_data)

                    self.send_queue.task_done()

                except Empty:
                    continue
                except Exception as e:
                    if self.on_error:
                        self.on_error(e)
                    break
        except Exception as e:
            if self.on_error:
                self.on_error(e)

    def _receive_loop(self) -> None:
        buffer = bytearray()

        handlers = {
            OpCode.TEXT: self._handle_receive_text,
            OpCode.BINARY: self._handle_receive_binary,
            OpCode.PING: self._handle_receive_ping,
            OpCode.PONG: self._handle_receive_pong,
            OpCode.CLOSE: self._handle_receive_close,
        }

        try:
            while self.running:
                try:
                    self.sock.settimeout(1.0)
                    data = self.sock.recv(4096)
                    if not data:
                        break

                    buffer.extend(data)

                    while len(buffer) >= 2:
                        try:
                            frame, frame_len = parse_frame(bytes(buffer))
                            buffer = buffer[frame_len:]

                            handler = handlers.get(frame.opcode)
                            if handler:
                                #print(f"{data} is in {handler.__name__}")
                                #print(handler)  # Before the call
                                #print(type(handler))

                                handler(frame)

                        except ValueError:
                            break

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.on_error:
                        self.on_error(e)
                    break
        except Exception as e:
            if self.on_error:
                self.on_error(e)

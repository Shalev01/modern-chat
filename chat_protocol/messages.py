from dataclasses import dataclass, asdict, field
import json
import inspect
import sys


@dataclass
class BaseChatMessage:
    _command: str = field(default="", init=False)

    def __post_init__(self):
        if not self._command:
            self._command = self.__class__.__name__.replace("ChatMessage", "")

    def to_json(self) -> str:
        data = asdict(self)
        data["_command"] = self._command
        return json.dumps(data)

    @classmethod
    def from_json(cls, json_str: str) -> "BaseChatMessage":
        data = json.loads(json_str)
        command = data.pop("_command", "")

        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if (inspect.isclass(obj) and
                    issubclass(obj, BaseChatMessage) and
                    obj != BaseChatMessage and
                    obj.__name__.replace("ChatMessage", "") == command):
                return obj(**data)

        return cls(**data)


@dataclass
class HiChatMessage(BaseChatMessage):
    name: str


@dataclass
class ByeChatMessage(BaseChatMessage):
    pass


@dataclass
class PrivateChatMessage(BaseChatMessage):
    name: str
    encrypted_text: str


@dataclass
class PublicChatMessage(BaseChatMessage):
    text: str


@dataclass
class ReadyChatMessage(BaseChatMessage):
    text: str


@dataclass
class AddUserChatMessage(BaseChatMessage):
    name: str
    public_key: str


@dataclass
class RemUserChatMessage(BaseChatMessage):
    name: str

@dataclass
class ErrorUserChatMessage(BaseChatMessage):
    text: str
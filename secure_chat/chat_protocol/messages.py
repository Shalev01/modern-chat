from dataclasses import dataclass, asdict, field
import json
import inspect
import sys
import uuid
from dacite import from_dict

@dataclass
class UserInfo:
    name: str
    public_key: str




@dataclass
class BaseSecureChatMessage:
    _command: str = field(default="", init=False)
    id: str = field(default_factory=lambda: str(uuid.uuid4()), init=False)

    def __post_init__(self):
        if not self._command:
            self._command = self.__class__.__name__

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)
        command = data.pop("_command", "")
        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if (inspect.isclass(obj) and
                    issubclass(obj, BaseSecureChatMessage) and
                    obj != BaseSecureChatMessage and
                    obj.__name__ == command):
                return from_dict(obj, data)
        raise Exception(f"Command not found {command}")



@dataclass
class JoinMessage(BaseSecureChatMessage):
    name: str
    signature: str


@dataclass
class LeaveMessage(BaseSecureChatMessage):
    pass


@dataclass
class PublicMessage(BaseSecureChatMessage):
    text: str

@dataclass
class PrivateMessage(BaseSecureChatMessage):
    to_name: str
    encrypted_text: str

@dataclass
class RoutedPrivateMessage(PrivateMessage):
    from_name: str

@dataclass
class RoutedPublicMessage(PublicMessage):
    from_name: str

@dataclass
class WelcomeMessage(BaseSecureChatMessage):
    users: list[UserInfo]


@dataclass
class AddUserMessage(BaseSecureChatMessage):
    name: str
    public_key: str


@dataclass
class RemoveUserMessage(BaseSecureChatMessage):
    name: str


@dataclass
class ErrorMessage(BaseSecureChatMessage):
    text: str
    ref_message_id: str | None = None


ClientToServerMessages = [
    JoinMessage,
    LeaveMessage,
    PublicMessage,
    PrivateMessage,
    ErrorMessage
]

ServerToClientMessages  =  [
    WelcomeMessage,
    AddUserMessage,
    RemoveUserMessage,
    RoutedPublicMessage,
    RoutedPrivateMessage,
    ErrorMessage
]
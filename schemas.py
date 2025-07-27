# schemas.py

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Literal, Tuple
from datetime import datetime
import base64
import binascii
import json
from pydantic import ValidationError


class MessageBase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid"
    )


class PrivateMessage(MessageBase):
    type: Literal["message"] = "message"
    from_: str = Field(..., alias="from")
    to: str
    to_type: Literal["user"] = "user"
    payload: str
    payload_type: Literal["text", "command"]
    timestamp: str

    @field_validator("from_", "to")
    @classmethod
    def validate_name(cls, v: str):
        if not v or not v.strip() or not v.isprintable():
            raise ValueError("Invalid name")
        if len(v) > 50:
            raise ValueError("Name too long")
        return v

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, v: str):
        if not isinstance(v, str) or len(v) > 1000:
            raise ValueError("Payload too long or invalid")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str):
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError("Timestamp must be in ISO format: YYYY-MM-DDTHH:MM:SS.ssssss")
        return v


class GroupMessage(MessageBase):
    type: Literal["group_message"] = "group_message"
    from_: str = Field(..., alias="from")
    to: str
    to_type: Literal["group"] = "group"
    content: str
    content_type: Literal["text"]
    timestamp: str

    @field_validator("from_", "to")
    @classmethod
    def validate_group_name(cls, v: str):
        if not v or not v.strip() or not v.isprintable():
            raise ValueError("Invalid name")
        if len(v) > 50:
            raise ValueError("Name too long")
        return v

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str):
        if not isinstance(v, str) or len(v) > 1000:
            raise ValueError("Content too long or invalid")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str):
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError("Timestamp must be in ISO format: YYYY-MM-DDTHH:MM:SS.ssssss")
        return v


class FileMessage(MessageBase):
    type: Literal["message_file"] = "message_file"
    from_: str = Field(..., alias="from")
    to: str
    to_type: Literal["user"] = "user"
    payload: str
    payload_type: Literal["file"]
    payload_id: str
    file_path: str
    timestamp: str

    @field_validator("from_", "to")
    @classmethod
    def validate_names(cls, v: str):
        if not v or not v.strip() or not v.isprintable():
            raise ValueError("Invalid name")
        if len(v) > 50:
            raise ValueError("Name too long")
        return v

    @field_validator("file_path")
    @classmethod
    def validate_path(cls, v: str):
        if not v or ".." in v or v.startswith("/") or len(v) > 255:
            raise ValueError("Invalid file path")
        return v

    @field_validator("payload")
    @classmethod
    def validate_base64(cls, v: str):
        try:
            base64.b64decode(v, validate=True)
        except binascii.Error:
            raise ValueError("Invalid base64 payload")
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: str):
        try:
            datetime.fromisoformat(v)
        except ValueError:
            raise ValueError("Timestamp must be in ISO format: YYYY-MM-DDTHH:MM:SS.ssssss")
        return v


def parse_and_validate_message(raw_data: str) -> Tuple[str, dict]:
    try:
        raw = json.loads(raw_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    msg_type = raw.get("type")
    if msg_type is None:
        # assume it's a private message with default type if it meets required keys
        required = {"from", "to", "payload", "payload_type", "timestamp"}
        if required.issubset(raw):
            raw["type"] = "message"
            raw["to_type"] = "user"
            msg_type = "message"

    try:
        if msg_type == "message":
            return "private", PrivateMessage(**raw).model_dump(by_alias=True)
        elif msg_type == "message_file":
            return "file", FileMessage(**raw).model_dump(by_alias=True)
        elif msg_type == "group_message":
            return "group", GroupMessage(**raw).model_dump(by_alias=True)
        else:
            raise ValueError(f"Unknown message type: {msg_type}")
    except ValidationError as ve:
        raise ve

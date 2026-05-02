from typing import List, Optional
from pydantic import BaseModel


# -----------------------------
# INPUT MESSAGE
# -----------------------------
class Message(BaseModel):
    role: str
    content: str


# -----------------------------
# OPENAI REQUEST
# -----------------------------
class ChatCompletionRequest(BaseModel):
    model: Optional[str] = "qwen2.5:3b"
    messages: List[Message]
    temperature: Optional[float] = 0.2
    stream: Optional[bool] = False


# -----------------------------
# OUTPUT MESSAGE
# -----------------------------
class AssistantMessage(BaseModel):
    role: str = "assistant"
    content: str


# -----------------------------
# OUTPUT CHOICE
# -----------------------------
class Choice(BaseModel):
    index: int = 0
    message: AssistantMessage
    finish_reason: str = "stop"


# -----------------------------
# OPENAI RESPONSE
# -----------------------------
class ChatCompletionResponse(BaseModel):
    id: str = "chatcmpl-1"
    object: str = "chat.completion"
    choices: List[Choice]
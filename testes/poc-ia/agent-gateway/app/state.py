from typing import TypedDict


class AgentState(TypedDict):
    question: str
    intent: str
    answer: str
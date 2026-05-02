from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

from app.llm import llm
from app.tools import tools

prompt = ChatPromptTemplate.from_messages(
    [
        ("system", """
Você é um assistente corporativo.

Regras:
- quando a pergunta envolver servidores, infraestrutura ou inventário:
  use ferramentas disponíveis
- caso contrário:
  responda normalmente
"""),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ]
)

agent = create_tool_calling_agent(
    llm,
    tools,
    prompt
)

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True
)


async def ask_agent(question: str):
    result = await executor.ainvoke(
        {"input": question}
    )
    return result["output"]
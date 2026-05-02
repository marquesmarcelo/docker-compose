# Configurando o OpenWebUI para usar o LLM Gateway

1. Vá para Admin Panel -> Settings -> Connections. Desative todas as conexões mantendo apenas OpenAI API.

2. Clique no botão em formato de '+', abaixo do nome da OpenAI API e no formulário informe:
* Connection type: Esternal
* URL: http://llm-gateway:8000/v1
* Auth: None

3. Clique no botão para testar

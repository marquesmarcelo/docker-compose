# Antigravity Skill & Padrões do Projeto

Este arquivo documenta as diretrizes arquiteturais, de design e de ferramentas utilizadas neste projeto. Sempre que for adicionar novas features ou refatorar algo, siga estritamente estas diretrizes.

## Stack Tecnológica
- **Linguagem:** Python 3
- **Framework Web:** FastAPI
- **Configurações:** `pydantic-settings`
- **Banco de Dados/Vetores:** PostgreSQL (via `psycopg`) para Vector Store.
- **Cache & Métricas:** Redis
- **Embeddings:** Ollama local.
- **Testes:** Pytest (com uso de `unittest.mock` para isolamento).
- **Processamento RAG:** LangChain (para carregamento de PDF e text splitting).

## Arquitetura e Estrutura de Diretórios
O projeto utiliza **Clean Architecture (Ports and Adapters)**, garantindo forte separação de responsabilidades (SRP) e inversão de dependência (DIP).

### 1. `core/`
- Arquivos de configuração global e setup inicial da aplicação. 
- O arquivo `config.py` exporta a classe `Settings` estendida do `BaseSettings` do Pydantic.

### 2. `domain/ports/`
- Contém **somente Interfaces (Classes Abstratas)**.
- Estas classes utilizam `abc.ABC` e `@abstractmethod`.
- A lógica de negócio jamais deve conhecer a implementação, apenas a interface definida no Port.

### 3. `infrastructure/`
- Contém as implementações concretas (Adapters) dos Ports definidos em `domain/ports/`.
- Cada implementação de infra (ex: Redis, Postgres, chamadas HTTP) deve residir aqui, subdividida por responsabilidade:
  - `cache/`
  - `database/`
  - `embedder/`
  - `metrics/`

### 4. `use_cases/`
- Onde a **regra de negócio** real da aplicação reside.
- Casos de uso devem ser classes independentes que recebem as instâncias dos Ports necessários através de seus construtores (Injeção de Dependência).
- Eles não devem possuir referências a bibliotecas da camada Web (FastAPI) nem a dependências concretas (psycopg, redis, requests).

### 5. `api/`
- A camada de entrada para tráfego web do FastAPI.
- **`routers/`**: Contém as rotas (`@router.post`, `@router.get`, etc). A lógica nas rotas deve ser mínima (apenas conversão de dados e chamada do Caso de Uso apropriado).
- **`dependencies.py`**: O local exclusivo onde a magia do FastAPI (`Depends()`) acontece. É aqui que os Adapters da `infrastructure/` são instanciados e passados para instanciar os Casos de Uso.

### 6. `tests/`
- **Unitários (`tests/unit/`)**: Todo Caso de Uso deve ser testado isoladamente, utilizando `unittest.mock.MagicMock` para injetar comportamentos "fakes" dos Ports. A regra de negócio deve ser validada cobrindo todas as saídas lógicas.

---

## Princípios (SOLID)

1. **S (Responsabilidade Única)**: Cada arquivo/módulo deve fazer apenas uma coisa. Não misture definição de rota com chamada de banco de dados.
2. **O (Aberto/Fechado)**: Não altere o `QueryUseCase` ou `IngestUseCase` para adicionar suporte a Memcached; ao invés disso, crie um novo Adapter (`MemcachedCache`) implementando o `CachePort` e apenas mude a injeção em `dependencies.py`.
3. **D (Inversão de Dependência)**: Módulos de alto nível (Casos de Uso) não devem depender de módulos de baixo nível (Redis, Banco de Dados). Ambos devem depender de abstrações (Ports).

---

## Fluxo Comum para Novas Features

Ao ser solicitado a criar uma nova rota ou processo:

1. Defina/Atualize as interfaces em `domain/ports/` caso seja necessário lidar com uma nova infraestrutura.
2. Escreva/Atualize a implementação daquela infra em `infrastructure/`.
3. Crie ou modifique o caso de uso em `use_cases/` para realizar o trabalho que o usuário quer.
4. Faça o mock dessas abstrações e crie os testes unitários da sua nova regra de negócio em `tests/unit/`.
5. Adicione as injeções em `api/dependencies.py`.
6. Crie ou modifique as rotas em `api/routers/` chamando o respectivo Caso de Uso.

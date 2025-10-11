# Instruções para iniciar o laboratório localmente

Os contêineres `ubuntu-novnc` e `kali-xrdp` são grandes demais para serem armazenados na Docker Registry gratuita. Por isso, você precisará compilá-los localmente antes de iniciar o laboratório.

1. Clone o repositório e compile as imagens:

```bash
$ git clone https://github.com/marquesmarcelo/docker-compose.git
$ cd docker-compose/kali-xrdp
$ docker build -t kali-xrdp:1.0.0 .
$ cd ../ubuntu-novnc
$ docker build -t ubuntu-novnc:1.0.0 .
```

2. Agora entre na pasta do curso e execute o `docker-compose`:

```bash
$ cd ../seg42
$ docker-compose up -d
```

3. Abra o seu navegador e acesse http://localhost:8080/vnc.html. A senha de acesso está na variável VNC_PASSWORD do arquivo docker-compose.yaml.

## Usuários

Abaixo a lista de usuários e senhas desta simulação:

| Aplicação | Usuário | Senha |
| :--- | :--- | :--- |
| **noVNC** | - | rnpesr |
| **root** | - | rnpesr |
| **aluno** | - | rnpesr |
| **Cortex** | admin | labuser |
| **MISP** | admin@admin.test | admin ou RnpEsr123456@ |
| **TheHive** | admin@thehive.local | secret |


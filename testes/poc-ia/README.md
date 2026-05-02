# Configuração do WSL e Ubuntu no Windows 11

1. Faça a Instalação do WSL 2 e do Ubuntu no Windows 11. Após abra o Terminal do Ubuntu.

2. Vamos iniciar com a instalação do Docker:

```bash
$ sudo apt update && sudo apt upgrade -y

$ sudo apt install -y \
  ca-certificates \
  curl \
  gnupg \
  lsb-release

$ sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

$ echo \
"deb [arch=$(dpkg --print-architecture) \
signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

$ sudo apt update
$ sudo apt install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

$ sudo usermod -aG docker $USER
$ newgrp docker
```

3. Agora vamos verificar se a GPU esta disponível no WSL

```bash
$ nvidia-smi
Fri May  1 14:26:08 2026
+-----------------------------------------------------------------------------------------+
| NVIDIA-SMI 590.57                 Driver Version: 591.86         CUDA Version: 13.1     |
+-----------------------------------------+------------------------+----------------------+
| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |
| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  Compute M. |
|                                         |                        |               MIG M. |
|=========================================+========================+======================|
|   0  NVIDIA GeForce GTX 1660 ...    On  |   00000000:01:00.0  On |                  N/A |
| 32%   45C    P8             16W /  125W |     789MiB /   6144MiB |     16%      Default |
|                                         |                        |                  N/A |
+-----------------------------------------+------------------------+----------------------+

+-----------------------------------------------------------------------------------------+
| Processes:                                                                              |
|  GPU   GI   CI              PID   Type   Process name                        GPU Memory |
|        ID   ID                                                               Usage      |
|=========================================================================================|
|    0   N/A  N/A              36      G   /Xwayland                             N/A      |
+-----------------------------------------------------------------------------------------+

$ docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi
(...)
docker: Error response from daemon: could not select device driver "" with capabilities: [[gpu]].
```

4. Neste cenário a GPU esta sendo visivel no WSL porém não esta disponível para futuros Conteiners Docker


5. Instale NVIDIA Container Toolkit:

```bash
$ curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
```

```bash
$ curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
```

```bash
$ sudo apt update
$ sudo apt install -y nvidia-container-toolkit
```

6. Configurar:

```bash
$ sudo nvidia-ctk runtime configure --runtime=docker
```

7. Reiniciar daemon:

```bash
$ sudo service docker restart
```

8. Teste novamente:

```bash
$ docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi
```

# Realizando a configuração dos componentes:

1. Baixando modelo para serem usados no ollama:

```bash
$ docker exec -it ollama ollama pull qwen2.5:3b
$ docker exec -it ollama ollama pull nomic-embed-text
```

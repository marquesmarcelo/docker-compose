# IMPORTANTE

Registrar no arquivo hosts da máquina local o IP da máquina docker que esta executando a aplicação. No exemplo abaixo o IP seria '172.28.217.99'

```conf
172.28.217.99 	gitlab.esr.local
```
# Login

Username: root
Password: RnpEsr123@

# Configuração do GitLab Runner

Após iniciar o GitLab e o GitLab Runner usando docker-compose up -d, você precisará registrar o GitLab Runner. Aqui estão os passos para registrar o runner:

## Obtenha o Token do Runner:

Acesse a interface web do GitLab (http://gitlab.esr.local ou o URL que você configurou).

Vá para a seção de administração do GitLab: Admin Area > Overview > CI/CD > Runners > New instance runner.

* marque 'Run untagged jobs'
* clique em 'Create runner'

O comando abaixo será mostrado na página web após criar o runner. Copie o valor do parametro '--token' pois iremos utiliza-lo no próximo passo para registrar o runner:

```bash
gitlab-runner register  --url http://gitlab.esr.local  --token glrt-TswupT6UsyJqsJxYnjsd
```

Registre o Runner:

Execute o comando de registro do runner a partir do contêiner do GitLab Runner:

```bash
docker exec -it gitlab-runner gitlab-runner register
```

Durante o processo de registro, você precisará fornecer:

```bash
Runtime platform                                    arch=amd64 os=linux pid=19 revision=6428c288 version=17.2.0
Running in system-mode.

Enter the GitLab instance URL (for example, https://gitlab.com/):
'http://gitlab.esr.local'
Enter the registration token:
'glrt-TswupT6UsyJqsJxYnjsd'
Verifying runner... is valid                        runner=TswupT6Us
Enter a name for the runner. This is stored only in the local config.toml file:
[b49940b2740c]: 'gitlab-esr-local'
Enter an executor: instance, docker-windows, docker+machine, custom, shell, ssh, parallels, virtualbox, docker, kuberne>'docker'
Enter the default Docker image (for example, ruby:2.7):
'gitlab-ce:latest'
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically r>
```

## Configuração do config.toml:

O processo de registro criará automaticamente o arquivo /etc/gitlab-runner/config.toml. Verifique se ele contém algo semelhante a isto:

```toml
concurrent = 1
check_interval = 0

[[runners]]
  name = "gitlab-esr-local"
  url = "http://gitlab.esr-local/"
  token = "YOUR_RUNNER_TOKEN"
  executor = "docker"
  [runners.custom_build_dir]
  [runners.docker]
    tls_verify = false
    image = "alpine:latest"
    privileged = true
    disable_entrypoint_overwrite = false
    oom_kill_disable = false
    disable_cache = false
    volumes = ["/cache"]
    shm_size = 0
  [runners.cache]
```

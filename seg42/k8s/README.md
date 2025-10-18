# Ordem de execução

1. Os conteineres abaixo não tem ordem de execução pois não possuem dependência entre sí.

```bash
$ cd ./docker-compose/seg42

$ kubectl apply -f novnc
$ kubectl apply -f kali-xrdp
$ kubectl apply -f misp-mysql
$ kubectl apply -f redis
$ kubectl apply -f elasticsearch
$ kubectl apply -f minio
$ kubectl apply -f cassandra

```

2. Os conteineres abaixo precisam ser executados apenas quando os conteineres acima estiverem up:

```bash
$ kubectl apply -f cortex-local
$ kubectl apply -f misp-local
$ kubectl apply -f misp-modules
```

3. Os próximos conteineres só podem ser executados apenas quandos os conteineres acima estiverem up:

```
$ kubectl apply -f thehive

```

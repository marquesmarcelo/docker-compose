# Fonte

https://medium.com/@fredrik.maxfield/simplified-zabbix-deployment-step-by-step-with-docker-and-portainer-19e85c08a65b

# Login

* endereço: http://localhost:8080
* usuário: Admin (primeira letra maiuscula)
* senha: zabbix

# SNMPv3

Para consultar um determinado grupo da MIB

```bash
snmpwalk -v3 -On -u testainers -l authPriv \
  -a SHA -A authpass \
  -x AES -X privpass \
  localhost:5161 .1.3.6.1.2.1.1
```

Para pegar um valor especifico que informa o email do administrador do equipamento
```bash
snmpget -v3 -u testainers -l authPriv \
  -a SHA -A authpass \
  -x AES -X privpass \
  localhost:5161 .1.3.6.1.2.1.1.4.0
```

Para configurar um valor especifico que informa o email do administrador do equipamento
```bash
snmpset -v3 -u testainers -l authPriv \
  -a SHA -A authpass \
  -x AES -X privpass \
  localhost:5161 .1.3.6.1.2.1.1.4.0 s "admin@testainers.com"
  ```

# Códigos MIBs no Linux

Lista de alguns códigos MIBs interessantes para sistema Linux
```bash
# Carga da CPU (1, 5, 15 minutos)
.1.3.6.1.4.1.2021.10.1.3

# Uso por núcleo (percentual)
.1.3.6.1.4.1.2021.11

# Memória total, livre e usada
.1.3.6.1.4.1.2021.4

# Memória swap
.1.3.6.1.4.1.2021.9

# Partições e uso de disco
.1.3.6.1.4.1.2021.9.1

# Uso em porcentagem por partição
.1.3.6.1.4.1.2021.9.1.9

# Listar todas as interfaces de rede
.1.3.6.1.2.1.2.2.1.2

# Obter estatísticas completas de todas as interfaces
IF-MIB::ifTable

# Endereços MAC:
.1.3.6.1.2.1.2.2.1.6

# Status operacional (up/down):
.1.3.6.1.2.1.2.2.1.8

# Tráfego de entrada (bytes recebidos):
.1.3.6.1.2.1.2.2.1.10

# Tráfego de saída (bytes enviados):
.1.3.6.1.2.1.2.2.1.16

# Taxa de erros (pacotes com erro):
.1.3.6.1.2.1.2.2.1.14

# Consultar uma interface específica
## Primeiro descubra o índice da interface com:
.1.3.6.1.2.1.2.2.1.1

## Depois consulte usando o índice (substitua X pelo índice desejado):
.1.3.6.1.2.1.2.2.1.10.X
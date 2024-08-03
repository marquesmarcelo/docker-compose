# Objetivo

Configurar um servidor de DNS primário e secundário usando o Bind9

# Fonte:
https://github.com/labbsr0x/docker-dns-bind9


# Testar DNS

```bash
dig @127.0.0.1 -p 5353 www.esr.local
dig @127.0.0.1 -p 5453 www.esr.local
```

# Hardening Switch

1. Atualização de Firmware

2. Configuração de Senhas Fortes e uso de chaveiro

3. Habilite a autenticação via TACACS+ ou RADIUS para gerenciamento centralizado de credenciais.

4. Desabilitação de Serviços Desnecessários: HTTP; Telnet; CDP (Cisco Discovery Protocol); LLDP

Configuração de Acesso Seguro SSH com timeout de sessão para desconectar sessões ociosas após um período de inatividade.

Configuração de Distribuição Automática de VLANs com VLAN Trunking Protocol (VTP) - Apenas switches CISCO

Desative o trunking automático (DTP) em portas que não precisam de trunking.

Habilite o BPDU Guard em portas de acesso para evitar ataques de Spanning Tree Protocol (STP).

Configuração do Switch Core como STP Root

Habilite o Root Guard para proteger a raiz da árvore STP.

Habilitação de Port Security para limitar em 3 o número de endereços MAC que podem ser aprendidos em uma porta.

Habilitação de DHCP Snooping parar prevenir ataques de spoofing de DHCP.

Habilitação de Dynamic ARP Inspection (DAI) para prevenir ataques de ARP spoofing.

Configuração de ACLs (Access Control Lists) com objetivo de impedir comunicação entre desktops.

Restrinja o acesso de gerenciamento apenas a endereços IP confiáveis.

Configuração de Logging para envio de logs a servidor centralizado.

Configure SNMP de forma segura, usando SNMPv3 com autenticação e criptografia. Se não possível SNMP v2. Habilitar apenas comunidade de leitura.

Habilitação de Storm Control para limite o tráfego de broadcast, multicast e unicast em portas.

Configuração de Autenticação 802.1X para autenticação baseada em MAC (MAC Authentication Bypass - MAB) para dispositivos que não suportam 802.1X.

Desativação de Portas Não Utilizadas

Habilitação de IGMP Snooping para controle o tráfego multicast.

Habilitação de QoS para priorização do tráfego crítico e evitar ataques de negação de serviço (DoS).

Habilitação de Controles de Segurança para IPv6: RA Guard; DHCPv6 Snooping

Backup Regular das Configurações do Switch

Configure NTP para usar autenticação e sincronize com servidores NTP confiáveis.

Habilitação de MAC Address Notification para monitorar mudanças nos endereços MAC.

Habilitação de Rapid Spanning Tree Protocol (RSTP) ou Multiple Spanning Tree Protocol (MSTP)

Configure BPDU Filter para evitar que portas de acesso enviem BPDUs.

Configuração de Segurança de VTP em modo transparente se precisar usá-lo (apenas em switch CISCO).

Habilitação de EtherChannel para agregar links e melhorar a redundância. Use o protocolo LACP (Link Aggregation Control Protocol) para negociação automática de canais.

Padronização de Fabricante

Segmentação de VLANs: Diminua a quantidade de máquinas em uma VLAN (máximo 256) e configure Inter-VLAN Routing.

Controle de Acesso Físico para assegurar que os switches estejam em locais seguros, com acesso físico restrito apenas a pessoal autorizado.

Segurança de Console configurando senhas seguras para acesso ao console e desative o acesso não autorizado. Colocar as senha no Chaveiro central

Proteção contra Ataques de Spoofing implementando IP Source Guard para prevenir ataques de IP spoofing.

Segurança de Logs

Envie logs para um servidor de logs centralizado e configure alertas para eventos críticos.

Segurança de SNMP

Restrinja o acesso SNMP apenas a endereços IP confiáveis.

Monitoramento Contínuo

Implemente soluções de monitoramento contínuo para detectar e responder a atividades suspeitas em tempo real.

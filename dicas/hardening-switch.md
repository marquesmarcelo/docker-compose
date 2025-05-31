# Checklist de Hardening para Switch (Cisco)

Este checklist visa fornecer um guia abrangente para fortalecer a segurança de switches Cisco, cobrindo diversas áreas desde a configuração inicial até a proteção avançada e monitoramento.

## 1. Atualizações e Configurações Iniciais

- [ ] Atualizou o IOS (Internetwork Operating System) do switch para a versão mais recente e estável.

- [ ] Configurou Senhas Fortes para todos os acessos administrativos (enable, console, VTY). Cadastrou as senhas no chaveiro central (ou cofre de senhas). 

- [ ] Usou Chaveiro (SSH Key) para autenticação em acessos SSH, desabilitando a autenticação por senha para SSH quando possível.

- [ ] Habilitou autenticação via TACACS+ ou RADIUS para gerenciamento centralizado de credenciais e auditoria.

- [ ] Configurou o hostname do switch de forma clara e identificável.

- [ ] Configurou um banner de login (login banner) com avisos legais e de segurança.

## 2. Acessos e Protocolos de Gerenciamento

- [ ] Habilitou SSH para acesso remoto seguro, configurando um timeout de sessão (e.g., 30-60 segundos) para desconectar sessões ociosas após inatividade. 

- [ ] Desabilitou Telnet, HTTP e outros serviços desnecessários (e.g., CDP, LLDP, Finger, BOOTP, HTTP server). 

- [ ] Restringiu o acesso de gerenciamento (SSH, HTTPS, SNMP) apenas a endereços IP confiáveis e redes de gerenciamento dedicadas.

- [ ] Implementou controle de acesso baseado em função (RBAC) para administração, atribuindo diferentes níveis de privilégio a usuários e grupos. 

- [ ] Habilitou autenticação 802.1X (e MAB para dispositivos sem suporte ao 802.1X) para controle de acesso à rede, utilizando um servidor RADIUS. 

## 3. Proteção contra Ataques

- [ ] Habilitou Port Security para limitar o número de endereços MAC aprendidos por porta (e.g., máximo de 3) e configurou a ação a ser tomada (e.g., restrict ou shutdown) em caso de violação. 

- [ ] Habilitou DHCP Snooping para prevenir ataques de spoofing de DHCP (servidores DHCP não autorizados) e proteger a integridade do banco de dados DHCP.

- [ ] Habilitou Dynamic ARP Inspection (DAI) para prevenir ataques de ARP spoofing e envenenamento de cache ARP.

- [ ] Habilitou IP Source Guard para prevenir ataques de IP spoofing, garantindo que o tráfego de uma porta tenha o endereço IP de origem esperado.

- [ ] Habilitou BPDU Guard nas portas de acesso (portas de borda) para proteger contra ataques no protocolo STP, desligando a porta se uma BPDU for recebida. 

- [ ] Habilitou Root Guard para proteger a raiz da árvore STP, prevenindo que um switch não autorizado se torne o root bridge. 

- [ ] Configurou o switch Core como o Root Bridge no Spanning Tree Protocol para garantir uma topologia STP previsível e segura.

- [ ] Habilitou o BPDU Filter nas portas de acesso que não devem participar do STP (e.g., para hosts finais).

- [ ] Habilitou o Storm Control para limitar tráfego de broadcast, multicast e unicast excessivo em portas, prevenindo ataques de inundação e degradação de desempenho.

- [ ] Habilitou RA Guard (Router Advertisement Guard) e DHCPv6 Snooping para segurança de IPv6, prevenindo anúncios de roteador maliciosos e servidores DHCPv6 não autorizados.

- [ ] Implementou proteção contra ataques de VLAN hopping (VLAN pruning, Private VLANs) em portas trunk ou específicas. 

## 4. Controle e Gerenciamento de Tráfego

- [ ] Habilitou IGMP Snooping para otimizar o tráfego multicast, encaminhando pacotes multicast apenas para as portas que possuem receptores interessados.

- [ ] Configurou QoS (Quality of Service) para priorizar o tráfego crítico (e.g., voz, vídeo) e prevenir DoS em links congestionados.

- [ ] Habilitou EtherChannel com LACP (Link Aggregation Control Protocol) para melhorar a redundância e o desempenho de links agregados entre switches.

## 5. Segurança de Logs e Monitoramento

- [ ] Configuração de Logging para envio de logs de segurança a um servidor Syslog centralizado e seguro. 

- [ ] Configurou alertas para eventos críticos (tentativas de login falhas, alterações de configuração, detecção de intrusão) e monitoramento contínuo de atividades suspeitas.

- [ ] Configurou SNMPv3 com autenticação e criptografia para monitoramento seguro (se SNMP for utilizado), desabilitando SNMPv1/v2c.

- [ ] Restringiu o acesso SNMP apenas a endereços IP confiáveis.

- [ ] Utilizou ferramentas de SIEM/XDR (como Wazuh) para correlação e análise de logs e eventos de segurança.

## 6. Proteção Física e Acessos Locais

- [ ] Controle de Acesso Físico: Garante que os switches estão em locais seguros (e.g., racks trancados, salas de equipamentos) e com acesso restrito a pessoal autorizado.

- [ ] Segurança de Console: Configurou senhas seguras e usou chaveiro para acesso ao console, desabilitando o acesso não autorizado (e.g., login local ou login authentication).

## 7. Configurações de VLANs e Segmentação de Rede

- [ ] Segmentou VLANs de acordo com a política de segurança, limitando a quantidade de dispositivos por VLAN (e.g., máximo de 256 dispositivos ou um número que otimize o domínio de broadcast). 

- [ ] Configurou Inter-VLAN Routing de forma segura (normalmente em um roteador ou um switch layer 3), aplicando ACLs para controlar o tráfego entre VLANs. 

- [ ] Configurou VLAN Trunking Protocol (VTP) em modo transparente, se necessário, para evitar propagação indesejada de VLANs ou desabilitou VTP se não for utilizado.

- [ ] Desabilitou o Trunking Automático (DTP - Dynamic Trunking Protocol) nas portas que não necessitam de trunking, configurando-as explicitamente como access ou trunk.

## 8. Backup e Sincronização

- [ ] Realizou backups regulares das configurações do switch e armazenou-os de forma segura.

- [ ] Configurou NTP para sincronizar com servidores NTP confiáveis e habilitou autenticação NTP.

## 9. Configurações Avançadas e Automação

- [ ] Habilitou Rapid Spanning Tree Protocol (RSTP) ou Multiple Spanning Tree Protocol (MSTP) para convergência mais rápida e gerenciamento de múltiplas instâncias de STP.

- [ ] Habilitou Portas de Backup e Redundância (e.g., HSRP, VRRP em switches L3) quando necessário, para garantir a alta disponibilidade da rede.

- [ ] Configurou playbook no Ansible e adicionou a configuração no Git para controle de versão e automação de implantação das configurações.

- [ ] Utilizou ferramentas como OpenSCAP para avaliação de conformidade e auditoria de segurança automatizada das configurações do switch.

- [ ] Gerenciamento de Acesso Privilegiado (PAM) para controlar e auditar o acesso a contas privilegiadas (e.g., Jumpserver).

- [ ] Documentou a infraestrutura de rede, incluindo o switch, no Netbox para visibilidade total e como "centro da verdade".

## 10. Monitoramento e Resposta a Incidentes

- [ ] Implementou soluções de monitoramento contínuo para detectar e responder a atividades suspeitas em tempo real.
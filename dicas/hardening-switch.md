# Checklist de Hardening para Switch

## **1. Atualizações e Configurações Iniciais**
- [ ] **Atualizou o Firmware** do switch para a versão mais recente.
- [ ] **Configurou Senhas Fortes** para todos os acessos administrativos e de console. Cadastrou as senhas no chaveiro central
- [ ] **Usou Chaveiro (SSH Key)** para autenticação, desabilitando senhas em configurações de SSH.
- [ ] **Habilitou autenticação via TACACS+ ou RADIUS** para gerenciamento centralizado de credenciais.

## **2. Acessos e Protocolos**
- [ ] **Habilitou SSH** para acesso remoto seguro, configurando 30s de **timeout de sessão** para desconectar sessões ociosas após inatividade.
- [ ] **Desabilitou Telnet, HTTP e outros serviços desnecessários**.
- [ ] **Desabilitou CDP e LLDP** caso não seja necessário para sua rede.
- [ ] **Restrigiu o acesso de gerenciamento** apenas a **endereços IP confiáveis**.
- [ ] **Habilitou autenticação 802.1X** (e MAB para dispositivos sem suporte ao 802.1X).
  
## **3. Proteção contra Ataques**
- [ ] **Habilitou Port Security** para limitar em 3 o número de endereços MAC aprendidos por porta.
- [ ] **Habilitou DHCP Snooping** para prevenir ataques de spoofing de DHCP.
- [ ] **Habilitou Dynamic ARP Inspection (DAI)** para prevenir ataques de ARP spoofing.
- [ ] **Habilitou IP Source Guard** para prevenir ataques de IP spoofing.
- [ ] **Habilitou BPDU Guard** nas portas de acesso para proteger contra ataques no protocolo STP.
- [ ] **Habilitou Root Guard** para proteger a raiz da árvore STP.
- [ ] **Configurou o switch Core como o Root** no Spanning Tree Protocol.
- [ ] **Habilitou o BPDU Filter** para evitar que portas de acesso enviem BPDUs.
- [ ] **Habilitou o Storm Control** para limitar tráfego de broadcast, multicast e unicast excessivo.
- [ ] **Habilitou RA Guard e DHCPv6 Snooping** para segurança de IPv6.
  
## **4. Controle e Gerenciamento de Tráfego**
- [ ] **Habilitou IGMP Snooping** para otimizar o tráfego multicast.
- [ ] **Configurou QoS (Quality of Service)** para priorizar o tráfego crítico e prevenir DoS.
- [ ] **Habilitou EtherChannel** com LACP para melhorar a redundância e desempenho de links agregados.

## **5. Segurança de Logs e Monitoramento**
- [ ] **Configuração de Logging** para envio de logs a um servidor centralizado.
- [ ] **Configurou alertas para eventos críticos** e monitoramento contínuo de atividades suspeitas.
- [ ] **Segurança de SNMP**: Configuração de comunidade pública no SNMPv3 com autenticação e criptografia (ou SNMPv2 com segurança limitada, se SNMPv3 não for possível).
- [ ] **Restrigiu o acesso SNMP** apenas a endereços IP confiáveis.

## **6. Proteção Física e Acessos Locais**
- [ ] **Controle de Acesso Físico**: Garante que os switches estão em locais seguros e com acesso restrito a pessoal autorizado.
- [ ] **Segurança de Console**: Configurou senhas seguras e usou chaveiro para acesso ao console, desabilitando o acesso não autorizado.

## **7. Configurações de VLANs e Segmentação de Rede**
- [ ] **Segmentou VLANs** de acordo com a política, limitando a quantidade de dispositivos por VLAN (máximo 256 dispositivos).
- [ ] **Configurou Inter-VLAN Routing** de forma segura.
- [ ] **Configurou VLAN Trunking Protocol (VTP)** em modo transparente, se necessário (apenas switches Cisco).
- [ ] **Desabilitou o Trunking Automático (DTP)** nas portas que não necessitam de trunking.

## **8. Backup e Sincronização**
- [ ] **Realizou backups regulares** das configurações do switch.
- [ ] **Configurou NTP** para sincronizar com servidores NTP confiáveis e usar autenticação NTP.

## **9. Configurações Avançadas**
- [ ] **Habilitou Rapid Spanning Tree Protocol (RSTP)** ou Multiple Spanning Tree Protocol (MSTP).
- [ ] **Habilitou Portas de Backup e Redundância** quando necessário, para garantir a alta disponibilidade da rede.

## **10. Monitoramento e Resposta a Incidentes**
- [ ] **Implementei soluções de monitoramento contínuo** para detectar e responder a atividades suspeitas em tempo real.

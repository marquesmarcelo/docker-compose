# Checklist de Hardening para Firewall (Cisco ASA)

Este checklist visa fornecer um guia abrangente para fortalecer a segurança de firewalls Cisco ASA, cobrindo diversas áreas desde a configuração inicial até a proteção avançada e monitoramento.

## 1. Atualizações e Configurações Iniciais

- [ ] Atualizou o sistema operacional do Cisco ASA (ASA OS) para a versão mais recente e estável, incluindo patches de segurança. 

- [ ] Configurou Senhas Fortes para todos os acessos administrativos (enable, console, ASDM, SSH). Cadastrou as senhas no chaveiro central (ou cofre de senhas). 

- [ ] Usou Chaveiro (SSH Key) para autenticação em acessos SSH, desabilitando a autenticação por senha para SSH quando possível.

- [ ] Habilitou autenticação via TACACS+ ou RADIUS para gerenciamento centralizado de credenciais e auditoria.

- [ ] Configurou o hostname do firewall de forma clara e identificável.

- [ ] Configurou um banner de login (login banner) com avisos legais e de segurança.

## 2. Acessos e Protocolos de Gerenciamento

- [ ] Protegeu a interface de gerenciamento (ASDM, SSH, HTTPS). 

- [ ] Habilitou SSH para acesso remoto seguro, configurando um timeout de sessão (e.g., 30-60 segundos) para desconectar sessões ociosas após inatividade.

- [ ] Desabilitou Telnet, HTTP e outros serviços desnecessários. 

- [ ] Restringiu o acesso de gerenciamento (ASDM, SSH, HTTPS, SNMP) apenas a endereços IP confiáveis e redes de gerenciamento dedicadas. 

- [ ] Utilizou autenticação multifator (MFA) para acesso administrativo. 

- [ ] Desabilitou o acesso remoto não essencial. 

## 3. Regras de Firewall e Proteção contra Ataques

- [ ] Revisou e otimizou as regras de firewall. 

- [ ] Aplicou o Princípio do Menor Privilégio (Default Deny) nas regras de firewall, ou seja, negue todo o tráfego que não é explicitamente permitido. 

- [ ] Adicionou as regras mais comuns/frequentemente usadas no início da lista de acesso para otimização de desempenho. 

- [ ] Implementou inspeção profunda de pacotes (DPI) e prevenção de intrusão (IPS) se o ASA for um Next-Generation Firewall (NGFW). 

- [ ] Configurou regras claras e objetivas. 

- [ ] Documentou detalhadamente todas as regras de firewall. 

- [ ] Implementou um processo de revisão e auditoria periódica das regras de firewall. 

- [ ] Realizou testes das regras para garantir que funcionam como esperado. 

- [ ] Utilizou grupos e objetos para organizar as regras e facilitar o gerenciamento. 

- [ ] Habilitou recursos de proteção contra ataques de negação de serviço (DoS/DDoS), como controle de conexão (rate-limiting) e proteção contra SYN floods.

- [ ] Configurou filtros para bloquear tráfego inválido ou malicioso (e.g., Bogons, Martian Addresses).

- [ ] Desabilitou a passagem de tráfego de broadcast/multicast desnecessário entre interfaces.

- [ ] Configurou VPNs (IPsec, SSL VPN) com criptografia forte e métodos de autenticação robustos (e.g., certificados, MFA).

## 4. Segmentação de Rede

- [ ] Definiu e implementou zonas de segurança (e.g., Inside, Outside, DMZ) e configurou as políticas de tráfego entre elas. 

- [ ] Utilizou firewalls perimetrais para proteger o limite da rede (conexão com a Internet). 

- [ ] Implementou firewalls internos para segmentar a rede interna, controlando o tráfego entre diferentes segmentos/VLANs. 

- [ ] Aplicou políticas de segurança específicas a diferentes segmentos da rede, conforme a necessidade de isolamento e controle de acesso granular. 

## 5. Segurança de Logs e Monitoramento

- [ ] Implementou logging e monitoramento detalhados de eventos de segurança. 

- [ ] Configurou o envio de logs para um servidor Syslog centralizado e seguro, incluindo eventos de firewall, tentativas de login, alterações de configuração e detecção de intrusão. 

- [ ] Configurou alertas para eventos críticos que indicam possíveis ameaças ou violações de política. 

- [ ] Monitorou continuamente o tráfego de rede (volume, padrões, protocolos, portas) e a utilização de recursos (CPU, memória) do firewall. 

- [ ] Utilizou ferramentas de SIEM/XDR (como Wazuh) para correlação e análise de logs e eventos de segurança, identificando ameaças e anomalias. 

- [ ] Configurou SNMPv3 com autenticação e criptografia para monitoramento seguro (se SNMP for utilizado).

- [ ] Restringiu o acesso SNMP apenas a endereços IP confiáveis.

## 6. Backup e Sincronização

- [ ] Realizou backups regulares das configurações do firewall e do IOS e armazenou-os de forma segura e offline.

- [ ] Configurou NTP para sincronizar com servidores NTP confiáveis e habilitou autenticação NTP.

## 7. Configurações Avançadas e Automação

- [ ] Manteve o sistema operacional e as regras de firewall atualizadas. 

- [ ] Implementou um processo de revisão periódica das regras de firewall. 

- [ ] Configurou playbook no Ansible e adicionou a configuração no Git para controle de versão e automação de implantação das configurações.

- [ ] Utilizou ferramentas como OpenSCAP para avaliação de conformidade e auditoria de segurança automatizada das configurações do firewall.

- [ ] Gerenciamento de Acesso Privilegiado (PAM) para controlar e auditar o acesso a contas privilegiadas (e.g., Jumpserver). 

- [ ] Documentou a infraestrutura de rede, incluindo o firewall, no Netbox para visibilidade total e como "centro da verdade". 

## 8. Resposta a Incidentes

- [ ] Desenvolveu e testou um plano de resposta a incidentes de segurança específico para o firewall.

- [ ] Implementou soluções de monitoramento contínuo para detectar e responder a atividades suspeitas em tempo real.
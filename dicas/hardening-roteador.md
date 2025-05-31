# Checklist de Hardening para Roteador (Cisco)

Este checklist visa fornecer um guia abrangente para fortalecer a segurança de roteadores Cisco, cobrindo diversas áreas desde a configuração inicial até a proteção avançada e monitoramento.

## 1. Atualizações e Configurações Iniciais

- [ ] Atualizou o IOS (Internetwork Operating System) do roteador para a versão mais recente e estável.

- [ ] Configurou Senhas Fortes para todos os acessos administrativos (enable, console, VTY). Cadastrou as senhas no chaveiro central (ou cofre de senhas).

- [ ] Usou Chaveiro (SSH Key) para autenticação em acessos SSH, desabilitando a autenticação por senha para SSH quando possível.

- [ ] Habilitou autenticação via TACACS+ ou RADIUS para gerenciamento centralizado de credenciais e auditoria.

- [ ] Configurou o hostname do roteador de forma clara e identificável.

- [ ] Configurou um banner de login (login banner) com avisos legais e de segurança.

## 2. Acessos e Protocolos de Gerenciamento

- [ ] Habilitou SSH para acesso remoto seguro, configurando um timeout de sessão (e.g., 30-60 segundos) para desconectar sessões ociosas após inatividade.

- [ ] Desabilitou Telnet, HTTP e outros serviços desnecessários (e.g., finger, identd, NTP no modo broadcast).

- [ ] Restringiu o acesso de gerenciamento (SSH, HTTPS, SNMP) apenas a endereços IP confiáveis e redes de gerenciamento dedicadas.

- [ ] Implementou controle de acesso baseado em função (RBAC) para administração, atribuindo diferentes níveis de privilégio a usuários e grupos.

- [ ] Habilitou autenticação multifator (MFA) para acesso administrativo, se suportado e aplicável.

- [ ] Desabilitou o acesso remoto não essencial.

## 3. Proteção contra Ataques e Filtragem de Tráfego

- [ ] Implementou Listas de Controle de Acesso (ACLs) nas interfaces apropriadas para controlar o tráfego de entrada e saída. 

- [ ] Aplicou o princípio do menor privilégio (default deny) nas ACLs.

- [ ] Criou regras claras e objetivas, com documentação detalhada.

- [ ] Adicionou as regras mais comuns no início do processo de roteamento para otimização.

- [ ] Implementou filtros para bloquear tráfego em roteadores de borda (interface com a Internet):

- [ ] Filtragem de "Bogons" ou "Martian Addresses" (endereços IP inválidos ou não roteáveis na internet pública).

- [ ] Bloqueio de serviços desnecessários (e.g., portas bem conhecidas de serviços não utilizados).

- [ ] Prevenção de ataques comuns (e.g., SYN flood, varreduras de porta).
Desabilitou o encaminhamento de pacotes direcionados (directed broadcast) para prevenir ataques de negação de serviço (DoS).

- [ ] Configurou protocolos de roteamento seguros, incluindo autenticação (e.g., OSPFv3 authentication, EIGRP authentication).

- [ ] Implementou filtros de roteamento para controlar a propagação de rotas e prevenir injeção de rotas maliciosas.

- [ ] Habilitou o uRPF (Unicast Reverse Path Forwarding) para prevenir spoofing de endereço de origem.

- [ ] Configurou proteção contra fragmentação excessiva de IP.

- [ ] Bloqueou opções IP maliciosas.

## 4. Controle e Gerenciamento de Tráfego

- [ ] Configurou QoS (Quality of Service) para priorizar o tráfego crítico (voz, vídeo) e prevenir DoS em links congestionados.

- [ ] Implementou Network Address Translation (NAT) de forma segura, se necessário.

- [ ] Configurou NetFlow/IPFIX para coleta detalhada de informações de tráfego.

## 5. Segurança de Logs e Monitoramento

- [ ] Configurou Logging para envio de logs de segurança a um servidor Syslog centralizado e seguro.

- [ ] Configurou alertas para eventos críticos (tentativas de login falhas, alterações de configuração, detecção de intrusão).

- [ ] Implementou monitoramento contínuo da utilização de recursos (CPU, memória, interfaces) e disponibilidade do roteador.

- [ ] Configurou SNMPv3 com autenticação e criptografia para monitoramento seguro (se SNMP for utilizado).

- [ ] Restringiu o acesso SNMP apenas a endereços IP confiáveis.

- [ ] Utilizou ferramentas de SIEM/XDR (como Wazuh) para correlação e análise de logs e eventos de segurança.

## 6. Backup e Sincronização

- [ ] Realizou backups regulares das configurações do roteador e armazenou-os de forma segura.

- [ ] Configurou NTP para sincronizar com servidores NTP confiáveis e habilitou autenticação NTP.

## 7. Configurações Avançadas e Automação

- [ ] Configurou um playbook no Ansible e adicionou a configuração no Git para controle de versão e automação de implantação de configurações.

- [ ] Utilizou ferramentas como OpenSCAP para avaliação de conformidade e auditoria de segurança automatizada das configurações do roteador.

- [ ] Gerenciamento de Acesso Privilegiado (PAM) para controlar e auditar o acesso a contas privilegiadas (e.g., Jumpserver).

- [ ] Documentou a infraestrutura de rede, incluindo o roteador, no Netbox para visibilidade total e como "centro da verdade".

## 8. Resposta a Incidentes

- [ ] Desenvolveu e testou um plano de resposta a incidentes de segurança para roteadores.

- [ ] Implementou soluções de monitoramento contínuo para detectar e responder a atividades suspeitas em tempo real.
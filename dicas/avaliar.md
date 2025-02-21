# Avaliar

| Grupo | Link | Informação Adicional |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| | [https://checkusernames.com/](https://checkusernames.com/) | |
| | [https://haveibeenpwned.com/](https://haveibeenpwned.com/) | |
| | [https://www.beenverified.com/](https://www.beenverified.com/) | |
| | [https://censys.io/](https://censys.io/) | |
| | [https://builtwith.com/](https://builtwith.com/) | |
| | Google Dorks | |
| | Maltego | |
| | Recon-Ng | |
| | theHaverster | |
| | Shodan | |
| | Jigsaw | |
| | SpiderFoot | |
| | Creepy | |
| | Nmap | |
| | Webshag | |
| | OpenVas | |
| | UnicornScan | |
| | Foca | |
| | ZoomEye | |
| | Spyse | |
| | IVRE | |
| | Metagoogil | |
| | exittool | |
| | [https://defaultpassword.us/](https://defaultpassword.us/) | |
| | [https://www.netresec.com/?page=NetworkMiner](https://www.netresec.com/?page=NetworkMiner) |
| IDS | [https://suricata.io/](https://suricata.io/) | |
| | [https://zeek.org/](https://zeek.org/) | |
| | [https://openargus.org/](https://openargus.org/) | |
| | [https://oval.mitre.org/](https://oval.mitre.org/) | |
| | [https://oss.oetiker.ch/mrtg/](https://oss.oetiker.ch/mrtg/) | |
| Honeypot | [https://github.com/thinkst/opencanary](https://github.com/thinkst/opencanary) | Honeypot |
| | [https://umbrella.cisco.com/blog/cisco-umbrella-1-million](https://umbrella.cisco.com/blog/cisco-umbrella-1-million) | Lista com 1 milhão de domínios confiáveis |
| | [https://talosintelligence.com/reputation_center/](https://talosintelligence.com/reputation_center/) | Consultar a reputação de um domínio |
| | [https://testconnectivity.microsoft.com/tests/o365](https://testconnectivity.microsoft.com/tests/o365) | Testar sistema de email |
| | [https://cuckoosandbox.org/](https://cuckoosandbox.org/) | Sandbox |
| | [https://digital.ai/devops-tools-periodic-table](https://digital.ai/devops-tools-periodic-table) | DevOps Tools Periodic table |
| | | |
| | | |
| | [https://github.com/technicaldada/pentbox](https://github.com/technicaldada/pentbox) | |
| | [https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview) |
| | [https://www.slavasoft.com/hashcalc/](https://www.slavasoft.com/hashcalc/) | |

	
Ferramentas e coleções:

#OSINT COLLETION

https://caipora.pro

https://start.me/p/DPYPMz/the-ultimate-osint-collection

https://start.me/p/L1rEYQ/osint4all

https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ/edit?gid=930747607#gid=930747607


# Banco de dados públicos

shodan.io

https://hunter.how

https://fofa.info

https://pulsedive.com/

#Extensão


#Email
https://chromewebstore.google.com/detail/email-extractor/jdianbbpnakhcmfkcckaboohfgnngfcc?pli=1

hunter.io

Mostrar principal | Responder

Veja esta mensagem em seu contexto


# OSINT Links

https://start.me/p/BPN26q/osint-napratica​


# Dorks

🔎 Básico - Pesquisa Específica
1️⃣ site:gov.br "documento confidencial" → Pesquisa documentos confidenciais em sites do governo brasileiro.
2️⃣ site:*.mil "restricted" OR "classified" → Pesquisa termos restritos em sites militares.
3️⃣ intitle:"index of" "backup" → Busca diretórios expostos contendo backups.
4️⃣ filetype:pdf site:universidade.br "prova" → Encontra provas vazadas de universidades.
5️⃣ inurl:admin login → Páginas de login administrativas expostas.
6️⃣ intitle:"index of" passwords → Pastas públicas contendo arquivos de senhas.
🔥 Intermediário - Arquivos Sensíveis
7️⃣ ext:sql | ext:txt | ext:xml "password" -github → Pesquisa arquivos contendo senhas.
8️⃣ filetype:xls OR filetype:csv "email" "password" → Planilhas públicas com credenciais.
9️⃣ site:pastebin.com "senha" OR "password" → Busca vazamentos no Pastebin.
🔟 site:drive.google.com OR site:dropbox.com "confidential" → Links públicos para arquivos privados.
1️⃣1️⃣ site:trello.com "password" OR "login" → Busca credenciais expostas no Trello.
🚀 Avançado - Cibersegurança & Exploração
1️⃣2️⃣ inurl:/phpinfo.php → Páginas que exibem configurações sensíveis do PHP.
1️⃣3️⃣ inurl:wp-config.php → Arquivos de configuração vazados do WordPress.
1️⃣4️⃣ intitle:"phpMyAdmin" "Welcome to phpMyAdmin" → Instâncias abertas de phpMyAdmin.
1️⃣5️⃣ ext:log intext:"error.log" OR intext:"php_error" → Logs de erro expostos na web.
1️⃣6️⃣ inurl:weblogic/console → Consoles WebLogic expostos.
1️⃣7️⃣ site:pastebin.com OR site:ghostbin.com "ssh private key" → Chaves SSH expostas.
🎭 Bônus - Dados Pessoais e Segurança
1️⃣8️⃣ "@gmail.com" filetype:xls OR filetype:csv OR filetype:txt → Vazamentos de emails.
1️⃣9️⃣ site:linkedin.com/in "CEO" "cybersecurity" → Pesquisa CEOs de empresas de segurança.
2️⃣0️⃣ site:github.com "DB_PASSWORD" → Busca senhas de bancos de dados expostas no GitHub.
2️⃣1️⃣ site:shodan.io "default password" → Busca senhas padrão de dispositivos IoT.
2️⃣2️⃣ inurl:"/webmail" OR inurl:"/roundcube" → Serviços de webmail expostos.

#Bug Bounty

https://chaos.projectdiscovery.io

# Onsint
https://www.osintdojo.com

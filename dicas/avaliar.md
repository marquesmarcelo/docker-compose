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

 Aula 03

##Recon Wifi
wigle.net
geowifi

# Extesão Recon
https://chromewebstore.google.com/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd?hl=pt

# RDAP

https://client.rdap.org

curl https://rdap.registro.br/domain/rnp.br
https://registro.br/rdap/


# Wordlist
https://github.com/danielmiessler/SecLists

# Enumeração de subdominios

ffuf
gobuster
sudfinder, assetfinder,
sublist3r

https://github.com/nmmorette/ScanMaster

#DNS transfer
https://github.com/nmmorette/bash-scripts/blob/main/dnstransfer.sh


#Hack Tricks

https://book.hacktricks.wiki/en/index.html

## Subdomain Takeover
https://book.hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html?highlight=subdomain%20take#subdomain-takeover

https://www.google.com/search?client=opera-gx&q=subdomain+takeover+bug+bounty&sourceid=opera&ie=UTF-8&oe=UTF-8



## Ferramentas completas

Online

#crt

crt.sh

https://crt.sh/

OSINT

The fastest way to obtain a lot of subdomains is search in external sources. The most used tools are the following ones (for better results configure the API keys):

BBOT

#bbot

# subdomains

```bash
bbot -t tesla.com -f subdomain-enum
```

# subdomains (passive only)

```bash
bbot -t tesla.com -f subdomain-enum -rf passive
```

# subdomains + port scan + web screenshots

```bash
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

Amass

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

subfinder

# Subfinder, use -silent to only have subdomains in the output

```bash
./subfinder-linux-amd64 -d tesla.com [-silent]
```
findomain

```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```

OneForAll

```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```

assetfinder

```bash
assetfinder --subs-only Sudomy
```

# It requires that you create a sudomy.api file with API keys

```bash
sudomy -d tesla.com
```

vita
```
vita -d tesla.com
```

theHarvester

```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
There are other interesting tools/APIs that even if not directly specialised in finding subdomains could be useful to find subdomains, like:

Crobat: Uses the API https://sonar.omnisint.io to obtain subdomains

# Get list of subdomains in output from the API

## This is the API the crobat tool will use

```bash
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
JLDC free API
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
RapidDNS free API
```

# Get Domains from rapiddns free API

```bash
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
https://crt.sh/
```

# Get Domains from crt free API

```bash
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
gau: fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl for any given domain.
```

# Get subdomains from GAUs found URLs

```bash
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
SubDomainizer & subscraper: They scrap the web looking for JS files and extract subdomains from there.
```

# Get only subdomains from SubDomainizer

```bash
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com
```

# Get only subdomains from subscraper, this already perform recursion over the found results

```bash
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

Shodan

# Get info about the domain

```bash
shodan domain # Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

Censys subdomain finder

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

DomainTrail.py

```bash
python3 DomainTrail.py -d example.com
```

securitytrails.com has a free API to search for subdomains and IP history

chaos.projectdiscovery.io

This project offers for free all the subdomains related to bug-bounty programs. You can access this data also using chaospy or even access the scope used by this project https://github.com/projectdiscovery/chaos-public-program-list

You can find a comparison of many of these tools here: https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off

# Enumeração automatizada

amass

theharvester

# 403 e 401 Bypass

https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/403-and-401-bypasses.html

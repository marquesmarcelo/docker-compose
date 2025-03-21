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


Para uso em pentests com Kali Linux, o chipset da placa Wi-Fi precisa suportar modo monitor e injeção de pacotes. Os chipsets mais recomendados e amplamente suportados pelo Kali Linux incluem:

Chipsets Recomendados

Chipset Suporte ao Modo Monitor Injeção de Pacotes Observações

Atheros AR9271 Sim Sim Muito compatível, usado em Alfa AWUS036NHA

Ralink RT3572 Sim Sim Suporte confiável, menos comum

Ralink RT3070 Sim Sim Popular em adaptadores antigos

Realtek RTL8812AU Sim (com driver) Sim Precisa instalar driver extra no Kali

Realtek RTL8814AU Sim (com driver) Sim Requer driver específico, usado em Alfa AWUS1900

Placas Wi-Fi Populares para Pentest

Alfa AWUS036NHA (Atheros AR9271) → Melhor estabilidade e compatibilidade nativa

Alfa AWUS036ACH (Realtek RTL8812AU) → Boa opção para dual-band (2.4GHz e 5GHz)

Panda PAU09 (Ralink RT3572) → Alternativa confiável para Kali

TP-Link TL-WN722N v1 (Atheros AR9271) → Somente a versão v1 funciona (v2 e v3 não suportam modo monitor)

A minha versão é a TP-Link TL-WN722N é barata e acessivel

Podem utilizar estes dois links como referência:

https://www.enisa.europa.eu/sites/default/files/publications/Update%20of%20CERT%20Baseline%20Capabilities.pdf

https://www.enisa.europa.eu/sites/default/files/publications/ENISA%20Report%20-%20How%20to%20setup%20CSIRT%20and%20SOC.pdf

Logo de início falei de alguns materiais massa sobre o Nmap:

- https://nmap.org/book/

- https://phrack.org/issues/51/11#article

- https://phrack.org/issues/54/9#article

Aproveitando a deixa sobre a e-zine Phrack, comentei de outras e-zines legais para darem uma lida e ficarem antenados no que há de novo no mundo de segurança/hacking:

- https://phrack.org/

- https://tramoia.sh/

- https://pagedout.institute/

- https://tmpout.sh/

Depois chegamos num ponto de falar sobre alguns materiais de estudos, principalmente voltados para redes e Linux:

- https://novatec.com.br/livros/analise-trafego-tcp-ip/
-
- https://www.amazon.com/TCP-Illustrated-Protocols-Addison-Wesley-Professional/dp/0321336313

- https://www.guiafoca.org/

- https://novatec.com.br/livros/programacao-shell-linux-13ed/

- https://overthewire.org/wargames/bandit/

Também comentei uma alternativa ao Nmap, o Rustscan:

- https://github.com/RustScan/RustScan

E falei o quanto interessante é pegar o código das coisas pra ler, por exemplo o plugin de banner grab do Nmap:

- https://github.com/nmap/nmap/blob/master/scripts/banner.nse

Depois disso chegamos na parte de algumas ferramentas para enumeração web e deixei algumas além das que tem no material para vocês testarem:

- https://github.com/ffuf/ffuf

- https://github.com/xmendez/wfuzz

- https://github.com/lanjelot/patator (Minha favorita <3)



Ao falar de curso do Metasploit comentei desse aqui:

- https://www.offsec.com/metasploit-unleashed/

Já sobre livro de pentest desses dois:

- https://novatec.com.br/livros/black-hat-python/

- https://novatec.com.br/livros/testes-invasao-pentest/

Quando falamos sobre exploits públicos comentei do searchsploit, ferramenta para buscar no terminal exploits do exploit-db:

- https://www.exploit-db.com/searchsploit

E para finalizar deixei um post no meu blog que mostra as etapas (boa parte delas já vimos) para invasão de alguma coisa. Nesse caso, utilizei como alvo um desafio mesmo:

- https://gildasio.gitlab.io/posts/mr-robot/

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

Malware Analysis - Sandboxing (https://github.com/0xc1r3ng/Malware-Sandboxes-Malware-Source)

URL	INFO

Cuckoo Sandbox	Open source, self hosted sandbox and automated analysis system.

Mastiff	Static analysis of malware.

Fastir	This tool collects different artefacts on live Windows and records the results in csv files.

SysAnalyser	Application that was designed to give malcode analysts an automated tool

Viper	Binary analysis and management framework

Zeltser analysis	Automated Malware Analysis

Manalyze	Manalyze started when antivirus tried to quarantine malware sample collection for the thirtieth time

Quarkslab IRMA	Asynchronous and customizable analysis platform for suspicious files!

Dorothy2	A malware/botnet analysis framework written in Ruby.

F-Secure see	Sandboxed Execution Environment

Noriben	hPython-based script that works in conjunction with Sysinternals Procmon

Malheur	Automatic Analysis of Malware Behavior

Drakvuf	Virtualization based agentless black-box binary analysis system.

Zero Wine Tryouts	Zero Wine Tryouts is an open source malware analysis tool.

CWSandbox	A “sandbox”, as it relates to computer security, is a designated, separate and restricted environment

Malwasm	Offline debugger for malware's reverse engineering

( Online ) Malware Analysis - Sandbox

URL	INFO

Malwr	Free analysis with an online Cuckoo Sandbox instance.

Hybrid analysis	Online malware analysis tool, powered by VxSandbox.

Virscan	FREE on-line scan service, which checks uploaded files for malware, using antivirus engines, indicated in the VirSCAN list.

Virusade	Hosted virus scanning for developers

VirusTotal	Free online analysis of malware samples and URLs

Malwareconfig	Online malware analysis samples

Detux GNU/Linux sandbox	sandbox developed to do traffic analysis of the Linux malwares and capture the IOCs by doing so. QEMU hypervisor is used to emulate Linux (Debian) for various CPU architectures.

AndroTotal	Free online analysis of APKs against multiple mobile antivirus apps.

Comodo	malware detection techniques Valkyrie conducts several analysis using run-time behavior and hundreds

Manalyzer	Free service which performs static analysis on PE executables to detect undesirable behavior.

ID Ransomware	Upload a ransom note and/or sample encrypted file to identify the ransomware that has encrypted your data.

Document Analyzer	Free dynamic analysis of DOC and PDF files.

Cryptam	Analyze suspicious office documents.

Metascan	Scan a file, hash or IP address for malware (free)

Jotti	Free online multi-AV scanner.

PDF Examiner	Suspected malware to be fed into our analysis network.

PDF examiner	Analyse suspicious PDF files.

Malware tracker	Provides malware analysis, forensics, and security solutions for enterprise.

Malware Sources

URL	INFO

http://cybercrime-tracker.net/	Cybercrime tracker

http://malc0de.com/database/	Malc0de

http://malwaredb.malekal.com/	Malekal

http://malshare.com	Malshare

http://tracker.h3x.eu/	Tracker

http://www.kernelmode.info	Kernel mode

https://www.botnets.fr/wiki/Main_Page	Botnet.fr

http://www.exposedbotnets.com/	Exposed Botnets

http://malware.dontneedcoffee.com/	Dont need coffee

http://vxvault.net/	VX Vault

https://github.com/ytisf/theZoo/tree/master/malwares/Binaries	Malware binaries

https://totalhash.cymru.com/	Total hash

https://zeustracker.abuse.ch	ZeuS Tracker

https://cse.google.com/cse/home?cx=011750002002865445766%3Apc60zx1rliu (from Corey Harrell)	Custom Google search engine

https://archive.org/details/malwaremuseum	Malware museum

https://ransomwaretracker.abuse.ch/tracker/	Ransomware tracker

https://docs.google.com/spreadsheets/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml#	Ransomware overview

https://shinolocker.com/	Ransomware simulator

http://contagiodump.blogspot.se/	Contagio

http://virusshare.com/	VirusShare

http://www.virusign.com/	Virusign

http://www.malwaredomainlist.com	Malware domain list

https://malware.lu/	Malware.lu

https://github.com/MISP/MISP	MISP

http://www.malware.pl/ - https://www.scumware.org/	SafeGroup

http://minotauranalysis.com	NovCon Minotaur

http://support.clean-mx.de/clean-mx/viruses.php	Clean MX

http://panda.gtisc.gatech.edu/malrec/	Edu malrec

https://www.abuse.ch/	Abuse CH

http://www.offensivecomputing.net/	Offensive computing

http://www.malwaredomains.com	Malware domain blocklist

https://github.com/technoskald/maltrieve	Maltrieve

https://stixproject.github.io/	Structured Threat Information eXpression

https://ytisf.github.io/theZoo/	The Zoo aka Malware DB

https://github.com/0day1day/mwcrawler	Tool Mwcrawler

Domain Analysis

Inspect domains and IP addresses.

AbuseIPDB - AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet.

badips.com - Community based IP blacklist service.

boomerang - A tool designed for consistent and safe capture of off network web resources.

Cymon - Threat intelligence tracker, with IP/domain/hash search.

Desenmascara.me - One click tool to retrieve as much metadata as possible for a website and to assess its good standing.

Dig - Free online dig and other network tools.

dnstwist - Domain name permutation engine for detecting typo squatting, phishing and corporate espionage.

IPinfo - Gather information about an IP or domain by searching online resources.

Machinae - OSINT tool for gathering information about URLs, IPs, or hashes. Similar to Automator.

mailchecker - Cross-language temporary email detection library.

MaltegoVT - Maltego transform for the VirusTotal API. Allows domain/IP research, and searching for file hashes and scan reports.

Multi rbl - Multiple DNS blacklist and forward confirmed reverse DNS lookup over more than 300 RBLs.

NormShield Services - Free API Services for detecting possible phishing domains, blacklisted ip addresses and breached accounts.


PhishStats - Phishing Statistics with search for IP, domain and website title
Spyse - subdomains, whois, realted domains, DNS, hosts AS, SSL/TLS info,

SecurityTrails - Historical and current WHOIS, historical and current DNS records, similar domains, certificate information and other domain and IP related API and tools.

SpamCop - IP based spam block list.

SpamHaus - Block list based on domains and IPs.

Sucuri SiteCheck - Free Website Malware and Security Scanner.

Talos Intelligence - Search for IP, domain or network owner. (Previously SenderBase.)

TekDefense Automater - OSINT tool for gathering information about URLs, IPs, or hashes.

URLhaus - A project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.

URLQuery - Free URL Scanner.

urlscan.io - Free URL Scanner & domain information.

Whois - DomainTools free online whois search.

Zeltser's List - Free online tools for researching malicious websites, compiled by Lenny Zeltser.

ZScalar Zulu - Zulu URL Risk Analyzer.

Documents and Shellcode

Analyze malicious JS and shellcode from PDFs and Office documents. See also the browser malware section.

AnalyzePDF - A tool for analyzing PDFs and attempting to determine whether they are malicious.

box-js - A tool for studying JavaScript malware, featuring JScript/WScript support and ActiveX emulation.

diStorm - Disassembler for analyzing malicious shellcode.

InQuest Deep File Inspection - Upload common malware lures for Deep File Inspection and heuristical analysis.

JS Beautifier - JavaScript unpacking and deobfuscation.

libemu - Library and tools for x86 shellcode emulation.

malpdfobj - Deconstruct malicious PDFs into a JSON representation.

OfficeMalScanner - Scan for malicious traces in MS Office documents.

olevba - A script for parsing OLE and OpenXML documents and extracting useful information.

Origami PDF - A tool for analyzing malicious PDFs, and more.

PDF Tools - pdfid, pdf-parser, and more from Didier Stevens.

PDF X-Ray Lite - A PDF analysis tool, the backend-free version of PDF X-RAY.

peepdf - Python tool for exploring possibly malicious PDFs.

QuickSand - QuickSand is a compact C framework to analyze suspected malware documents to identify exploits in streams of different encodings and to locate and extract embedded 
executables.

Spidermonkey - Mozilla's JavaScript engine, for debugging malicious JS.

Malware Corpora

Malware samples collected for analysis.

Clean MX - Realtime database of malware and malicious domains.

Contagio - A collection of recent malware samples and analyses.

Exploit Database - Exploit and shellcode samples.

Infosec - CERT-PA - Malware samples collection and analysis.

InQuest Labs - Evergrowing searchable corpus of malicious Microsoft documents.

Javascript Mallware Collection - Collection of almost 40.000 javascript malware samples

Malpedia - A resource providing rapid identification and actionable context for malware investigations.

Malshare - Large repository of malware actively scrapped from malicious sites.

Ragpicker - Plugin based malware crawler with pre-analysis and reporting functionalities

theZoo - Live malware samples for analysts.

Tracker h3x - Agregator for malware corpus tracker and malicious download sites.

vduddu malware repo - Collection of various malware files and source code.

VirusBay - Community-Based malware repository and social network.

ViruSign - Malware database that detected by many anti malware programs except ClamAV.

VirusShare - Malware repository, registration required.

VX Vault - Active collection of malware samples.

Zeltser's Sources - A list of malware sample sources put together by Lenny Zeltser.

Zeus Source Code - Source for the Zeus trojan leaked in 2011.

VX Underground - Massive and growing collection of free malware samples.

Honeypots

Trap and collect your own samples.

Conpot - ICS/SCADA honeypot.

Cowrie - SSH honeypot, based on Kippo.

DemoHunter - Low interaction Distributed Honeypots.

Dionaea - Honeypot designed to trap malware.

Glastopf - Web application honeypot.

Honeyd - Create a virtual honeynet.

HoneyDrive - Honeypot bundle Linux distro.

Honeytrap - Opensource system for running, monitoring and managing honeypots.

MHN - MHN is a centralized server for management and data collection of honeypots. MHN allows you to deploy sensors quickly and to collect data immediately, viewable from a neat web interface.

Mnemosyne - A normalizer for honeypot data; supports Dionaea.

Thug - Low interaction honeyclient, for investigating malicious websites.

Pra quem ainda está levando surra do git, segue uma sugestão de joguinho para reforçar o aprendizado: https://learngitbranching.js.org/

Desafio legal pra praticar sobre XSS:

- https://xss-game.appspot.com/

E para responder a dúvida de um colega recorri a uma imagem que montei numa apresentação:

- https://gildasio.gitlab.io/talk/h2t-semcomp/#8

Essa apresentação está disponível em meu site... Como é de conteúdo pertinente para o curso, acho legal assistirem. O título é "Web App Hardening: HTTP Headers":

- https://gildasio.gitlab.io/teaching/

Noutro momento falamos ainda sobre WAF e algumas possibilidades de bypass:

- https://websitesecuritystore.com/wp-content/uploads/2021/10/what-is-web-application-firewall.svg

- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#generic-waf-bypass

- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/3%20-%20XSS%20Common%20WAF%20Bypass.md

Sobre materiais de estudo a respeito de SQL injection comentei desses livros:

- https://www.amazon.com/Injection-Attacks-Defense-Justin-Clarke/dp/1597499633

- https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470

Depois fiz um jabázin sobre uma ferramenta que montei para auxiliar na exploração de falhas de injeção de comandos:

- https://github.com/gildasio/wshlient

- https://asciinema.org/a/q1eUYpO1GNYbEV2wta9CiIjGh

Nela, inclusive, tem uns exemplos de payloads de códigos disfarçados em imagens... fica aí a recomendação:

- https://github.com/gildasio/wshlient/blob/main/auxiliary_files/webshells/simple_jpg.php

- https://github.com/gildasio/wshlient/blob/main/auxiliary_files/webshells/image.php

Aqui tomem os links q comentei na aula de hoje sobre XSS e mais sobre segurança web client side sorriso

Livro sobre XSS: https://www.amazon.com/XSS-Attacks-Scripting-Exploits-Defense/dp/1597491543

Um cara muito bom sobre XSS que posta costumeiramente no Twitter e Youtube:

- https://x.com/brutelogic

- https://x.com/RodoAssis

- https://www.youtube.com/user/brutelogic

Palestra "Muito além do alert() em ataques web client side":

- https://www.slideshare.net/slideshow/muito-alm-do-alert-em-ataques-web-client-side/69599104

Ferramenta h2t para recomendações de melhorias de segurança web somente baseada em configurações de cabeçalhos HTTP:

- https://github.com/gildasio/h2t

# Treinamento Privesc

https://tryhackme.com/room/linuxprivesc

https://tryhackme.com/room/linuxprivescarena

https://tryhackme.com/room/sudovulnsbypass

https://tryhackme.com/room/sudovulnsbof

https://tryhackme.com/room/sudovulnssamedit

https://tryhackme.com/room/dirtypipe

https://tryhackme.com/room/pwnkit


# Fundamentos linux

https://tryhackme.com/module/linux-fundamentals


# Comandos básicos de enumeração:


#Máquina: hostname uname -r uname -a #Usuário: whoami id cat /etc/passwd #Rede: ip a ip r arp -v cat /etc/resolv.conf #Kernel Information uname -a #Operating System cat /etc/issue cat /etc/*-release #User info whoami w id grep $USER /etc/passwd - Lastlog lastlog | grep -v '**Never logged in**' -list all root cat /etc/passwd |cut -f1,3,4 -d":" | grep "0:0" |cut -f1 -d":" |awk '{print $1}' #Processes ps auxwww ps -u root ps -u $USER #File and folder cat /etc/shadow - sticky bit find / -perm -1000 -type d 2>/dev/null find / -perm -4000 2> /dev/null - SUID find / -perm -u=s -type f 2>/dev/null - SSGID find / -perm -g=s -type f 2>/dev/null #grep for keywords grep 'pass*' /etc/*.conf 2> /dev/null grep 'key' /etc/*.conf 2> /dev/null grep 'secret' /etc/*.conf 2> /dev/null #permission on root ls -als root/ #other users history find /* -name *.*history* -print 2> /dev/null #Capabilities getcap -r / 2>/dev/null #Metasploit modules post/linux/gather/enum_configs post/linux/gather/enum_system post/linux/gather/enum_network post/linux/gather/enum_psk post/linux/gather/hashdump post/linux/gather/openvpn_credentials post/linux/gather/phpmyadmin_credsteal #Automatic tools https://github.com/reider-roque/linpostexp/blob/master/linprivchecker.py http://pentestmonkey.net/tools/audit/unix-privesc-check


History search

*cat ~/.history | less

find /* -name *.history -print 2> /dev/null


# Find

https://nmmorette.notion.site/Find-4e6c1ec752b94b8ebe8a0ab00e0046f2

find


Seguem alguns links com materiais para treino na área de forense.

https://www.ashemery.com/dfir.html

https://cfreds-archive.nist.gov/

https://www.dfir.training/downloads/test-images?limit=20&limitstart=20

Bom, aqui uns links que comentamos na aula de hoje hehe

Primeiro, uns programas que podem ser utilizados para mexer com API:

- https://www.usebruno.com/

- https://www.postman.com/

- https://insomnia.rest/

- https://gildasio.gitlab.io/talk/kernel-skills-userspace-debugging/#/1/1

E por fim, falamos de alguns materiais pra ficar fera em Linux:

- https://novatec.com.br/livros/programacao-shell-linux-13ed/

- https://www.guiafoca.org/

- https://www.amazon.com/Linux-Bible-Christopher-Negus/dp/1119578884

- https://www.linuxfromscratch.org/

Dei um breve resumo lá na aula do que se trata, e aqui o link:

- https://gildasio.gitlab.io/posts/hacking-myself-again/

Quando falei sobre núvem disse dos benefícios para pentests e comentei daquele projeto Segfault que o pessoal do THC mantém e disponibiliza pra gente uma máquina para podermos fazer diversos testes. Aqui o link do projeto:

- https://www.thc.org/segfault/

Daí fomos falar de IoT e pra levantar a onda dos perigos dessas tecnologias falei sobre o caso da Botnet Mirai:

- https://en.wikipedia.org/wiki/Mirai_(malware)

- https://book.hacktricks.wiki/en/index.html

- https://github.com/swisskyrepo/PayloadsAllTheThings

- https://ippsec.rocks/

- https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470

- https://portswigger.net/web-security

Ainda falando sobre aprender conversamos sobre participar de comunidade, como isso é muito importante e auxilia bastante no nosso aprendizado. Aqui algumas comunidades muito legais que costumo participar:

- https://www.becodoexploit.com/6hack.html

- https://axesec.cc/pages/estudos/

- https://boitatech.com/

Daí sobre API falei do material da OWASP que é legal também:

- https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing/12-API_Testing

E por fim alguns equipamentos voltados para testes de redes:

- https://shop.hak5.org/products/wifi-pineapple

- https://shop.hak5.org/products/lan-turtle

- https://flipperzero.one/

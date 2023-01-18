[Day 1] Frameworks Someone's coming to town!

Frameworks:
	Security frameworks are politics and procedures that the organizations should follow to establish security control. They are created by identifying and managing the risks that may lead to an attack.

NIST cybersec framework:
	The cybersecurity framework was developed by the Nacional Institute of Standards and Techonolgy and this framework provide a detailed guidance for organizations to manage and reduce their cyber risk.
	This framework focus on five essential functions: Identify -> Protect -> Detect -> Respond -> Recover.

ISO 27000:
	The ISO 27001 and ISO 27002 are known for cybersecurity and outline the requirements for creating, implementing and managing and information security management security (ISMS). 

MITRE ATT&CK Framework:
	The MITRE ATT&CK is a knowledge base of TTP´s (Tactics, Techniques and Procedures). This framework analise attacks in high detailed way, so the organisations can develop effective security programs for themself.
 
Cyber Kill Chain:
	A key concept of this framework was adopted from the military with the terminology kill chain. The Cyber Kill Chain describes the stages commonly followed by cyber attacks.
	There are seven stages on this chain: Recon -> Weaponisation -> Delivery -> Exploitation -> Installation -> Command and control -> Actions on Objetives.

Unified kill Chain:
	The Unified kill Chain can be described as the unification of MITRE ATT&CK and Cyber Kill Chain frameworks. This kill chain is composed by 17 stages:
	Cycle 1 (in): Reconnaissance -> Weaponisation -> Delivery -> Social Engeeniring -> Exploitation -> Persistence -> Defence Evasion -> Command and Controll
	Cycle 2 (through): Pivoting -> Discovery -> Privilege Escalation -> Execution -> Credential Access ->  Lateral Movement
	Cycle 3 (Out): Collection -> Exfiltration -> Impact -> Objectives

Q1: The Bandit Yeti
Q2: THM{IT'S A Y3T1 CHR1$TMA $} 
Q3: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------

[Day 2] Log Analysis Santa's Naughty & Nice Log

What are Log files, and why are they useful
	Log files are files that contains historical records off all events, for example: Login attemps; Traffic on network; Files; Password changes; Application erros; etc...

Example of a log file:
	1 -> A timestamp of the event (Date,Time)
	2 -> The name of the service that is generating the logfile (ssh connection in this example)
	3 -> The actual event (In this case the autenthication failed)
	![[Pasted image 20221230230551.png]]

Q1: NO ANSWER NEEDED
Q2: 2
Q3: webserver.log
Q4: NO ANSWER NEEDED
Q5: Friday 
Q6: 10.10.249.191
Q7: santaslist.txt
Q8: THM{STOLENSANTASLIST}
Q9: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------

[Day 3] OSINT Nothing escapes detective McRed

What is OSINT?
	OSINT (Open Source Intelligence) is gathering and analysing public available data for intelligence pruposes, wich include   information collected from the Internet, the media, photos, etc..

OSINT Techniques:
	Google Dorks, Google Dorking involves using specialist search terms and advanced search operators to find results that are not usually displayed using regular search terms.
	Some examples: inurl (inurl:hacking) / filetype:pdf / site:tryhackme.com / site:github.com "DB_PASSWORD" (this will only look for DB_PASSWORD on the github website).
	-
	Whois lookup, whois database stores public domain information such as registrant (domain owner), administrative, billing and technical contacts in a centralised database. https://who.is
	-
	Robots.txt, the robots.txt is a publicly accessible file created by the website administrator and intended for search engines to allow or disallow indexing of the website's URLs.
	-
	Breached Database Search, a lot of Databases suffer with data breaches and the information come outsite. You can check on this website if your information has been leaked or not. https://haveibeenpwned.com/
	-
	Searching GitHub Repos, github is a platform that allows developers to host their code through version control. A developer can create multiple repositories and set the privacy setting as well. A common flaw is that the privacy of the repository is set as public, which means anyone can access it.

Q1: NAMECHEAP INC
Q2: {THM_OSINT_WORKS}
Q3: config.php
Q4:qa.santagift.shop
Q5: S@nta2022
Q6: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------

[Day 4] Scanning Scanning through the snow

What is scanning?
	Scanning is a set of procedures to identify live hosts, ports and services, discover the OS of the victim and identify vulnerabilities and threats in the network.

Scanning Types:
	Passive Scanning, this method involves scanning a network without directly interact with the target device. Passive scanning is usually carried out through packet capture and analysis tools like Wireshark
	-
	Ative Scanning, Active scanning is a scanning method whereby you scan individual endpoints in an IT network to retrieve more detailed information, the active scan involves sending packets or queries directly to specific assets rather than passively collecting that data by "catching" it in transit on the network's traffic.

Scanning Techniques:
	Network scanning, A network is usually a collection of interconnected hosts or computers to share information and resources. Network scanning helps to discover and map a complete network, including any live computer or hosts, open ports, IP addresses, and services running on any live host and operating system
	-
	Port scanning, port scanning is a conventional method to examine open ports in a network capable of receiving and sending data. First, an attacker maps a complete network with installed devices/ hosts like firewalls, routers, servers etc., then scans open ports on each live host. Port number varies between 0 to 65,536 based on the type of service running on the host
	-
	Vulnerability scanning, The vulnerability scanning proactively identifies the network's vulnerabilities in an automated way that helps determine whether the system may be threatened or exploited. Free and paid tools are available that help to identify loopholes in a target system through a pre-build database of vulnerabilities. Pentesters widely use tools such as [Nessus](https://www.tenable.com/products/nessus) and [Acunetix](https://www.acunetix.com/) to identify loopholes in a system.

Scanning tools:
	Nmap:   
	Ping Scan: Allows scanning the live hosts in the network without going deeper and checking for ports services etc. Usage: `nmap -sn MACHINE_IP`.
	Operating System Scan: Allows scanning of the type of OS running on a live host. Usage: `nmap -O MACHINE_IP`.
	Detecting Services: Get a list of running services on a live host. Usage: `nmap -sV MACHINE_IP`
	-
	Nikto:
	Nikto is open-source software that allows scanning websites for vulnerabilities. It enables looking for subdomains, outdated servers, debug messages etc., on a website. You can access it on the AttackBox by typing `nikto -host MACHINE_IP`

Q1: Apache
Q2: ssh
Q3: {THM_SANTA_SMB_SERVER}
Q4: santa25
Q5: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------

[Day 5] Brute-Forcing He knows when you're awake

Remote Access Service:
	SSH, Secure Shell. It was initially used in Unix systems to remote login, it contains an CLI (command-line Interface), so the user can execute code.
	-
	RDP, Remote Desktop Protocol (also know by: Remote Desktop Control (RDC), or only Remote Desktop (RD)). it provides a graphical user interface (GUI) to access an MS Windows System.
	-
	VNC, Virtual Network Computing. It provides access to a graphical interface with allows the user to view the desktop and control the mouse and keyboard.

Authentication:
	Authentication refers to the process where a system validates your identity. There are three parameteres that can validate your identity:
	Something you know, refers to something you can memorize, such as a password
	-
	Something you have, refers to something you own, hardware or software, such as a token, mobile phone, or a key file.
	-
	Something you are, refers to biometric authentication, fingerptint or retina for example.

Attacking Passwords:
	Passwords are the most commonly used authentication methods. Passwords are exposed to a variety of attacks for example:
	Shoulder Surfing, Looking over the victim´s shoulder might reveal the pattern they use to unlock their phone for example.
	-
	Password Gessing, Without proper cyber security awareness, some users might be inclined to use personal details, such as birth date or daughter´s name as there are easiest to remember.
	-
	Dictionary attack, This approach expands on password guessing and attempts to include all valid words in a dictionary or a word list.
	-
	Brute force attack, This attack is the most exhaustive and time-consuming, where an attacker can try all possible characters combinations (Famous wordlist rockyou.txt (/usr/share/wordlists/rockyou.txt))

Hacking an Authentication Service:
	We can start using nmap -sS $IP to see if there is any open port for an authentication service.
	Then, if we found like a port 22 (ssh) open, we can try using some sort of tool like hydra, is this way:
	hydra -l username (or -L for a list of usernames/dictionary) -p password (or -P for password list) $IP ssh

Q1: 1q2w3e4r
Q2: THM{I_SEE_YOUR_SCREEN}
Q3: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------

[Day 6] Email Analysis It's beginning to look a lot like phishing

What is Email Analysis?
	Email analysis is the process of extracting the email header information to expose the email file details. This headers contains details of the email like: Sender,recipient,path,return address and attachments.
	-
	Concerns in email analysis: Security issues, Identifying suspicious patterns in emails / Perfomance issues, identifying delivery and delay issues in emails.
	-
	Social Engineering, is a psychological manipulation of people into performing or divulging information by exploiting weakness in human nature.
	-
	Phishing, Is a sub-section of social engineering, delivered through email to trick someone into either revealing personal information and credentials or executing malicious code on
	their computer.

How to analyse emails?

| Field         | Details                                                          |
| ------------- | ---------------------------------------------------------------- |
| From          | Sender´s Address                                                 |
| To            | Receiver´s address, including cc and bcc                         |
| Date          | Timestamp, when the email was sent                               |
| Subject       | The subject of the email                                         |
| Return Path   | The return address of the reply.                                 |
| Domain Key    | Email domain keys are provided by email services to identify and authenticate emails.                                             |
| SPF           | Shows the server that was used to send the email                 |
| Message-id    | Unique ID of the email                                           |
| MIME-Version  | It help´s to understand contents and attachments                 |
| X-headers     | The receiver mail providers usually add these fields             |
| X-received    | Mail servers that the email went through                         |
| X-Spam status | Spam score of the email                                          |
| X-Mailer      | Email client name                                                | 

Q1: chief.elf@santaclaus.thm
Q2: murphy.evident@bandityeti.thm
Q3: Chief Elf
Q4: 3
Q5: AoC2022_Email_Analysis
Q6: RISKY
Q7: Division_of_labour-Load_share_plan.doc  
Q8: 0827bb9a2e7c0628b82256759f0f888ca1abd6a2d903acdb8e44aca6a1a03467  
Q9: Defense Evasion  
Q10: macro_hunter
Q11: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------

[Day 7] CyberChef Maldocs roasting on an open fire

This Exercise focus mainly in learning how to use Cyberchef (https://gchq.github.io/CyberChef/).

Q1: 9.49.0
Q2: 10
Q3: mysterygift.exe
Q4: hxxps[://]cdn[.]bandityeti[.]THM/files/index/
Q5: THM_MYSTERY_FLAG
Q6: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------
[Day 8] Smart Contracts Last Christmas I gave you my ETH

What is a blockchain:
	A blockchain is a digital databse disbtibuted among nodes of a p2p network. The blockchain is distributed among "peers" or members with no central server "decentralized". Due to its decentralized nature, each peer is expected to maintain the integrity of the blockchain.

Smart contracts:
	A majority of practical applications of blockchain rely on a tech known as a smart contract, this are the most commonly used as the backbone of DeFi applications (Decentralized Finance applications) to support a cryptocurrency on a blockchain.


Q1: NO ANSWER NEEDED
Q2: flag{411_ur_37h_15_m1n3}
Q3: NO ANSWER NEEDED

------------------------------------------------------------------------------------------------

[Day 9] Pivoting Dock the halls

What is a docker:
	

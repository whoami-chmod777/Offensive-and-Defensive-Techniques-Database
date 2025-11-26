
--- Information Gathering in Web Applications ---

We'll focused on the information gathering process, which is a crucial first step in cybersecurity. 
This post will covers active and passive information gathering techniques, providing foundational knowledge about different methods and tools that can be used to assess the security posture of a target. 
Active information gathering involves direct interaction with the target, while passive information gathering involves collecting information about the target without its knowledge.

The detailed topics include Whois queries, identifying technologies used on target websites, using the Internet Archive (Wayback Machine), advanced search techniques like Google Dorks, metadata analysis, DNS enumeration, discovery tools like theHarvester, subdomain enumeration, and file and directory scanning methods. 

These topics provide a comprehensive guide to methodologies and tools that are useful when testing the security of a web application or conducting cybersecurity research.
 
• Introduction
• Whois
• Technologies Used in Websites
• Internet Archive - Wayback Machine
• Google Dorks
• Meta Files
• DNS Enumeration
• Other Discovery Tools
• Subdomain Enumeration
• File and Directory Scanning


-- Introduction --

We will learn the fundamental ways, techniques, and tools for gathering detailed information about a website. 
Information gathering enables cybersecurity professionals to understand attack surfaces, identify potential weaknesses, and develop attack/defense strategies. 
This process is generally examined under two main categories: "active information gathering" and "passive information gathering."

➜ Active Information Gathering

This approach involves direct interaction with the target system. Queries sent or requests made during the information gathering process can be detected by the target system and may leave traces. 
Therefore, active information gathering methods are commonly considered more aggressive and should be conducted carefully.

➜ Passive Information Gathering

Passive information gathering is performed without direct interaction with the target system. 
These methods allow for gathering information about the target without leaving traces on the system, making the process much more covert. 
Passive information gathering methods include WHOIS queries, social media analysis, and the examination of third-party databases.


-- Whois --

Whois is a query and response protocol that allows you to gather important information about a website or an IP address. 
Whois queries can reveal a wealth of important information such as the domain owner, contact details, registration and expiration dates, and the service provider.

➜ Whois Query

First, we need to choose a tool to perform a Whois query. These tools can be web-based online tools or command-line tools.

root💀hackerbox:~# whois google.com
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.verisign-grs.com

domain:       COM

organisation: VeriSign Global Registry Services
address:      12061 Bluemont Way
address:      Reston VA 20190
address:      United States of America (the)

contact:      administrative
name:         Registry Customer Service
organisation: VeriSign Global Registry Services
address:      12061 Bluemont Way
address:      Reston VA 20190
address:      United States of America (the)
phone:        +1 703 925-6999
fax-no:       +1 703 948 3978
e-mail:       info@verisign-grs.com

contact:      technical
name:         Registry Customer Service
organisation: VeriSign Global Registry Services
address:      12061 Bluemont Way
address:      Reston VA 20190
address:      United States of America (the)
phone:        +1 703 925-6999
fax-no:       +1 703 948 3978
e-mail:       info@verisign-grs.com

nserver:      A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30
nserver:      B.GTLD-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30
nserver:      C.GTLD-SERVERS.NET 192.26.92.30 2001:503:83eb:0:0:0:0:30
nserver:      D.GTLD-SERVERS.NET 192.31.80.30 2001:500:856e:0:0:0:0:30
nserver:      E.GTLD-SERVERS.NET 192.12.94.30 2001:502:1ca1:0:0:0:0:30
nserver:      F.GTLD-SERVERS.NET 192.35.51.30 2001:503:d414:0:0:0:0:30
nserver:      G.GTLD-SERVERS.NET 192.42.93.30 2001:503:eea3:0:0:0:0:30
nserver:      H.GTLD-SERVERS.NET 192.54.112.30 2001:502:8cc:0:0:0:0:30
nserver:      I.GTLD-SERVERS.NET 192.43.172.30 2001:503:39c1:0:0:0:0:30
nserver:      J.GTLD-SERVERS.NET 192.48.79.30 2001:502:7094:0:0:0:0:30
nserver:      K.GTLD-SERVERS.NET 192.52.178.30 2001:503:d2d:0:0:0:0:30
nserver:      L.GTLD-SERVERS.NET 192.41.162.30 2001:500:d937:0:0:0:0:30
nserver:      M.GTLD-SERVERS.NET 192.55.83.30 2001:501:b1f9:0:0:0:0:30
ds-rdata:     19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a

whois:        whois.verisign-grs.com

status:       ACTIVE
remarks:      Registration information: http://www.verisigninc.com

created:      1985-01-01
changed:      2023-12-07
source:       IANA

# whois.verisign-grs.com

   Domain Name: GOOGLE.COM
   Registry Domain ID: 2138514_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2019-09-09T15:39:04Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar: MarkMonitor Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
   Registrar Abuse Contact Phone: +1.2086851750
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: NS1.GOOGLE.COM
   Name Server: NS2.GOOGLE.COM
   Name Server: NS3.GOOGLE.COM
   Name Server: NS4.GOOGLE.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
Last update of whois database: 2024-03-28T09:32:14Z 

# whois.markmonitor.com

Domain Name: google.com
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2019-09-09T15:39:04+0000
Creation Date: 1997-09-15T07:00:00+0000
Registrar Registration Expiration Date: 2028-09-13T07:00:00+0000
Registrar: MarkMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2086851750
Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
Domain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
Domain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
Domain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)
Registrant Organization: Google LLC
Registrant State/Province: CA
Registrant Country: US
Registrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com
Admin Organization: Google LLC
Admin State/Province: CA
Admin Country: US
Admin Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com
Tech Organization: Google LLC
Tech State/Province: CA
Tech Country: US
Tech Email: Select Request Email Form at https://domains.markmonitor.com/whois/google.com
Name Server: ns2.google.com
Name Server: ns4.google.com
Name Server: ns1.google.com
Name Server: ns3.google.com
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
Last update of WHOIS database: 2024-03-28T09:28:24+0000


➜ Interpretation of Whois Information

⇒ Domain Owner and Contact Information: Indicates who controls a website and how to contact them.
⇒ Registration and Expiration Dates: Shows when a domain was registered and when it needs to be renewed. This provides an idea of how long the domain has been active.
⇒ Nameserver Information: Indicates which DNS servers the domain uses, providing insights into the hosting provider.


https://lookup.icann.org/en
https://www.whois.com/whois/
https://whois.domaintools.com/


-- Technologies Used in Websites --

Websites are built using various technologies and tools, including server software, programming languages, frameworks, database systems, and more. 
We will see how to identify the underlying technologies of a website. Determining the technologies used in a website is crucial for identifying potential security vulnerabilities.

• Tools and Methods Used
• Curl Command
• Common Technology Identification Indicators

➜ Tools and Methods Used

⇒ Online Tools
Web-based tools provide technological information about a website. These tools analyze websites and determine the technologies used. 
Popular tools such as BuiltWith and Wappalyzer allow you to quickly identify the technologies used by a website

https://builtwith.com/
https://www.wappalyzer.com/

⇒ Browser Extensions
Browser extensions like Wappalyzer and WhatRuns are also very useful for identifying technologies used on websites. These extensions provide instant information about the technologies on the websites you visit.

https://www.wappalyzer.com/
https://www.whatruns.com/

⇒ Command-Line Tools
Tools like Curl can be used to query HTTP headers from web servers. These headers can reveal hints about the server software, CMS system, and sometimes the programming language used.

➜ Curl Command

root💀hackerbox:~# curl --head https://wordpress.org
HTTP/2 200 
server: nginx
date: Thu, 28 Mar 2024 10:44:38 GMT
content-type: text/html; charset=UTF-8
vary: Accept-Encoding
strict-transport-security: max-age=3600
x-olaf: ⛄
link: <https://wordpress.org/wp-json/>; rel="https://api.w.org/"
link: <https://wordpress.org/wp-json/wp/v2/pages/457>; rel="alternate"; type="application/json"
link: <https://w.org/>; rel=shortlink
x-frame-options: SAMEORIGIN
alt-svc: h3=":443"; ma=86400
x-nc: HIT ord 2

From the head request, we discovered that the wordpress.org site is running on an nginx web server.

➜  Common Technology Identification Indicators

⇒ Cookies

Web technologies often create specific cookies in browsers. The names of these cookies can include references to the technologies used.

+-------------------+----------------------------------------------+
| Framework         | Cookie                                       |
+-------------------+----------------------------------------------+
| Zope              | zope3                                        |
| CakePHP           | cakephp                                      |
| Kohana            | kohanasession                                |
| Laravel           | laravel_session                              |
| phpBB             | phpbb3_                                      |
| WordPress         | wp-settings                                  |
| 1C-Bitrix         | BITRIX_                                      |
| AMFcms            | AMP                                          |
| Django CMS        | django                                       |
| DotNetNuke        | DotNetNukeAnonymous                          |
| e107              | e107_tz                                      |
| EPiServer         | EPiTrace, EPiServer                          |
| Graffiti CMS      | graffitibot                                  |
| Hotaru CMS        | hotaru_mobile                                |
| ImpressCMS        | ICMSession                                   |
| Indico            | MAKCSESSION                                  |
| InstantCMS        | InstantCMS[logdate]                          |
| Kentico CMS       | CMSPreferredCulture                          |
| MODx              | SN4[{12ymb}]                                 |
| TYPO3             | fe_typo_user                                 |
| Dynamicweb        | Dynamicweb                                   |
| LEPTON            | lep[some_numeric_value]+sessionid            |
| Wix               | Domain=wix.com                               |
| VIVVO             | VivvoSessionId                               |
+-------------------+----------------------------------------------+

⇒ HTML Source Code

Technologies used in websites often require the addition of specific HTML tags. These tags may include references to the technologies used.

+--------------+-------------------------------------------------------------------------------------------------------------+
| Application  | Keyword                                                                                                     |
+--------------+-------------------------------------------------------------------------------------------------------------+
| WordPress    | <meta name="generator" content="WordPress 3.9.2" />                                                         |
| phpBB        | <body id="phpbb">                                                                                           |
| Mediawiki    | <meta name="generator" content="MediaWiki 1.21.9" />                                                        |
| Joomla       | <meta name="generator" content="Joomla! - Open Source Content Management" />                                |
| Drupal       | <meta name="Generator" content="Drupal 7 (http://drupal.org)" />                                            |
| DotNetNuke   | <meta name="generator" content="DNN Platform - [http://www.dnnsoftware.com](http://www.dnnsoftware.com)" /> |
+--------------+-------------------------------------------------------------------------------------------------------------+


-- Internet Archive - Wayback Machine --












•
➜ 
⇒
->
►


















-- Google Dorks --


-- Meta Files --


-- DNS Enumeration --


-- Other Discovery Tools --


-- Subdomain Enumeration --


-- File and Directory Scanning --







*

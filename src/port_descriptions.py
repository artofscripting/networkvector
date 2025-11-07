#!/usr/bin/env python3
"""
Port Descriptions Database for Network Vector

Comprehensive database of TCP port information including:
- Service descriptions and technical details
- Security risk assessments and recommendations
- Documentation links for further information
- 130+ well-known and commonly used ports

This module provides detailed port intelligence for the Network Vector scanner
to help users understand discovered services and assess security implications.
"""

# Comprehensive port descriptions database
PORT_DESCRIPTIONS = {
    # System and well-known ports (1-1023)
    1: {
        "description": "TCP Port Service Multiplexer",
        "details": "System port for TCP port service multiplexer. Rarely used in modern systems.",
        "security": "LOW RISK - System reserved port",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    2: {
        "description": "CompressNET Management Utility",
        "details": "Legacy compression service management. Not commonly used.",
        "security": "LOW RISK - Legacy system service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    3: {
        "description": "Compression Process",
        "details": "Data compression service. Legacy protocol rarely seen today.",
        "security": "LOW RISK - Legacy compression service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    5: {
        "description": "Remote Job Entry",
        "details": "Remote job entry protocol for mainframe systems. Legacy service.",
        "security": "MEDIUM RISK - Legacy remote access",
        "link": "https://en.wikipedia.org/wiki/Remote_job_entry"
    },
    7: {
        "description": "Echo Protocol",
        "details": "Simple network testing protocol that echoes back received data.",
        "security": "LOW RISK - Network testing service",
        "link": "https://tools.ietf.org/html/rfc862"
    },
    9: {
        "description": "Discard Protocol",
        "details": "Null service that discards all received data. Used for testing.",
        "security": "LOW RISK - Testing service",
        "link": "https://tools.ietf.org/html/rfc863"
    },
    11: {
        "description": "Active Users (systat)",
        "details": "System status protocol showing active users. Security risk if exposed.",
        "security": "MEDIUM RISK - Exposes system information",
        "link": "https://tools.ietf.org/html/rfc866"
    },
    13: {
        "description": "Daytime Protocol",
        "details": "Returns current date and time in human-readable format.",
        "security": "LOW RISK - Time service",
        "link": "https://tools.ietf.org/html/rfc867"
    },
    15: {
        "description": "Netstat Service",
        "details": "Returns network status information. Can expose network topology.",
        "security": "MEDIUM RISK - Network information disclosure",
        "link": "https://en.wikipedia.org/wiki/Netstat"
    },
    17: {
        "description": "Quote of the Day (QOTD)",
        "details": "Returns a quote or message. Sometimes exploited for DDoS amplification.",
        "security": "MEDIUM RISK - Can be used for amplification attacks",
        "link": "https://tools.ietf.org/html/rfc865"
    },
    18: {
        "description": "Message Send Protocol",
        "details": "Legacy messaging protocol. Rarely used in modern systems.",
        "security": "LOW RISK - Legacy messaging",
        "link": "https://tools.ietf.org/html/rfc1312"
    },
    19: {
        "description": "Character Generator (chargen)",
        "details": "Generates continuous stream of characters. DDoS amplification risk.",
        "security": "HIGH RISK - DDoS amplification vector",
        "link": "https://tools.ietf.org/html/rfc864"
    },
    20: {
        "description": "FTP Data Transfer",
        "details": "File Transfer Protocol data channel for active mode transfers.",
        "security": "HIGH RISK - Unencrypted file transfer",
        "link": "https://en.wikipedia.org/wiki/File_Transfer_Protocol"
    },
    21: {
        "description": "FTP Control - File Transfer Protocol control channel",
        "details": "Used for uploading/downloading files. Often a security risk if unencrypted.",
        "security": "HIGH RISK - Unencrypted, credentials sent in plaintext",
        "link": "https://en.wikipedia.org/wiki/File_Transfer_Protocol"
    },
    22: {
        "description": "SSH - Secure Shell remote access",
        "details": "Encrypted remote terminal access and secure file transfer (SFTP/SCP).",
        "security": "SECURE - Encrypted communication",
        "link": "https://www.openssh.com/"
    },
    23: {
        "description": "Telnet - Unencrypted remote terminal",
        "details": "Legacy remote terminal protocol. Sends passwords in plaintext.",
        "security": "HIGH RISK - Unencrypted, avoid using",
        "link": "https://en.wikipedia.org/wiki/Telnet"
    },
    25: {
        "description": "SMTP - Simple Mail Transfer Protocol",
        "details": "Email server communication for sending emails between servers.",
        "security": "MEDIUM - Can be secured with TLS",
        "link": "https://tools.ietf.org/html/rfc5321"
    },
    37: {
        "description": "Time Protocol",
        "details": "Network time protocol that returns time since Unix epoch.",
        "security": "LOW RISK - Time synchronization",
        "link": "https://tools.ietf.org/html/rfc868"
    },
    39: {
        "description": "Resource Location Protocol",
        "details": "Legacy resource discovery protocol. Rarely used today.",
        "security": "LOW RISK - Legacy discovery service",
        "link": "https://tools.ietf.org/html/rfc887"
    },
    42: {
        "description": "Host Name Server",
        "details": "Legacy hostname resolution service. Superseded by DNS.",
        "security": "LOW RISK - Legacy naming service",
        "link": "https://tools.ietf.org/html/rfc953"
    },
    43: {
        "description": "WHOIS - Domain registration lookup",
        "details": "Domain and IP address registration information lookup service.",
        "security": "LOW RISK - Public information service",
        "link": "https://tools.ietf.org/html/rfc3912"
    },
    49: {
        "description": "TACACS Login Host Protocol",
        "details": "Terminal Access Controller Access Control System authentication.",
        "security": "MEDIUM RISK - Authentication service",
        "link": "https://tools.ietf.org/html/rfc1492"
    },
    50: {
        "description": "Remote Mail Checking Protocol",
        "details": "Legacy protocol for checking remote mail. Rarely used.",
        "security": "LOW RISK - Legacy mail service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    53: {
        "description": "DNS - Domain Name System",
        "details": "Translates domain names to IP addresses. Critical internet infrastructure.",
        "security": "LOW RISK - Standard service, can be secured with DoT/DoH",
        "link": "https://www.cloudflare.com/learning/dns/what-is-dns/"
    },
    57: {
        "description": "MTP - Mail Transfer Protocol",
        "details": "Legacy mail transfer protocol. Superseded by SMTP.",
        "security": "LOW RISK - Legacy mail protocol",
        "link": "https://tools.ietf.org/html/rfc780"
    },
    58: {
        "description": "XNS Mail Protocol",
        "details": "Xerox Network Systems mail protocol. Legacy system.",
        "security": "LOW RISK - Legacy Xerox protocol",
        "link": "https://en.wikipedia.org/wiki/Xerox_Network_Systems"
    },
    67: {
        "description": "DHCP/BOOTP Server",
        "details": "Dynamic Host Configuration Protocol server for IP address assignment.",
        "security": "MEDIUM RISK - Network configuration service",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    68: {
        "description": "DHCP/BOOTP Client",
        "details": "Dynamic Host Configuration Protocol client for receiving IP configuration.",
        "security": "LOW RISK - DHCP client communication",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    69: {
        "description": "TFTP - Trivial File Transfer Protocol",
        "details": "Simple file transfer protocol without authentication. Often insecure.",
        "security": "HIGH RISK - No authentication, plaintext transfer",
        "link": "https://tools.ietf.org/html/rfc1350"
    },
    70: {
        "description": "Gopher Protocol",
        "details": "Legacy hierarchical document system predating the World Wide Web.",
        "security": "LOW RISK - Legacy document protocol",
        "link": "https://tools.ietf.org/html/rfc1436"
    },
    71: {
        "description": "NETRJS Protocol",
        "details": "Network Remote Job Service. Legacy mainframe job submission.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    72: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    73: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    74: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    79: {
        "description": "Finger Protocol",
        "details": "User information lookup protocol. Exposes user details and system info.",
        "security": "HIGH RISK - Information disclosure, privacy concerns",
        "link": "https://tools.ietf.org/html/rfc1288"
    },
    80: {
        "description": "HTTP - HyperText Transfer Protocol",
        "details": "Web server communication. Unencrypted web traffic.",
        "security": "MEDIUM RISK - Unencrypted, use HTTPS instead",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    81: {
        "description": "HTTP Alternate",
        "details": "Alternative HTTP port often used for web administration or proxies.",
        "security": "MEDIUM RISK - Unencrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    82: {
        "description": "XFER Utility",
        "details": "File transfer utility. Implementation varies by system.",
        "security": "MEDIUM RISK - File transfer service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    83: {
        "description": "MIT ML Device",
        "details": "MIT Machine Learning device protocol. Research/academic use.",
        "security": "LOW RISK - Academic research protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    84: {
        "description": "Common Trace Facility",
        "details": "System tracing and debugging facility.",
        "security": "MEDIUM RISK - System debugging information",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    85: {
        "description": "MIT ML Device (continued)",
        "details": "MIT Machine Learning device protocol continuation.",
        "security": "LOW RISK - Academic research protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    87: {
        "description": "Terminal Link",
        "details": "Legacy terminal linking protocol. Rarely used today.",
        "security": "LOW RISK - Legacy terminal service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    88: {
        "description": "Kerberos Authentication",
        "details": "Network authentication protocol using tickets and encryption.",
        "security": "SECURE - Strong authentication protocol",
        "link": "https://web.mit.edu/kerberos/"
    },
    89: {
        "description": "SU-MIT Telnet Gateway",
        "details": "Stanford University MIT Telnet gateway service.",
        "security": "MEDIUM RISK - Telnet gateway service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    90: {
        "description": "DNSIX Security Attribute Token Map",
        "details": "Defense Intelligence Agency security token mapping.",
        "security": "MEDIUM RISK - Security token service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    95: {
        "description": "SUPDUP Protocol",
        "details": "Stanford University Display Protocol for remote terminals.",
        "security": "MEDIUM RISK - Remote terminal protocol",
        "link": "https://en.wikipedia.org/wiki/SUPDUP"
    },
    98: {
        "description": "Linuxconf",
        "details": "Linux system configuration tool web interface.",
        "security": "HIGH RISK - System configuration access",
        "link": "https://en.wikipedia.org/wiki/Linuxconf"
    },
    99: {
        "description": "WIP Message Protocol",
        "details": "Wireless Internet Protocol message service.",
        "security": "MEDIUM RISK - Wireless messaging service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    100: {
        "description": "NEWACCT Account Creation",
        "details": "Automated account creation service. Security risk if exposed.",
        "security": "HIGH RISK - Account creation service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    
    # Additional well-known ports (101-200)
    101: {
        "description": "NIC Host Name Server",
        "details": "Network Information Center hostname resolution service.",
        "security": "LOW RISK - Legacy naming service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    102: {
        "description": "ISO-TSAP Protocol",
        "details": "ISO Transport Service Access Point. Legacy networking protocol.",
        "security": "LOW RISK - Legacy ISO protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    103: {
        "description": "Genesis Point-to-Point Trans Net",
        "details": "Legacy networking protocol for point-to-point communication.",
        "security": "LOW RISK - Legacy networking protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    104: {
        "description": "ACR-NEMA Digital Imaging",
        "details": "Medical imaging communication protocol (predecessor to DICOM).",
        "security": "MEDIUM RISK - Medical data transmission",
        "link": "https://en.wikipedia.org/wiki/DICOM"
    },
    105: {
        "description": "CCSO Nameserver (CSNet)",
        "details": "Computer Science Network nameserver protocol.",
        "security": "LOW RISK - Legacy nameserver",
        "link": "https://en.wikipedia.org/wiki/CSNET"
    },
    106: {
        "description": "3COM-TSMUX",
        "details": "3COM terminal server multiplexer protocol.",
        "security": "MEDIUM RISK - Terminal server access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    107: {
        "description": "Remote Telnet Service",
        "details": "Remote telnet service with additional features.",
        "security": "HIGH RISK - Remote terminal access",
        "link": "https://en.wikipedia.org/wiki/Telnet"
    },
    108: {
        "description": "SNA Gateway Access Server",
        "details": "IBM Systems Network Architecture gateway service.",
        "security": "MEDIUM RISK - Legacy IBM networking",
        "link": "https://en.wikipedia.org/wiki/Systems_Network_Architecture"
    },
    109: {
        "description": "POP2 - Post Office Protocol v2",
        "details": "Legacy email retrieval protocol. Superseded by POP3.",
        "security": "HIGH RISK - Legacy, unencrypted email protocol",
        "link": "https://tools.ietf.org/html/rfc937"
    },
    110: {
        "description": "POP3 - Post Office Protocol v3",
        "details": "Email retrieval protocol. Downloads emails to client device.",
        "security": "MEDIUM RISK - Can be secured with SSL/TLS",
        "link": "https://tools.ietf.org/html/rfc1939"
    },
    111: {
        "description": "RPC Portmapper - Remote Procedure Call",
        "details": "Maps RPC program numbers to network ports. Used by NFS and other services.",
        "security": "HIGH RISK - Can expose other services",
        "link": "https://en.wikipedia.org/wiki/Open_Network_Computing_Remote_Procedure_Call"
    },
    112: {
        "description": "McIDAS Data Transmission Protocol",
        "details": "Meteorological data transmission for weather systems.",
        "security": "LOW RISK - Weather data service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    113: {
        "description": "Ident - User identification protocol",
        "details": "Identifies the user of a TCP connection. Privacy and security concerns.",
        "security": "MEDIUM RISK - User information disclosure",
        "link": "https://tools.ietf.org/html/rfc1413"
    },
    115: {
        "description": "SFTP - Simple File Transfer Protocol",
        "details": "Legacy simple file transfer protocol (not SSH SFTP).",
        "security": "MEDIUM RISK - Legacy file transfer",
        "link": "https://tools.ietf.org/html/rfc913"
    },
    117: {
        "description": "UUCP Path Service",
        "details": "Unix-to-Unix Copy Protocol path information service.",
        "security": "LOW RISK - Legacy Unix networking",
        "link": "https://en.wikipedia.org/wiki/UUCP"
    },
    118: {
        "description": "SQL Services",
        "details": "Structured Query Language database services.",
        "security": "HIGH RISK - Database access",
        "link": "https://en.wikipedia.org/wiki/SQL"
    },
    119: {
        "description": "NNTP - Network News Transfer Protocol",
        "details": "Protocol for reading and posting Usenet news articles.",
        "security": "MEDIUM RISK - News/forum service",
        "link": "https://tools.ietf.org/html/rfc3977"
    },
    120: {
        "description": "CFDPTKT - Configuration File Transfer",
        "details": "Configuration file transfer protocol.",
        "security": "MEDIUM RISK - Configuration transfer",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    121: {
        "description": "ERPC - Encore RPC",
        "details": "Encore Computer Corporation Remote Procedure Call.",
        "security": "MEDIUM RISK - Legacy RPC service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    123: {
        "description": "NTP - Network Time Protocol",
        "details": "Synchronizes computer clocks across networks.",
        "security": "LOW RISK - Time synchronization service",
        "link": "https://www.ntp.org/"
    },
    125: {
        "description": "LOCUS-MAP - Network Mapping",
        "details": "LOCUS distributed system mapping protocol.",
        "security": "MEDIUM RISK - Network topology information",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    129: {
        "description": "PWDGEN Password Generator",
        "details": "Password generation service. Security risk if exposed.",
        "security": "HIGH RISK - Password generation service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    135: {
        "description": "Microsoft RPC Endpoint Mapper",
        "details": "Windows RPC service that maps RPC endpoints. Critical Windows service.",
        "security": "HIGH RISK - Common attack target, restrict access",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/rpc-start-page"
    },
    137: {
        "description": "NetBIOS Name Service",
        "details": "Windows NetBIOS name resolution service. Legacy networking.",
        "security": "HIGH RISK - Legacy protocol, information disclosure",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    138: {
        "description": "NetBIOS Datagram Service",
        "details": "Windows NetBIOS datagram distribution service.",
        "security": "HIGH RISK - Legacy protocol, security issues",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    139: {
        "description": "NetBIOS Session Service - Windows networking",
        "details": "Legacy Windows file sharing protocol. Part of SMB over NetBIOS.",
        "security": "HIGH RISK - Legacy protocol, disable if possible",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    143: {
        "description": "IMAP - Internet Message Access Protocol",
        "details": "Email access protocol that keeps emails on server. More advanced than POP3.",
        "security": "MEDIUM RISK - Should use SSL/TLS (port 993)",
        "link": "https://tools.ietf.org/html/rfc3501"
    },
    389: {
        "description": "LDAP - Lightweight Directory Access Protocol",
        "details": "Directory service protocol for accessing user/computer information.",
        "security": "MEDIUM RISK - Should use LDAPS (port 636)",
        "link": "https://ldap.com/"
    },
    443: {
        "description": "HTTPS - HTTP over SSL/TLS",
        "details": "Secure web server communication with encrypted traffic.",
        "security": "SECURE - Encrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Glossary/HTTPS"
    },
    445: {
        "description": "Microsoft-DS - SMB file sharing",
        "details": "Modern Windows file sharing protocol. Replaced NetBIOS SMB.",
        "security": "HIGH RISK - Common ransomware target, secure properly",
        "link": "https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-smb-overview"
    },
    465: {
        "description": "SMTP over SSL - Secure email submission",
        "details": "Encrypted email submission protocol. More secure than plain SMTP.",
        "security": "SECURE - Encrypted email transmission",
        "link": "https://tools.ietf.org/html/rfc8314"
    },
    587: {
        "description": "SMTP Submission - Email submission with STARTTLS",
        "details": "Modern email submission port that supports encryption via STARTTLS.",
        "security": "SECURE - Can be encrypted",
        "link": "https://tools.ietf.org/html/rfc6409"
    },
    631: {
        "description": "IPP - Internet Printing Protocol",
        "details": "Network printing protocol used by CUPS and modern printers.",
        "security": "LOW RISK - Printing service",
        "link": "https://tools.ietf.org/html/rfc8011"
    },
    636: {
        "description": "LDAPS - LDAP over SSL/TLS",
        "details": "Secure LDAP directory service with encrypted communication.",
        "security": "SECURE - Encrypted directory access",
        "link": "https://ldap.com/ldap-over-ssl-tls-and-starttls/"
    },
    993: {
        "description": "IMAPS - IMAP over SSL/TLS",
        "details": "Secure IMAP email access with encrypted communication.",
        "security": "SECURE - Encrypted email access",
        "link": "https://tools.ietf.org/html/rfc8314"
    },
    995: {
        "description": "POP3S - POP3 over SSL/TLS",
        "details": "Secure POP3 email retrieval with encrypted communication.",
        "security": "SECURE - Encrypted email retrieval",
        "link": "https://tools.ietf.org/html/rfc8314"
    },
    1433: {
        "description": "Microsoft SQL Server - Database server",
        "details": "Microsoft SQL Server database engine. Contains sensitive business data.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://docs.microsoft.com/en-us/sql/sql-server/"
    },
    1521: {
        "description": "Oracle Database - TNS Listener",
        "details": "Oracle database listener service. Handles database connections.",
        "security": "HIGH RISK - Database access, secure properly",
        "link": "https://docs.oracle.com/en/database/"
    },
    2049: {
        "description": "NFS - Network File System",
        "details": "Unix/Linux network file sharing protocol.",
        "security": "MEDIUM RISK - Secure with proper authentication",
        "link": "https://en.wikipedia.org/wiki/Network_File_System"
    },
    3306: {
        "description": "MySQL Database Server",
        "details": "Popular open-source database management system.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://dev.mysql.com/doc/"
    },
    3389: {
        "description": "Microsoft RDP - Remote Desktop Protocol",
        "details": "Windows remote desktop access. Frequently targeted by attackers.",
        "security": "HIGH RISK - Common attack target, secure with NLA",
        "link": "https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol"
    },
    5432: {
        "description": "PostgreSQL Database Server",
        "details": "Advanced open-source relational database management system.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://www.postgresql.org/docs/"
    },
    5900: {
        "description": "VNC - Virtual Network Computing",
        "details": "Remote desktop protocol. Often poorly secured by default.",
        "security": "HIGH RISK - Often weak passwords, encrypt traffic",
        "link": "https://en.wikipedia.org/wiki/Virtual_Network_Computing"
    },
    6379: {
        "description": "Redis - In-memory data structure store",
        "details": "Fast in-memory database, cache, and message broker.",
        "security": "HIGH RISK - Often exposed without authentication",
        "link": "https://redis.io/documentation"
    },
    8080: {
        "description": "HTTP Alternate - Web cache/proxy server",
        "details": "Alternative HTTP port often used by web applications and proxies.",
        "security": "MEDIUM RISK - Unencrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    8443: {
        "description": "HTTPS Alternate - Secure web server alternate",
        "details": "Alternative HTTPS port used by web applications and admin interfaces.",
        "security": "SECURE - Encrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Glossary/HTTPS"
    },
    24800: {
        "description": "Synergy - Screen and keyboard sharing",
        "details": "Software for sharing mouse and keyboard between computers.",
        "security": "MEDIUM RISK - Can intercept keystrokes",
        "link": "https://symless.com/synergy"
    },
    
    # Additional commonly found ports from network scans
    515: {
        "description": "Line Printer Daemon (LPD) - Print spooler",
        "details": "Network printing protocol for Unix/Linux systems and network printers.",
        "security": "MEDIUM RISK - Network printing service",
        "link": "https://tools.ietf.org/html/rfc1179"
    },
    548: {
        "description": "AFP - Apple Filing Protocol",
        "details": "Apple file sharing protocol for macOS systems and network storage.",
        "security": "MEDIUM RISK - Apple file sharing, encrypt if possible",
        "link": "https://en.wikipedia.org/wiki/Apple_Filing_Protocol"
    },
    873: {
        "description": "rsync - Remote synchronization",
        "details": "File synchronization protocol for efficient data transfer and backup.",
        "security": "MEDIUM RISK - File transfer service, secure with SSH tunnel",
        "link": "https://rsync.samba.org/"
    },
    902: {
        "description": "VMware ESX Console",
        "details": "VMware vSphere console access and management interface.",
        "security": "HIGH RISK - Virtual infrastructure management",
        "link": "https://docs.vmware.com/en/VMware-vSphere/"
    },
    912: {
        "description": "VMware vCenter/ESX",
        "details": "VMware management and monitoring services.",
        "security": "HIGH RISK - Virtual infrastructure management",
        "link": "https://docs.vmware.com/en/VMware-vSphere/"
    },
    1080: {
        "description": "SOCKS Proxy - Proxy protocol",
        "details": "SOCKS proxy protocol for network traffic routing and anonymization.",
        "security": "MEDIUM RISK - Proxy service, monitor usage",
        "link": "https://tools.ietf.org/html/rfc1928"
    },
    1433: {
        "description": "Microsoft SQL Server - Database server",
        "details": "Microsoft SQL Server database engine. Contains sensitive business data.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://docs.microsoft.com/en-us/sql/sql-server/"
    },
    1521: {
        "description": "Oracle Database - TNS Listener",
        "details": "Oracle database listener service. Handles database connections.",
        "security": "HIGH RISK - Database access, secure properly",
        "link": "https://docs.oracle.com/en/database/"
    },
    1723: {
        "description": "PPTP - Point-to-Point Tunneling Protocol",
        "details": "Legacy VPN protocol with known security vulnerabilities.",
        "security": "HIGH RISK - Deprecated, use modern VPN protocols",
        "link": "https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol"
    },
    1900: {
        "description": "UPnP - Universal Plug and Play",
        "details": "Automatic device discovery and configuration. Often insecure.",
        "security": "HIGH RISK - Can expose internal services",
        "link": "https://en.wikipedia.org/wiki/Universal_Plug_and_Play"
    },
    2049: {
        "description": "NFS - Network File System",
        "details": "Unix/Linux network file sharing protocol.",
        "security": "MEDIUM RISK - Secure with proper authentication",
        "link": "https://en.wikipedia.org/wiki/Network_File_System"
    },
    2869: {
        "description": "UPnP/SSDP - Universal Plug and Play discovery",
        "details": "Windows UPnP device discovery and media sharing service.",
        "security": "MEDIUM RISK - Can expose internal services",
        "link": "https://en.wikipedia.org/wiki/Universal_Plug_and_Play"
    },
    3306: {
        "description": "MySQL Database Server",
        "details": "Popular open-source database management system.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://dev.mysql.com/doc/"
    },
    3689: {
        "description": "iTunes/DAAP - Digital Audio Access Protocol",
        "details": "Apple iTunes music sharing and streaming service.",
        "security": "LOW RISK - Media streaming service",
        "link": "https://en.wikipedia.org/wiki/Digital_Audio_Access_Protocol"
    },
    5432: {
        "description": "PostgreSQL Database Server",
        "details": "Advanced open-source relational database management system.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://www.postgresql.org/docs/"
    },
    5800: {
        "description": "VNC over HTTP - Remote desktop via web",
        "details": "VNC remote desktop access through web browser interface.",
        "security": "HIGH RISK - Remote desktop access, often weak passwords",
        "link": "https://en.wikipedia.org/wiki/Virtual_Network_Computing"
    },
    6379: {
        "description": "Redis - In-memory data structure store",
        "details": "Fast in-memory database, cache, and message broker.",
        "security": "HIGH RISK - Often exposed without authentication",
        "link": "https://redis.io/documentation"
    },
    7070: {
        "description": "RealServer/Aruba - Media streaming or network management",
        "details": "Real-time media streaming or Aruba network device management.",
        "security": "MEDIUM RISK - Media/network management service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    8008: {
        "description": "HTTP Alternate - Alternative web server",
        "details": "Alternative HTTP port often used for web applications and embedded devices.",
        "security": "MEDIUM RISK - Unencrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    8009: {
        "description": "HTTP Alternate/AJP - Apache JServ Protocol",
        "details": "Apache JServ Protocol for connecting web servers with application servers.",
        "security": "MEDIUM RISK - Application server communication",
        "link": "https://tomcat.apache.org/tomcat-9.0-doc/config/ajp.html"
    },
    8873: {
        "description": "dxspider/rsync alternate - Packet radio cluster",
        "details": "DX Spider packet radio cluster software or rsync alternative port.",
        "security": "LOW RISK - Amateur radio or file sync service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    9050: {
        "description": "Tor SOCKS - Tor proxy service",
        "details": "Tor anonymity network SOCKS proxy for anonymous internet access.",
        "security": "MEDIUM RISK - Anonymity service, monitor usage policy",
        "link": "https://www.torproject.org/"
    },
    9100: {
        "description": "PDL - Printer Data Language",
        "details": "Direct network printing protocol used by HP and other printers.",
        "security": "LOW RISK - Network printing service",
        "link": "https://en.wikipedia.org/wiki/Printer_Job_Language"
    },
    10001: {
        "description": "SCP-Config - Network device configuration",
        "details": "Network device configuration protocol or custom application service.",
        "security": "MEDIUM RISK - Device configuration service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    22939: {
        "description": "Palo Alto Networks - Management interface",
        "details": "Palo Alto Networks firewall management and configuration interface.",
        "security": "HIGH RISK - Firewall management access",
        "link": "https://docs.paloaltonetworks.com/"
    },
    49152: {
        "description": "Windows Dynamic Port - Ephemeral port range",
        "details": "Windows dynamic/ephemeral port range used for outbound connections and RPC.",
        "security": "MEDIUM RISK - Windows system service",
        "link": "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements"
    },
    62078: {
        "description": "Apple iPhoto/Screen Sharing - macOS service",
        "details": "Apple macOS screen sharing, iPhoto sharing, or other Apple services.",
        "security": "MEDIUM RISK - Apple system service",
        "link": "https://support.apple.com/en-us/HT204618"
    },
    
    # Development and application ports commonly found
    3000: {
        "description": "Node.js/React Development Server or Grafana",
        "details": "Common development server port for Node.js, React, web applications, or Grafana dashboard.",
        "security": "MEDIUM RISK - Development/monitoring service",
        "link": "https://nodejs.org/"
    },
    3001: {
        "description": "Node.js/Development Server Alternate",
        "details": "Alternative development server port for web applications and APIs.",
        "security": "MEDIUM RISK - Development service, should not be public", 
        "link": "https://nodejs.org/"
    },
    4000: {
        "description": "Development Server - Various frameworks",
        "details": "Common port for development servers, Docker registry, or web applications.",
        "security": "MEDIUM RISK - Development/application service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    5000: {
        "description": "Flask/Python Development Server",
        "details": "Default port for Flask development server and various Python applications.",
        "security": "MEDIUM RISK - Development service, should not be public",
        "link": "https://flask.palletsprojects.com/"
    },
    8000: {
        "description": "Django/Python Development Server", 
        "details": "Default port for Django development server and Python web applications.",
        "security": "MEDIUM RISK - Development service, should not be public",
        "link": "https://www.djangoproject.com/"
    },
    
    # Additional database and enterprise ports
    27017: {
        "description": "MongoDB Database",
        "details": "MongoDB NoSQL database server default port.",
        "security": "HIGH RISK - Database, often misconfigured without auth",
        "link": "https://docs.mongodb.com/"
    },
    
    # Container and orchestration ports
    2375: {
        "description": "Docker REST API (unencrypted)",
        "details": "Docker daemon REST API without TLS encryption.",
        "security": "HIGH RISK - Container management, use TLS (2376)",
        "link": "https://docs.docker.com/engine/api/"
    },
    2376: {
        "description": "Docker REST API (encrypted)",
        "details": "Docker daemon REST API with TLS encryption.",
        "security": "MEDIUM RISK - Secure container management API",
        "link": "https://docs.docker.com/engine/api/"
    },
    6443: {
        "description": "Kubernetes API Server",
        "details": "Kubernetes cluster API server for container orchestration.",
        "security": "HIGH RISK - Container orchestration control plane",
        "link": "https://kubernetes.io/docs/"
    },
    10250: {
        "description": "Kubernetes kubelet API",
        "details": "Kubernetes node agent API for container management.",
        "security": "HIGH RISK - Kubernetes node management",
        "link": "https://kubernetes.io/docs/"
    },
    
    # Monitoring and metrics ports
    9090: {
        "description": "Prometheus - Metrics collection",
        "details": "Prometheus monitoring system and time series database.",
        "security": "MEDIUM RISK - Monitoring system, can expose metrics",
        "link": "https://prometheus.io/"
    },
    9200: {
        "description": "Elasticsearch - Search engine",
        "details": "Elasticsearch distributed search and analytics engine.",
        "security": "HIGH RISK - Search engine, often misconfigured",
        "link": "https://www.elastic.co/elasticsearch/"
    },
    
    # Additional common system and network ports (100+ new entries)
    1: {
        "description": "TCP Port Service Multiplexer",
        "details": "System port for TCP port service multiplexer. Rarely used in modern systems.",
        "security": "LOW RISK - System reserved port",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    3: {
        "description": "Compression Process",
        "details": "Data compression service. Legacy protocol rarely seen today.",
        "security": "LOW RISK - Legacy compression service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    4: {
        "description": "Unassigned System Port",
        "details": "Unassigned system port in the well-known range.",
        "security": "LOW RISK - System reserved",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    6: {
        "description": "Unassigned System Port",
        "details": "Unassigned system port in the well-known range.",
        "security": "LOW RISK - System reserved",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    7: {
        "description": "Echo Protocol",
        "details": "Simple network testing protocol that echoes back received data.",
        "security": "LOW RISK - Network testing service",
        "link": "https://tools.ietf.org/html/rfc862"
    },
    9: {
        "description": "Discard Protocol",
        "details": "Null service that discards all received data. Used for testing.",
        "security": "LOW RISK - Testing service",
        "link": "https://tools.ietf.org/html/rfc863"
    },
    11: {
        "description": "Active Users (systat)",
        "details": "System status protocol showing active users. Security risk if exposed.",
        "security": "MEDIUM RISK - Exposes system information",
        "link": "https://tools.ietf.org/html/rfc866"
    },
    13: {
        "description": "Daytime Protocol",
        "details": "Returns current date and time in human-readable format.",
        "security": "LOW RISK - Time service",
        "link": "https://tools.ietf.org/html/rfc867"
    },
    15: {
        "description": "Netstat Service",
        "details": "Returns network status information. Can expose network topology.",
        "security": "MEDIUM RISK - Network information disclosure",
        "link": "https://en.wikipedia.org/wiki/Netstat"
    },
    17: {
        "description": "Quote of the Day (QOTD)",
        "details": "Returns a quote or message. Sometimes exploited for DDoS amplification.",
        "security": "MEDIUM RISK - Can be used for amplification attacks",
        "link": "https://tools.ietf.org/html/rfc865"
    },
    18: {
        "description": "Message Send Protocol",
        "details": "Legacy messaging protocol. Rarely used in modern systems.",
        "security": "LOW RISK - Legacy messaging",
        "link": "https://tools.ietf.org/html/rfc1312"
    },
    19: {
        "description": "Character Generator (chargen)",
        "details": "Generates continuous stream of characters. DDoS amplification risk.",
        "security": "HIGH RISK - DDoS amplification vector",
        "link": "https://tools.ietf.org/html/rfc864"
    },
    26: {
        "description": "RSFTP - Simple Mail Transfer",
        "details": "Legacy simple mail transfer protocol.",
        "security": "LOW RISK - Legacy protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    30: {
        "description": "Unassigned",
        "details": "Unassigned port in well-known range.",
        "security": "LOW RISK - System reserved",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    32: {
        "description": "Unassigned",
        "details": "Unassigned port in well-known range.",
        "security": "LOW RISK - System reserved",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    33: {
        "description": "Display Support Protocol",
        "details": "Legacy display support protocol.",
        "security": "LOW RISK - Legacy display service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    37: {
        "description": "Time Protocol",
        "details": "Network time protocol that returns time since Unix epoch.",
        "security": "LOW RISK - Time synchronization",
        "link": "https://tools.ietf.org/html/rfc868"
    },
    42: {
        "description": "Host Name Server",
        "details": "Legacy hostname resolution service. Superseded by DNS.",
        "security": "LOW RISK - Legacy naming service",
        "link": "https://tools.ietf.org/html/rfc953"
    },
    49: {
        "description": "TACACS Login Host Protocol",
        "details": "Terminal Access Controller Access Control System authentication.",
        "security": "MEDIUM RISK - Authentication service",
        "link": "https://tools.ietf.org/html/rfc1492"
    },
    50: {
        "description": "Remote Mail Checking Protocol",
        "details": "Legacy protocol for checking remote mail. Rarely used.",
        "security": "LOW RISK - Legacy mail service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    57: {
        "description": "MTP - Mail Transfer Protocol",
        "details": "Legacy mail transfer protocol. Superseded by SMTP.",
        "security": "LOW RISK - Legacy mail protocol",
        "link": "https://tools.ietf.org/html/rfc780"
    },
    58: {
        "description": "XNS Mail Protocol",
        "details": "Xerox Network Systems mail protocol. Legacy system.",
        "security": "LOW RISK - Legacy Xerox protocol",
        "link": "https://en.wikipedia.org/wiki/Xerox_Network_Systems"
    },
    67: {
        "description": "DHCP/BOOTP Server",
        "details": "Dynamic Host Configuration Protocol server for IP address assignment.",
        "security": "MEDIUM RISK - Network configuration service",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    68: {
        "description": "DHCP/BOOTP Client",
        "details": "Dynamic Host Configuration Protocol client for receiving IP configuration.",
        "security": "LOW RISK - DHCP client communication",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    70: {
        "description": "Gopher Protocol",
        "details": "Legacy hierarchical document system predating the World Wide Web.",
        "security": "LOW RISK - Legacy document protocol",
        "link": "https://tools.ietf.org/html/rfc1436"
    },
    81: {
        "description": "HTTP Alternate",
        "details": "Alternative HTTP port often used for web administration or proxies.",
        "security": "MEDIUM RISK - Unencrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    82: {
        "description": "XFER Utility",
        "details": "File transfer utility. Implementation varies by system.",
        "security": "MEDIUM RISK - File transfer service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    83: {
        "description": "MIT ML Device",
        "details": "MIT Machine Learning device protocol. Research/academic use.",
        "security": "LOW RISK - Academic research protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    84: {
        "description": "Common Trace Facility",
        "details": "System tracing and debugging facility.",
        "security": "MEDIUM RISK - System debugging information",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    85: {
        "description": "MIT ML Device (continued)",
        "details": "MIT Machine Learning device protocol continuation.",
        "security": "LOW RISK - Academic research protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    90: {
        "description": "DNSIX Security Attribute Token Map",
        "details": "Defense Intelligence Agency security token mapping.",
        "security": "MEDIUM RISK - Security token service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    99: {
        "description": "WIP Message Protocol",
        "details": "Wireless Internet Protocol message service.",
        "security": "MEDIUM RISK - Wireless messaging service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    100: {
        "description": "NEWACCT Account Creation",
        "details": "Automated account creation service. Security risk if exposed.",
        "security": "HIGH RISK - Account creation service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    101: {
        "description": "NIC Host Name Server",
        "details": "Network Information Center hostname resolution service.",
        "security": "LOW RISK - Legacy naming service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    102: {
        "description": "ISO-TSAP Protocol",
        "details": "ISO Transport Service Access Point. Legacy networking protocol.",
        "security": "LOW RISK - Legacy ISO protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    106: {
        "description": "3COM-TSMUX",
        "details": "3COM terminal server multiplexer protocol.",
        "security": "MEDIUM RISK - Terminal server access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    109: {
        "description": "POP2 - Post Office Protocol v2",
        "details": "Legacy email retrieval protocol. Superseded by POP3.",
        "security": "HIGH RISK - Legacy, unencrypted email protocol",
        "link": "https://tools.ietf.org/html/rfc937"
    },
    125: {
        "description": "LOCUS-MAP - Network Mapping",
        "details": "LOCUS distributed system mapping protocol.",
        "security": "MEDIUM RISK - Network topology information",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    144: {
        "description": "NewS - Network News System",
        "details": "Network news distribution system.",
        "security": "MEDIUM RISK - News distribution service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    146: {
        "description": "ISO-IP0 - ISO Transport Protocol",
        "details": "ISO transport protocol over IP networks.",
        "security": "LOW RISK - Legacy ISO networking",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    152: {
        "description": "Background File Transfer Program",
        "details": "Background file transfer service for batch operations.",
        "security": "MEDIUM RISK - File transfer service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    153: {
        "description": "SGMP - Simple Gateway Monitoring Protocol",
        "details": "Legacy network monitoring protocol. Superseded by SNMP.",
        "security": "MEDIUM RISK - Network monitoring service",
        "link": "https://tools.ietf.org/html/rfc1028"
    },
    158: {
        "description": "DMSP - Distributed Mail System Protocol",
        "details": "Distributed mail system communication protocol.",
        "security": "MEDIUM RISK - Mail system service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    163: {
        "description": "CMIP-MAN - Network Management",
        "details": "Common Management Information Protocol management.",
        "security": "MEDIUM RISK - Network management service",
        "link": "https://en.wikipedia.org/wiki/Common_Management_Information_Protocol"
    },
    174: {
        "description": "MAILQ - Mail Queue",
        "details": "Mail queue management service.",
        "security": "MEDIUM RISK - Mail queue access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    177: {
        "description": "XDMCP - X Display Manager Control Protocol",
        "details": "X Window System display manager protocol.",
        "security": "HIGH RISK - Remote X11 access, often unencrypted",
        "link": "https://en.wikipedia.org/wiki/X_Display_Manager_Control_Protocol"
    },
    199: {
        "description": "SMUX - SNMP Multiplexer",
        "details": "SNMP protocol multiplexer for network management.",
        "security": "MEDIUM RISK - Network management multiplexer",
        "link": "https://tools.ietf.org/html/rfc1227"
    },
    
    # Additional registered ports (1024-5000 range)
    1024: {
        "description": "Reserved/Dynamic Port Range Start",
        "details": "Start of dynamic/registered port range. Often used by applications.",
        "security": "MEDIUM RISK - Application-specific usage",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1025: {
        "description": "Network Blackjack/Microsoft RPC",
        "details": "Network Blackjack game or Microsoft RPC services.",
        "security": "MEDIUM RISK - Application or RPC service",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    1026: {
        "description": "Calendar Access Protocol/Microsoft RPC",
        "details": "Calendar access protocol or Microsoft RPC endpoint.",
        "security": "MEDIUM RISK - Calendar or RPC service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    1027: {
        "description": "ICQ/Microsoft RPC",
        "details": "ICQ instant messaging or Microsoft RPC service.",
        "security": "MEDIUM RISK - Messaging or RPC service",
        "link": "https://en.wikipedia.org/wiki/ICQ"
    },
    1028: {
        "description": "Microsoft RPC",
        "details": "Microsoft Windows RPC endpoint mapper service.",
        "security": "MEDIUM RISK - Windows RPC service",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    1029: {
        "description": "Microsoft RPC",
        "details": "Microsoft Windows RPC service endpoint.",
        "security": "MEDIUM RISK - Windows RPC service",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    1030: {
        "description": "BBN IAD/Microsoft RPC",
        "details": "BBN Internet Access Device or Microsoft RPC service.",
        "security": "MEDIUM RISK - Network device or RPC service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    1050: {
        "description": "CORBA/Java RMI",
        "details": "Common Object Request Broker Architecture or Java RMI service.",
        "security": "MEDIUM RISK - Distributed object service",
        "link": "https://en.wikipedia.org/wiki/Common_Object_Request_Broker_Architecture"
    },
    1099: {
        "description": "Java RMI Registry",
        "details": "Java Remote Method Invocation registry service.",
        "security": "HIGH RISK - Java application access",
        "link": "https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/"
    },
    1100: {
        "description": "MCTP",
        "details": "Management Component Transport Protocol.",
        "security": "MEDIUM RISK - Management protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    1194: {
        "description": "OpenVPN",
        "details": "OpenVPN secure tunnel/VPN service.",
        "security": "SECURE - VPN service",
        "link": "https://openvpn.net/"
    },
    1234: {
        "description": "Ultimedia Services/VLC",
        "details": "Ultimedia Services or VLC media player streaming.",
        "security": "MEDIUM RISK - Media streaming service",
        "link": "https://www.videolan.org/vlc/"
    },
    1337: {
        "description": "WASTE/Gaming",
        "details": "WASTE encrypted P2P protocol or gaming services.",
        "security": "MEDIUM RISK - P2P or gaming service",
        "link": "https://en.wikipedia.org/wiki/WASTE"
    },
    1414: {
        "description": "IBM MQSeries",
        "details": "IBM MQ message queuing middleware.",
        "security": "MEDIUM RISK - Message queuing service",
        "link": "https://www.ibm.com/products/mq"
    },
    1494: {
        "description": "Citrix ICA",
        "details": "Citrix Independent Computing Architecture remote desktop.",
        "security": "MEDIUM RISK - Remote desktop service",
        "link": "https://www.citrix.com/"
    },
    1512: {
        "description": "WINS",
        "details": "Windows Internet Name Service for NetBIOS name resolution.",
        "security": "MEDIUM RISK - Windows networking service",
        "link": "https://en.wikipedia.org/wiki/Windows_Internet_Name_Service"
    },
    1533: {
        "description": "Sametime",
        "details": "IBM Lotus Sametime instant messaging and collaboration.",
        "security": "MEDIUM RISK - Collaboration service",
        "link": "https://en.wikipedia.org/wiki/IBM_Sametime"
    },
    1556: {
        "description": "VerifyTrust",
        "details": "VerifyTrust certificate validation service.",
        "security": "MEDIUM RISK - Certificate service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    1588: {
        "description": "PTP - Precision Time Protocol",
        "details": "IEEE 1588 Precision Time Protocol for clock synchronization.",
        "security": "LOW RISK - Time synchronization",
        "link": "https://en.wikipedia.org/wiki/Precision_Time_Protocol"
    },
    1604: {
        "description": "Citrix Session Sharing",
        "details": "Citrix session sharing service.",
        "security": "MEDIUM RISK - Remote access service",
        "link": "https://www.citrix.com/"
    },
    1645: {
        "description": "RADIUS Authentication",
        "details": "Remote Authentication Dial-In User Service authentication.",
        "security": "MEDIUM RISK - Authentication service",
        "link": "https://tools.ietf.org/html/rfc2865"
    },
    1646: {
        "description": "RADIUS Accounting",
        "details": "Remote Authentication Dial-In User Service accounting.",
        "security": "MEDIUM RISK - Accounting service",
        "link": "https://tools.ietf.org/html/rfc2866"
    },
    1701: {
        "description": "L2TP - Layer 2 Tunneling Protocol",
        "details": "VPN tunneling protocol often used with IPSec.",
        "security": "SECURE - VPN tunneling protocol",
        "link": "https://tools.ietf.org/html/rfc2661"
    },
    1720: {
        "description": "H.323 Call Signaling",
        "details": "H.323 multimedia communication call signaling.",
        "security": "MEDIUM RISK - VoIP signaling",
        "link": "https://en.wikipedia.org/wiki/H.323"
    },
    1812: {
        "description": "RADIUS Authentication (Official)",
        "details": "Official RADIUS authentication port (moved from 1645).",
        "security": "MEDIUM RISK - Authentication service",
        "link": "https://tools.ietf.org/html/rfc2865"
    },
    1813: {
        "description": "RADIUS Accounting (Official)",
        "details": "Official RADIUS accounting port (moved from 1646).",
        "security": "MEDIUM RISK - Accounting service",
        "link": "https://tools.ietf.org/html/rfc2866"
    },
    1935: {
        "description": "RTMP - Real Time Messaging Protocol",
        "details": "Adobe Flash video streaming protocol.",
        "security": "MEDIUM RISK - Video streaming service",
        "link": "https://en.wikipedia.org/wiki/Real-Time_Messaging_Protocol"
    },
    1998: {
        "description": "Cisco X.25 over TCP",
        "details": "Cisco X.25 protocol over TCP/IP.",
        "security": "MEDIUM RISK - Cisco networking protocol",
        "link": "https://en.wikipedia.org/wiki/X.25"
    },
    2000: {
        "description": "Cisco SCCP",
        "details": "Cisco Skinny Client Control Protocol for IP phones.",
        "security": "MEDIUM RISK - VoIP control protocol",
        "link": "https://en.wikipedia.org/wiki/Skinny_Client_Control_Protocol"
    },
    2002: {
        "description": "Globe/6to4 Tunnel",
        "details": "Globe protocol or 6to4 IPv6 transition tunnel.",
        "security": "MEDIUM RISK - Tunneling service",
        "link": "https://tools.ietf.org/html/rfc3056"
    },
    2121: {
        "description": "CCProxy FTP",
        "details": "CCProxy FTP proxy service.",
        "security": "MEDIUM RISK - FTP proxy service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    2181: {
        "description": "Apache ZooKeeper",
        "details": "Apache ZooKeeper distributed coordination service.",
        "security": "MEDIUM RISK - Distributed coordination service",
        "link": "https://zookeeper.apache.org/"
    },
    2222: {
        "description": "SSH Alternate/EtherNet/IP",
        "details": "Alternative SSH port or EtherNet/IP industrial protocol.",
        "security": "SECURE - Alternative SSH or industrial protocol",
        "link": "https://www.openssh.com/"
    },
    2301: {
        "description": "Compaq HTTP",
        "details": "Compaq HTTP management interface.",
        "security": "MEDIUM RISK - Management interface",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    2323: {
        "description": "3D nwn2/Telnet Alternate",
        "details": "3D Neverwinter Nights 2 or alternative Telnet service.",
        "security": "MEDIUM RISK - Gaming or remote access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    2381: {
        "description": "HP Openview HTTPs",
        "details": "HP OpenView network management HTTPS interface.",
        "security": "MEDIUM RISK - Network management",
        "link": "https://en.wikipedia.org/wiki/HP_OpenView"
    },
    2382: {
        "description": "HP Openview HTTP",
        "details": "HP OpenView network management HTTP interface.",
        "security": "MEDIUM RISK - Network management",
        "link": "https://en.wikipedia.org/wiki/HP_OpenView"
    },
    2483: {
        "description": "Oracle database listener",
        "details": "Oracle database listener alternate port.",
        "security": "HIGH RISK - Database service",
        "link": "https://docs.oracle.com/en/database/"
    },
    2484: {
        "description": "Oracle database listener SSL",
        "details": "Oracle database listener with SSL encryption.",
        "security": "MEDIUM RISK - Encrypted database service",
        "link": "https://docs.oracle.com/en/database/"
    },
    2967: {
        "description": "Symantec AntiVirus",
        "details": "Symantec AntiVirus management and updates.",
        "security": "LOW RISK - Antivirus management",
        "link": "https://www.broadcom.com/products/cyber-security"
    },
    2968: {
        "description": "Enpp",
        "details": "Encrypted Network Packet Protocol.",
        "security": "MEDIUM RISK - Encrypted network protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    2998: {
        "description": "Real Secure",
        "details": "ISS Real Secure intrusion detection system.",
        "security": "MEDIUM RISK - Security monitoring",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    3002: {
        "description": "EXLM Agent",
        "details": "EXLM (unknown) agent service.",
        "security": "MEDIUM RISK - Agent service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    3128: {
        "description": "Squid HTTP Proxy",
        "details": "Squid web proxy cache server.",
        "security": "MEDIUM RISK - Web proxy service",
        "link": "http://www.squid-cache.org/"
    },
    3268: {
        "description": "Microsoft Global Catalog LDAP",
        "details": "Microsoft Active Directory Global Catalog LDAP.",
        "security": "MEDIUM RISK - Directory service",
        "link": "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/"
    },
    3269: {
        "description": "Microsoft Global Catalog LDAP SSL",
        "details": "Microsoft Active Directory Global Catalog LDAP over SSL.",
        "security": "SECURE - Encrypted directory service",
        "link": "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/"
    },
    3283: {
        "description": "Net Assistant",
        "details": "Apple Net Assistant remote desktop service.",
        "security": "MEDIUM RISK - Remote desktop service",
        "link": "https://support.apple.com/"
    },
    3299: {
        "description": "SAP Router",
        "details": "SAP Router network proxy service.",
        "security": "MEDIUM RISK - SAP networking service",
        "link": "https://help.sap.com/"
    },
    3333: {
        "description": "DEC Notes",
        "details": "DEC Notes collaboration software.",
        "security": "MEDIUM RISK - Collaboration service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    3690: {
        "description": "Subversion (SVN)",
        "details": "Apache Subversion version control system.",
        "security": "MEDIUM RISK - Version control service",
        "link": "https://subversion.apache.org/"
    },
    3780: {
        "description": "Videotex",
        "details": "Videotex information service protocol.",
        "security": "LOW RISK - Information service",
        "link": "https://en.wikipedia.org/wiki/Videotex"
    },
    3790: {
        "description": "XMLRPC",
        "details": "XML-RPC remote procedure call protocol.",
        "security": "MEDIUM RISK - RPC service",
        "link": "http://xmlrpc.scripting.com/"
    },
    
    # Additional high-value ports and modern services
    4001: {
        "description": "NewOak",
        "details": "NewOak communication protocol or application service.",
        "security": "MEDIUM RISK - Application service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    4045: {
        "description": "NFS Lock Manager",
        "details": "Network File System lock manager service.",
        "security": "MEDIUM RISK - File system locking",
        "link": "https://tools.ietf.org/html/rfc1813"
    },
    4125: {
        "description": "Microsoft Remote Web Workplace",
        "details": "Microsoft Small Business Server remote web workplace.",
        "security": "MEDIUM RISK - Remote access service",
        "link": "https://docs.microsoft.com/en-us/windows-server/"
    },
    4224: {
        "description": "Cisco Audio Session Tunneling",
        "details": "Cisco audio session tunneling for VoIP.",
        "security": "MEDIUM RISK - VoIP tunneling",
        "link": "https://www.cisco.com/"
    },
    4321: {
        "description": "Remote Who Is",
        "details": "Remote Who Is service for user information.",
        "security": "MEDIUM RISK - User information service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    4444: {
        "description": "Krb524/Oracle WebLogic",
        "details": "Kerberos 524 service or Oracle WebLogic server.",
        "security": "MEDIUM RISK - Authentication or application server",
        "link": "https://web.mit.edu/kerberos/"
    },
    4445: {
        "description": "UPNOTIFYP",
        "details": "UPNOTIFYP notification service.",
        "security": "MEDIUM RISK - Notification service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    4567: {
        "description": "TRAM",
        "details": "TRAM (Trivial Reliable Announcement Multicast) protocol.",
        "security": "MEDIUM RISK - Multicast protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    4711: {
        "description": "eMule",
        "details": "eMule peer-to-peer file sharing client.",
        "security": "MEDIUM RISK - P2P file sharing",
        "link": "https://www.emule-project.net/"
    },
    4728: {
        "description": "Computer Associates Desktop DNA",
        "details": "CA Desktop DNA management service.",
        "security": "MEDIUM RISK - System management",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    4899: {
        "description": "Radmin",
        "details": "Radmin remote administration tool.",
        "security": "HIGH RISK - Remote administration access",
        "link": "https://www.radmin.com/"
    },
    5001: {
        "description": "Sockets de Troie/IPerf",
        "details": "Sockets de Troie trojan or iPerf network testing tool.",
        "security": "HIGH RISK - Potential trojan or network testing",
        "link": "https://iperf.fr/"
    },
    5051: {
        "description": "ITA Agent",
        "details": "ITA (Intel Technology Access) agent service.",
        "security": "MEDIUM RISK - Management agent",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    5060: {
        "description": "SIP - Session Initiation Protocol",
        "details": "VoIP signaling protocol for voice/video calls.",
        "security": "MEDIUM RISK - VoIP signaling",
        "link": "https://tools.ietf.org/html/rfc3261"
    },
    5061: {
        "description": "SIP-TLS - SIP over TLS",
        "details": "Secure SIP signaling over TLS encryption.",
        "security": "SECURE - Encrypted VoIP signaling",
        "link": "https://tools.ietf.org/html/rfc3261"
    },
    5101: {
        "description": "Yahoo! Messenger",
        "details": "Yahoo! Messenger instant messaging service.",
        "security": "MEDIUM RISK - Instant messaging",
        "link": "https://en.wikipedia.org/wiki/Yahoo!_Messenger"
    },
    5190: {
        "description": "AOL Instant Messenger",
        "details": "AOL Instant Messenger (AIM) service.",
        "security": "MEDIUM RISK - Instant messaging",
        "link": "https://en.wikipedia.org/wiki/AIM_(software)"
    },
    5222: {
        "description": "XMPP/Jabber Client",
        "details": "Extensible Messaging and Presence Protocol client connections.",
        "security": "MEDIUM RISK - Instant messaging protocol",
        "link": "https://xmpp.org/"
    },
    5223: {
        "description": "XMPP/Jabber Client SSL",
        "details": "XMPP client connections over SSL encryption.",
        "security": "SECURE - Encrypted messaging",
        "link": "https://xmpp.org/"
    },
    5269: {
        "description": "XMPP/Jabber Server",
        "details": "XMPP server-to-server connections.",
        "security": "MEDIUM RISK - Messaging server communication",
        "link": "https://xmpp.org/"
    },
    5353: {
        "description": "mDNS - Multicast DNS",
        "details": "Multicast DNS service discovery (Apple Bonjour, Avahi).",
        "security": "LOW RISK - Local service discovery",
        "link": "https://tools.ietf.org/html/rfc6762"
    },
    5555: {
        "description": "Android Debug Bridge/SAP",
        "details": "Android ADB or SAP management service.",
        "security": "HIGH RISK - Debug access or SAP management",
        "link": "https://developer.android.com/studio/command-line/adb"
    },
    5631: {
        "description": "PC-Anywhere Data",
        "details": "Symantec PC-Anywhere remote control data channel.",
        "security": "HIGH RISK - Remote control software",
        "link": "https://en.wikipedia.org/wiki/Symantec_pcAnywhere"
    },
    5632: {
        "description": "PC-Anywhere Status",
        "details": "Symantec PC-Anywhere remote control status channel.",
        "security": "HIGH RISK - Remote control software",
        "link": "https://en.wikipedia.org/wiki/Symantec_pcAnywhere"
    },
    5666: {
        "description": "NRPE - Nagios Remote Plugin Executor",
        "details": "Nagios monitoring system remote plugin executor.",
        "security": "MEDIUM RISK - Monitoring service",
        "link": "https://www.nagios.org/"
    },
    5672: {
        "description": "AMQP - Advanced Message Queuing Protocol",
        "details": "RabbitMQ and other message queuing systems.",
        "security": "MEDIUM RISK - Message queuing service",
        "link": "https://www.amqp.org/"
    },
    5984: {
        "description": "CouchDB",
        "details": "Apache CouchDB NoSQL database HTTP interface.",
        "security": "MEDIUM RISK - NoSQL database",
        "link": "https://couchdb.apache.org/"
    },
    5985: {
        "description": "WinRM HTTP",
        "details": "Windows Remote Management over HTTP.",
        "security": "MEDIUM RISK - Windows remote management",
        "link": "https://docs.microsoft.com/en-us/windows/win32/winrm/"
    },
    5986: {
        "description": "WinRM HTTPS",
        "details": "Windows Remote Management over HTTPS.",
        "security": "SECURE - Encrypted Windows remote management",
        "link": "https://docs.microsoft.com/en-us/windows/win32/winrm/"
    },
    6000: {
        "description": "X11 - X Window System",
        "details": "X Window System remote display protocol.",
        "security": "HIGH RISK - Remote GUI access, often unencrypted",
        "link": "https://www.x.org/"
    },
    6001: {
        "description": "X11 Display 1",
        "details": "X Window System display 1 (additional display).",
        "security": "HIGH RISK - Remote GUI access",
        "link": "https://www.x.org/"
    },
    6667: {
        "description": "IRC - Internet Relay Chat",
        "details": "Internet Relay Chat server communication.",
        "security": "MEDIUM RISK - Chat service",
        "link": "https://tools.ietf.org/html/rfc1459"
    },
    6881: {
        "description": "BitTorrent",
        "details": "BitTorrent peer-to-peer file sharing protocol.",
        "security": "MEDIUM RISK - P2P file sharing",
        "link": "https://www.bittorrent.org/"
    },
    6969: {
        "description": "BitTorrent Tracker",
        "details": "BitTorrent tracker service for peer discovery.",
        "security": "MEDIUM RISK - P2P tracker service",
        "link": "https://www.bittorrent.org/"
    },
    7001: {
        "description": "Cassandra/AFS3",
        "details": "Apache Cassandra database or AFS3 file system.",
        "security": "MEDIUM RISK - Database or file system",
        "link": "https://cassandra.apache.org/"
    },
    7199: {
        "description": "Cassandra JMX",
        "details": "Apache Cassandra JMX monitoring interface.",
        "security": "MEDIUM RISK - Database monitoring",
        "link": "https://cassandra.apache.org/"
    },
    7777: {
        "description": "cbt/Oracle",
        "details": "Computer Based Training or Oracle services.",
        "security": "MEDIUM RISK - Training or database service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    8086: {
        "description": "InfluxDB",
        "details": "InfluxDB time series database HTTP interface.",
        "security": "MEDIUM RISK - Time series database",
        "link": "https://www.influxdata.com/"
    },
    8181: {
        "description": "HTTP Alternate/GeoServer",
        "details": "Alternative HTTP port or GeoServer map service.",
        "security": "MEDIUM RISK - Web service or mapping",
        "link": "http://geoserver.org/"
    },
    8333: {
        "description": "Bitcoin",
        "details": "Bitcoin cryptocurrency network protocol.",
        "security": "MEDIUM RISK - Cryptocurrency service",
        "link": "https://bitcoin.org/"
    },
    8500: {
        "description": "HashiCorp Consul",
        "details": "Consul service discovery and configuration.",
        "security": "MEDIUM RISK - Service discovery",
        "link": "https://www.consul.io/"
    },
    8600: {
        "description": "HashiCorp Consul DNS",
        "details": "Consul DNS interface for service discovery.",
        "security": "LOW RISK - DNS interface",
        "link": "https://www.consul.io/"
    },
    8888: {
        "description": "Jupyter Notebook/HTTP Alternate",
        "details": "Jupyter Notebook server or alternative HTTP service.",
        "security": "MEDIUM RISK - Development environment",
        "link": "https://jupyter.org/"
    },
    9091: {
        "description": "Transmission/XMLRPC",
        "details": "Transmission BitTorrent client or XML-RPC service.",
        "security": "MEDIUM RISK - BitTorrent client or RPC",
        "link": "https://transmissionbt.com/"
    },
    9092: {
        "description": "Apache Kafka",
        "details": "Apache Kafka distributed streaming platform.",
        "security": "MEDIUM RISK - Streaming platform",
        "link": "https://kafka.apache.org/"
    },
    9418: {
        "description": "Git Protocol",
        "details": "Git version control system network protocol.",
        "security": "MEDIUM RISK - Version control",
        "link": "https://git-scm.com/"
    },
    10000: {
        "description": "Webmin",
        "details": "Webmin web-based system administration tool.",
        "security": "HIGH RISK - System administration interface",
        "link": "http://www.webmin.com/"
    },
    11211: {
        "description": "Memcached",
        "details": "Memcached distributed memory caching system.",
        "security": "HIGH RISK - Often exposed without authentication",
        "link": "https://memcached.org/"
    },
    25565: {
        "description": "Minecraft",
        "details": "Minecraft game server default port.",
        "security": "MEDIUM RISK - Gaming service",
        "link": "https://www.minecraft.net/"
    },
    27015: {
        "description": "Half-Life/Steam",
        "details": "Half-Life game server or Steam gaming platform.",
        "security": "MEDIUM RISK - Gaming service",
        "link": "https://store.steampowered.com/"
    },
    50070: {
        "description": "Hadoop NameNode",
        "details": "Apache Hadoop NameNode web interface.",
        "security": "MEDIUM RISK - Big data management",
        "link": "https://hadoop.apache.org/"
    },
    
    # Additional 100 ports - Specialized services, IoT, Enterprise, and Emerging Tech
    71: {
        "description": "NETRJS Protocol",
        "details": "Network Remote Job Service. Legacy mainframe job submission.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    72: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    73: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    74: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    87: {
        "description": "Terminal Link",
        "details": "Legacy terminal linking protocol. Rarely used today.",
        "security": "LOW RISK - Legacy terminal service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    89: {
        "description": "SU-MIT Telnet Gateway",
        "details": "Stanford University MIT Telnet gateway service.",
        "security": "MEDIUM RISK - Telnet gateway service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    95: {
        "description": "SUPDUP Protocol",
        "details": "Stanford University Display Protocol for remote terminals.",
        "security": "MEDIUM RISK - Remote terminal protocol",
        "link": "https://en.wikipedia.org/wiki/SUPDUP"
    },
    98: {
        "description": "Linuxconf",
        "details": "Linux system configuration tool web interface.",
        "security": "HIGH RISK - System configuration access",
        "link": "https://en.wikipedia.org/wiki/Linuxconf"
    },
    103: {
        "description": "Genesis Point-to-Point Trans Net",
        "details": "Legacy networking protocol for point-to-point communication.",
        "security": "LOW RISK - Legacy networking protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    104: {
        "description": "ACR-NEMA Digital Imaging",
        "details": "Medical imaging communication protocol (predecessor to DICOM).",
        "security": "MEDIUM RISK - Medical data transmission",
        "link": "https://en.wikipedia.org/wiki/DICOM"
    },
    105: {
        "description": "CCSO Nameserver (CSNet)",
        "details": "Computer Science Network nameserver protocol.",
        "security": "LOW RISK - Legacy nameserver",
        "link": "https://en.wikipedia.org/wiki/CSNET"
    },
    107: {
        "description": "Remote Telnet Service",
        "details": "Remote telnet service with additional features.",
        "security": "HIGH RISK - Remote terminal access",
        "link": "https://en.wikipedia.org/wiki/Telnet"
    },
    108: {
        "description": "SNA Gateway Access Server",
        "details": "IBM Systems Network Architecture gateway service.",
        "security": "MEDIUM RISK - Legacy IBM networking",
        "link": "https://en.wikipedia.org/wiki/Systems_Network_Architecture"
    },
    112: {
        "description": "McIDAS Data Transmission Protocol",
        "details": "Meteorological data transmission for weather systems.",
        "security": "LOW RISK - Weather data service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    117: {
        "description": "UUCP Path Service",
        "details": "Unix-to-Unix Copy Protocol path information service.",
        "security": "LOW RISK - Legacy Unix networking",
        "link": "https://en.wikipedia.org/wiki/UUCP"
    },
    118: {
        "description": "SQL Services",
        "details": "Structured Query Language database services.",
        "security": "HIGH RISK - Database access",
        "link": "https://en.wikipedia.org/wiki/SQL"
    },
    120: {
        "description": "CFDPTKT - Configuration File Transfer",
        "details": "Configuration file transfer protocol.",
        "security": "MEDIUM RISK - Configuration transfer",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    121: {
        "description": "ERPC - Encore RPC",
        "details": "Encore Computer Corporation Remote Procedure Call.",
        "security": "MEDIUM RISK - Legacy RPC service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    129: {
        "description": "PWDGEN Password Generator",
        "details": "Password generation service. Security risk if exposed.",
        "security": "HIGH RISK - Password generation service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    145: {
        "description": "UAAC Protocol",
        "details": "Unix-to-Unix Copy Protocol with authentication.",
        "security": "MEDIUM RISK - File transfer with authentication",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    150: {
        "description": "NetBIOS Session Service (continued)",
        "details": "Extended NetBIOS session service functionality.",
        "security": "HIGH RISK - Legacy Windows networking",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    156: {
        "description": "SQL Service",
        "details": "Database SQL service access.",
        "security": "HIGH RISK - Database service access",
        "link": "https://en.wikipedia.org/wiki/SQL"
    },
    164: {
        "description": "CMIP-AGENT",
        "details": "Common Management Information Protocol agent.",
        "security": "MEDIUM RISK - Management agent service",
        "link": "https://en.wikipedia.org/wiki/Common_Management_Information_Protocol"
    },
    178: {
        "description": "NextStep Window Server",
        "details": "NextStep operating system window server.",
        "security": "MEDIUM RISK - GUI access service",
        "link": "https://en.wikipedia.org/wiki/NeXTSTEP"
    },
    191: {
        "description": "Prospero Directory Service",
        "details": "Distributed directory service protocol.",
        "security": "MEDIUM RISK - Directory service access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    201: {
        "description": "AppleTalk Routing Maintenance",
        "details": "Apple networking protocol routing maintenance.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    202: {
        "description": "AppleTalk Name Binding",
        "details": "Apple networking protocol name binding service.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    204: {
        "description": "AppleTalk Echo",
        "details": "Apple networking protocol echo service.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    206: {
        "description": "AppleTalk Zone Information",
        "details": "Apple networking protocol zone information service.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    209: {
        "description": "Quick Mail Transfer Protocol",
        "details": "Alternative mail transfer protocol.",
        "security": "MEDIUM RISK - Mail transfer service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    210: {
        "description": "ANSI Z39.50",
        "details": "Information retrieval protocol for bibliographic databases.",
        "security": "LOW RISK - Database query protocol",
        "link": "https://en.wikipedia.org/wiki/Z39.50"
    },
    213: {
        "description": "IPX - Internetwork Packet Exchange",
        "details": "Novell NetWare networking protocol.",
        "security": "MEDIUM RISK - Legacy Novell networking",
        "link": "https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange"
    },
    220: {
        "description": "IMAP3 - Internet Message Access Protocol v3",
        "details": "Legacy version of IMAP email protocol.",
        "security": "MEDIUM RISK - Legacy email protocol",
        "link": "https://tools.ietf.org/html/rfc1203"
    },
    245: {
        "description": "LINK - Link Protocol",
        "details": "Network link establishment protocol.",
        "security": "MEDIUM RISK - Network link service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    347: {
        "description": "Fatmen Server",
        "details": "File and Tape Management system server.",
        "security": "MEDIUM RISK - File management service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    363: {
        "description": "RSVP Tunnel",
        "details": "Resource Reservation Protocol tunnel service.",
        "security": "MEDIUM RISK - Quality of Service protocol",
        "link": "https://tools.ietf.org/html/rfc2205"
    },
    401: {
        "description": "UPS Uninterruptible Power Supply",
        "details": "Network UPS monitoring and management protocol.",
        "security": "MEDIUM RISK - Infrastructure monitoring",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    444: {
        "description": "SNPP - Simple Network Paging Protocol",
        "details": "Protocol for sending pager messages over networks.",
        "security": "MEDIUM RISK - Paging service",
        "link": "https://tools.ietf.org/html/rfc1861"
    },
    524: {
        "description": "NCP - NetWare Core Protocol",
        "details": "Novell NetWare file and print sharing protocol.",
        "security": "MEDIUM RISK - Legacy Novell networking",
        "link": "https://en.wikipedia.org/wiki/NetWare_Core_Protocol"
    },
    543: {
        "description": "Klogin - Kerberized Login",
        "details": "Kerberos-authenticated remote login service.",
        "security": "SECURE - Kerberos-authenticated login",
        "link": "https://web.mit.edu/kerberos/"
    },
    544: {
        "description": "Kshell - Kerberized Shell",
        "details": "Kerberos-authenticated remote shell service.",
        "security": "SECURE - Kerberos-authenticated shell",
        "link": "https://web.mit.edu/kerberos/"
    },
    555: {
        "description": "DSF/Personal Agent",
        "details": "Data Security Framework or Personal Agent service.",
        "security": "MEDIUM RISK - Security or agent service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    563: {
        "description": "SNEWS - Secure Network News",
        "details": "Secure Network News Transfer Protocol over SSL/TLS.",
        "security": "SECURE - Encrypted news transfer",
        "link": "https://tools.ietf.org/html/rfc4642"
    },
    593: {
        "description": "HTTP RPC Ep Map",
        "details": "HTTP RPC endpoint mapper service.",
        "security": "MEDIUM RISK - RPC mapping service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    616: {
        "description": "SCO System Administration Server",
        "details": "SCO Unix system administration server.",
        "security": "HIGH RISK - System administration",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    617: {
        "description": "SCO Desktop Administration Server",
        "details": "SCO Unix desktop administration server.",
        "security": "HIGH RISK - Desktop administration",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    625: {
        "description": "ASIA",
        "details": "ASIA protocol service.",
        "security": "MEDIUM RISK - Protocol service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    646: {
        "description": "LDP - Label Distribution Protocol",
        "details": "MPLS Label Distribution Protocol.",
        "security": "MEDIUM RISK - MPLS networking",
        "link": "https://tools.ietf.org/html/rfc5036"
    },
    648: {
        "description": "RRP - Registry Registrar Protocol",
        "details": "Domain registry registrar protocol.",
        "security": "MEDIUM RISK - Domain registry service",
        "link": "https://tools.ietf.org/html/rfc3632"
    },
    666: {
        "description": "Doom/MDaemon",
        "details": "Doom game protocol or MDaemon email server.",
        "security": "MEDIUM RISK - Gaming or email service",
        "link": "https://en.wikipedia.org/wiki/Doom_(1993_video_game)"
    },
    667: {
        "description": "DisOrd",
        "details": "DisOrd protocol service.",
        "security": "MEDIUM RISK - Protocol service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    668: {
        "description": "MeComm",
        "details": "MeComm communication protocol.",
        "security": "MEDIUM RISK - Communication service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    683: {
        "description": "CORBA IIOP",
        "details": "CORBA Internet Inter-ORB Protocol.",
        "security": "MEDIUM RISK - Distributed object protocol",
        "link": "https://en.wikipedia.org/wiki/Common_Object_Request_Broker_Architecture"
    },
    687: {
        "description": "ASIPREGISTRY",
        "details": "AppleTalk Session Protocol registry.",
        "security": "LOW RISK - Apple protocol registry",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    691: {
        "description": "MS Exchange Routing",
        "details": "Microsoft Exchange Server routing service.",
        "security": "MEDIUM RISK - Email routing",
        "link": "https://docs.microsoft.com/en-us/exchange/"
    },
    700: {
        "description": "EPP - Extensible Provisioning Protocol",
        "details": "Domain name provisioning protocol.",
        "security": "MEDIUM RISK - Domain provisioning",
        "link": "https://tools.ietf.org/html/rfc5730"
    },
    705: {
        "description": "AgentX",
        "details": "SNMP AgentX protocol for subagents.",
        "security": "MEDIUM RISK - SNMP subagent protocol",
        "link": "https://tools.ietf.org/html/rfc2741"
    },
    711: {
        "description": "Cisco TDP",
        "details": "Cisco Tag Distribution Protocol.",
        "security": "MEDIUM RISK - Cisco networking protocol",
        "link": "https://www.cisco.com/"
    },
    714: {
        "description": "IRIS over XPC",
        "details": "Internet Registry Information Service over XPC.",
        "security": "MEDIUM RISK - Registry service",
        "link": "https://tools.ietf.org/html/rfc4992"
    },
    720: {
        "description": "SMQP",
        "details": "Simple Message Queue Protocol.",
        "security": "MEDIUM RISK - Message queuing",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    722: {
        "description": "Name Server",
        "details": "Name server protocol service.",
        "security": "MEDIUM RISK - Name resolution service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    726: {
        "description": "CALC",
        "details": "Calendar calculation service.",
        "security": "LOW RISK - Calendar service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    749: {
        "description": "Kerberos Administration",
        "details": "Kerberos administration protocol.",
        "security": "SECURE - Kerberos administration",
        "link": "https://web.mit.edu/kerberos/"
    },
    765: {
        "description": "Webster Network Dictionary",
        "details": "Network dictionary lookup service.",
        "security": "LOW RISK - Dictionary service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    777: {
        "description": "Multiling HTTP",
        "details": "Multiling HTTP service.",
        "security": "MEDIUM RISK - HTTP service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    783: {
        "description": "SPAMassassin",
        "details": "SpamAssassin spam filtering service.",
        "security": "LOW RISK - Spam filtering",
        "link": "https://spamassassin.apache.org/"
    },
    787: {
        "description": "QSC",
        "details": "Quick Service Control protocol.",
        "security": "MEDIUM RISK - Service control",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    800: {
        "description": "mdbs_daemon",
        "details": "MDBS daemon service.",
        "security": "MEDIUM RISK - Database daemon",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    801: {
        "description": "Device",
        "details": "Device control protocol.",
        "security": "MEDIUM RISK - Device control",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    808: {
        "description": "CCPROXY-HTTP",
        "details": "CCProxy HTTP proxy service.",
        "security": "MEDIUM RISK - HTTP proxy",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    843: {
        "description": "Adobe Flash Socket Policy",
        "details": "Adobe Flash cross-domain policy service.",
        "security": "MEDIUM RISK - Flash security policy",
        "link": "https://en.wikipedia.org/wiki/Adobe_Flash"
    },
    880: {
        "description": "Secure Web Server",
        "details": "Secure web server alternative port.",
        "security": "SECURE - Secure web server",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    888: {
        "description": "AccessBuilder",
        "details": "3Com AccessBuilder management.",
        "security": "MEDIUM RISK - Network device management",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    898: {
        "description": "sun-manageconsole",
        "details": "Sun Microsystems management console.",
        "security": "MEDIUM RISK - System management",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    900: {
        "description": "OMG Initial Refs",
        "details": "Object Management Group initial references.",
        "security": "MEDIUM RISK - Object management",
        "link": "https://www.omg.org/"
    },
    901: {
        "description": "SWAT - Samba Web Administration",
        "details": "Samba Web Administration Tool.",
        "security": "HIGH RISK - Samba administration",
        "link": "https://www.samba.org/"
    },
    903: {
        "description": "self documenting Telnet Door",
        "details": "Self-documenting Telnet door service.",
        "security": "MEDIUM RISK - Telnet door service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    911: {
        "description": "xact-backup",
        "details": "Transaction backup service.",
        "security": "MEDIUM RISK - Backup service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    981: {
        "description": "Remote HTTPS management",
        "details": "Remote HTTPS management interface.",
        "security": "MEDIUM RISK - Remote management",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    987: {
        "description": "Sony RTP-MIDI",
        "details": "Sony Real-Time Protocol MIDI.",
        "security": "LOW RISK - MIDI protocol",
        "link": "https://en.wikipedia.org/wiki/RTP-MIDI"
    },
    992: {
        "description": "Telnet over TLS/SSL",
        "details": "Secure Telnet over TLS/SSL encryption.",
        "security": "SECURE - Encrypted Telnet",
        "link": "https://tools.ietf.org/html/rfc2818"
    },
    
    # IoT, Industrial, and Specialized Enterprise Services (Final 27 ports)
    1883: {
        "description": "MQTT - Message Queuing Telemetry Transport",
        "details": "Lightweight messaging protocol for IoT devices.",
        "security": "MEDIUM RISK - IoT messaging protocol",
        "link": "https://mqtt.org/"
    },
    8883: {
        "description": "MQTT over SSL/TLS",
        "details": "Secure MQTT messaging with SSL/TLS encryption.",
        "security": "SECURE - Encrypted IoT messaging",
        "link": "https://mqtt.org/"
    },
    502: {
        "description": "Modbus TCP",
        "details": "Industrial automation protocol for SCADA systems.",
        "security": "HIGH RISK - Industrial control system",
        "link": "https://en.wikipedia.org/wiki/Modbus"
    },
    20000: {
        "description": "DNP3 - Distributed Network Protocol",
        "details": "Industrial control systems communication protocol.",
        "security": "HIGH RISK - Critical infrastructure protocol",
        "link": "https://en.wikipedia.org/wiki/DNP3"
    },
    44818: {
        "description": "EtherNet/IP",
        "details": "Industrial Ethernet protocol for automation.",
        "security": "HIGH RISK - Industrial automation",
        "link": "https://en.wikipedia.org/wiki/EtherNet/IP"
    },
    102: {
        "description": "S7comm - Siemens PLC Protocol",
        "details": "Siemens S7 PLC communication protocol.",
        "security": "HIGH RISK - Industrial PLC control",
        "link": "https://en.wikipedia.org/wiki/S7_communication"
    },
    4840: {
        "description": "OPC UA - OPC Unified Architecture",
        "details": "Industrial IoT and automation platform protocol.",
        "security": "MEDIUM RISK - Industrial IoT protocol",
        "link": "https://opcfoundation.org/"
    },
    1234: {
        "description": "VLC/Ultimedia Services",
        "details": "VLC media player streaming or Ultimedia services.",
        "security": "MEDIUM RISK - Media streaming",
        "link": "https://www.videolan.org/vlc/"
    },
    5353: {
        "description": "mDNS - Multicast DNS",
        "details": "Zero-configuration networking service discovery.",
        "security": "LOW RISK - Local service discovery",
        "link": "https://tools.ietf.org/html/rfc6762"
    },
    5355: {
        "description": "LLMNR - Link-Local Multicast Name Resolution",
        "details": "Windows link-local name resolution protocol.",
        "security": "MEDIUM RISK - Windows networking",
        "link": "https://tools.ietf.org/html/rfc4795"
    },
    1900: {
        "description": "UPnP - Universal Plug and Play",
        "details": "Automatic device discovery and configuration.",
        "security": "HIGH RISK - Can expose internal services",
        "link": "https://en.wikipedia.org/wiki/Universal_Plug_and_Play"
    },
    7547: {
        "description": "CWMP - CPE WAN Management Protocol",
        "details": "TR-069 protocol for remote management of CPE devices.",
        "security": "HIGH RISK - Remote device management",
        "link": "https://en.wikipedia.org/wiki/TR-069"
    },
    8291: {
        "description": "MikroTik WinBox",
        "details": "MikroTik RouterOS management interface.",
        "security": "HIGH RISK - Router management",
        "link": "https://mikrotik.com/"
    },
    8728: {
        "description": "MikroTik API",
        "details": "MikroTik RouterOS API service.",
        "security": "HIGH RISK - Router API access",
        "link": "https://mikrotik.com/"
    },
    8729: {
        "description": "MikroTik API SSL",
        "details": "MikroTik RouterOS API over SSL.",
        "security": "MEDIUM RISK - Encrypted router API",
        "link": "https://mikrotik.com/"
    },
    161: {
        "description": "SNMP - Simple Network Management Protocol",
        "details": "Network device monitoring and management.",
        "security": "HIGH RISK - Often misconfigured, use SNMPv3",
        "link": "https://www.paessler.com/snmp"
    },
    162: {
        "description": "SNMP Trap",
        "details": "SNMP trap receiver for network device notifications.",
        "security": "MEDIUM RISK - Network monitoring notifications",
        "link": "https://www.paessler.com/snmp"
    },
    5044: {
        "description": "Lumberjack/Beats Protocol",
        "details": "Elastic Beats log shipping protocol.",
        "security": "MEDIUM RISK - Log aggregation service",
        "link": "https://www.elastic.co/beats/"
    },
    9200: {
        "description": "Elasticsearch REST API",
        "details": "Elasticsearch search engine REST API.",
        "security": "HIGH RISK - Search engine, often misconfigured",
        "link": "https://www.elastic.co/elasticsearch/"
    },
    9300: {
        "description": "Elasticsearch Transport Protocol",
        "details": "Elasticsearch inter-node communication.",
        "security": "HIGH RISK - Cluster communication",
        "link": "https://www.elastic.co/elasticsearch/"
    },
    5601: {
        "description": "Kibana",
        "details": "Kibana data visualization dashboard.",
        "security": "MEDIUM RISK - Data visualization interface",
        "link": "https://www.elastic.co/kibana/"
    },
    9600: {
        "description": "Logstash",
        "details": "Logstash data processing pipeline.",
        "security": "MEDIUM RISK - Data processing service",
        "link": "https://www.elastic.co/logstash/"
    },
    32400: {
        "description": "Plex Media Server",
        "details": "Plex media streaming server.",
        "security": "MEDIUM RISK - Media streaming service",
        "link": "https://www.plex.tv/"
    },
    32469: {
        "description": "Plex DLNA Server",
        "details": "Plex DLNA media sharing service.",
        "security": "MEDIUM RISK - Media sharing protocol",
        "link": "https://www.plex.tv/"
    },
    8096: {
        "description": "Jellyfin Media Server",
        "details": "Jellyfin open-source media streaming server.",
        "security": "MEDIUM RISK - Media streaming service",
        "link": "https://jellyfin.org/"
    },
    8920: {
        "description": "Jellyfin HTTPS",
        "details": "Jellyfin media server HTTPS interface.",
        "security": "SECURE - Encrypted media streaming",
        "link": "https://jellyfin.org/"
    },
    4001: {
        "description": "NewOak/Docker Swarm",
        "details": "NewOak service or Docker Swarm management.",
        "security": "MEDIUM RISK - Service management",
        "link": "https://docs.docker.com/engine/swarm/"
    },
    
    # Cloud Services & Container Orchestration (20 ports)
    2375: {
        "description": "Docker Daemon API (insecure)",
        "details": "Docker daemon REST API without TLS encryption.",
        "security": "HIGH RISK - Unencrypted Docker API",
        "link": "https://docs.docker.com/engine/api/"
    },
    2376: {
        "description": "Docker Daemon API (secure)",
        "details": "Docker daemon REST API with TLS encryption.",
        "security": "MEDIUM RISK - Encrypted Docker API",
        "link": "https://docs.docker.com/engine/api/"
    },
    2377: {
        "description": "Docker Swarm Cluster Management",
        "details": "Docker Swarm cluster management communication.",
        "security": "MEDIUM RISK - Swarm cluster communication",
        "link": "https://docs.docker.com/engine/swarm/"
    },
    6443: {
        "description": "Kubernetes API Server",
        "details": "Kubernetes cluster API server.",
        "security": "HIGH RISK - Kubernetes control plane",
        "link": "https://kubernetes.io/"
    },
    10250: {
        "description": "Kubelet API",
        "details": "Kubernetes kubelet API for node management.",
        "security": "HIGH RISK - Kubernetes node control",
        "link": "https://kubernetes.io/"
    },
    10256: {
        "description": "Kube-Proxy Health Check",
        "details": "Kubernetes kube-proxy health check endpoint.",
        "security": "LOW RISK - Health check service",
        "link": "https://kubernetes.io/"
    },
    8472: {
        "description": "VXLAN",
        "details": "Virtual Extensible LAN overlay networking.",
        "security": "MEDIUM RISK - Network overlay protocol",
        "link": "https://tools.ietf.org/html/rfc7348"
    },
    4789: {
        "description": "VXLAN (Official)",
        "details": "Official VXLAN port for overlay networks.",
        "security": "MEDIUM RISK - Network overlay protocol",
        "link": "https://tools.ietf.org/html/rfc7348"
    },
    2379: {
        "description": "etcd Client Communication",
        "details": "etcd distributed key-value store client API.",
        "security": "HIGH RISK - Distributed database",
        "link": "https://etcd.io/"
    },
    2380: {
        "description": "etcd Server Communication",
        "details": "etcd peer-to-peer communication.",
        "security": "HIGH RISK - Cluster coordination",
        "link": "https://etcd.io/"
    },
    8080: {
        "description": "HTTP Alternative/Tomcat",
        "details": "Alternative HTTP port, often used by Tomcat.",
        "security": "MEDIUM RISK - Web server alternative port",
        "link": "https://tomcat.apache.org/"
    },
    8008: {
        "description": "HTTP Alternative/Matrix",
        "details": "Alternative HTTP port or Matrix homeserver.",
        "security": "MEDIUM RISK - Web service alternative",
        "link": "https://matrix.org/"
    },
    9090: {
        "description": "Prometheus Metrics",
        "details": "Prometheus monitoring system metrics.",
        "security": "MEDIUM RISK - Monitoring metrics exposure",
        "link": "https://prometheus.io/"
    },
    9093: {
        "description": "Prometheus Alertmanager",
        "details": "Prometheus alert management service.",
        "security": "MEDIUM RISK - Alert management",
        "link": "https://prometheus.io/"
    },
    3000: {
        "description": "Grafana Dashboard",
        "details": "Grafana analytics and monitoring dashboard.",
        "security": "MEDIUM RISK - Monitoring dashboard",
        "link": "https://grafana.com/"
    },
    9091: {
        "description": "Prometheus Pushgateway",
        "details": "Prometheus metrics push gateway.",
        "security": "MEDIUM RISK - Metrics ingestion",
        "link": "https://prometheus.io/"
    },
    4317: {
        "description": "OpenTelemetry gRPC",
        "details": "OpenTelemetry Protocol (OTLP) over gRPC.",
        "security": "MEDIUM RISK - Telemetry data collection",
        "link": "https://opentelemetry.io/"
    },
    4318: {
        "description": "OpenTelemetry HTTP",
        "details": "OpenTelemetry Protocol (OTLP) over HTTP.",
        "security": "MEDIUM RISK - Telemetry data collection",
        "link": "https://opentelemetry.io/"
    },
    14268: {
        "description": "Jaeger Collector",
        "details": "Jaeger tracing collector service.",
        "security": "MEDIUM RISK - Distributed tracing",
        "link": "https://www.jaegertracing.io/"
    },
    16686: {
        "description": "Jaeger UI",
        "details": "Jaeger tracing user interface.",
        "security": "MEDIUM RISK - Tracing dashboard",
        "link": "https://www.jaegertracing.io/"
    },
    
    # Message Queuing & Streaming (15 ports)
    5672: {
        "description": "RabbitMQ AMQP",
        "details": "RabbitMQ message broker AMQP protocol.",
        "security": "MEDIUM RISK - Message broker",
        "link": "https://www.rabbitmq.com/"
    },
    15672: {
        "description": "RabbitMQ Management",
        "details": "RabbitMQ management web interface.",
        "security": "HIGH RISK - Message broker management",
        "link": "https://www.rabbitmq.com/"
    },
    25672: {
        "description": "RabbitMQ Clustering",
        "details": "RabbitMQ inter-node cluster communication.",
        "security": "MEDIUM RISK - Cluster communication",
        "link": "https://www.rabbitmq.com/"
    },
    9092: {
        "description": "Apache Kafka",
        "details": "Apache Kafka message streaming platform.",
        "security": "HIGH RISK - Message streaming platform",
        "link": "https://kafka.apache.org/"
    },
    2181: {
        "description": "Apache ZooKeeper",
        "details": "ZooKeeper coordination service for distributed systems.",
        "security": "HIGH RISK - Distributed coordination",
        "link": "https://zookeeper.apache.org/"
    },
    8083: {
        "description": "Kafka Connect REST",
        "details": "Kafka Connect REST API for data integration.",
        "security": "MEDIUM RISK - Data integration API",
        "link": "https://kafka.apache.org/"
    },
    9021: {
        "description": "Confluent Control Center",
        "details": "Confluent Platform monitoring and management.",
        "security": "MEDIUM RISK - Kafka management interface",
        "link": "https://www.confluent.io/"
    },
    8081: {
        "description": "Schema Registry",
        "details": "Confluent Schema Registry for Kafka schemas.",
        "security": "MEDIUM RISK - Schema management",
        "link": "https://www.confluent.io/"
    },
    1883: {
        "description": "MQTT (duplicate entry - will be updated)",
        "details": "Message Queuing Telemetry Transport for IoT.",
        "security": "MEDIUM RISK - IoT messaging",
        "link": "https://mqtt.org/"
    },
    4222: {
        "description": "NATS Messaging",
        "details": "NATS cloud-native messaging system.",
        "security": "MEDIUM RISK - Cloud messaging",
        "link": "https://nats.io/"
    },
    6222: {
        "description": "NATS Routing",
        "details": "NATS server-to-server routing protocol.",
        "security": "MEDIUM RISK - Message routing",
        "link": "https://nats.io/"
    },
    8222: {
        "description": "NATS Monitoring",
        "details": "NATS server monitoring interface.",
        "security": "MEDIUM RISK - Message server monitoring",
        "link": "https://nats.io/"
    },
    4150: {
        "description": "NSQ Message Queue",
        "details": "NSQ distributed messaging platform.",
        "security": "MEDIUM RISK - Distributed messaging",
        "link": "https://nsq.io/"
    },
    4151: {
        "description": "NSQ Lookup Daemon",
        "details": "NSQ topology information service.",
        "security": "MEDIUM RISK - Service discovery",
        "link": "https://nsq.io/"
    },
    4161: {
        "description": "NSQ Admin",
        "details": "NSQ administrative web interface.",
        "security": "MEDIUM RISK - Message queue administration",
        "link": "https://nsq.io/"
    },
    
    # Database Services (20 ports)
    5432: {
        "description": "PostgreSQL",
        "details": "PostgreSQL relational database server.",
        "security": "HIGH RISK - Database server",
        "link": "https://www.postgresql.org/"
    },
    3306: {
        "description": "MySQL/MariaDB",
        "details": "MySQL or MariaDB database server.",
        "security": "HIGH RISK - Database server",
        "link": "https://www.mysql.com/"
    },
    1521: {
        "description": "Oracle Database",
        "details": "Oracle Database listener service.",
        "security": "HIGH RISK - Enterprise database",
        "link": "https://www.oracle.com/"
    },
    1433: {
        "description": "Microsoft SQL Server",
        "details": "Microsoft SQL Server database engine.",
        "security": "HIGH RISK - Database server",
        "link": "https://www.microsoft.com/sql-server/"
    },
    50000: {
        "description": "IBM DB2",
        "details": "IBM DB2 database server.",
        "security": "HIGH RISK - Enterprise database",
        "link": "https://www.ibm.com/products/db2-database"
    },
    27017: {
        "description": "MongoDB",
        "details": "MongoDB NoSQL document database.",
        "security": "HIGH RISK - Document database",
        "link": "https://www.mongodb.com/"
    },
    27018: {
        "description": "MongoDB Shard Server",
        "details": "MongoDB shard server for horizontal scaling.",
        "security": "HIGH RISK - Database sharding",
        "link": "https://www.mongodb.com/"
    },
    27019: {
        "description": "MongoDB Config Server",
        "details": "MongoDB configuration server for sharded clusters.",
        "security": "HIGH RISK - Database configuration",
        "link": "https://www.mongodb.com/"
    },
    28017: {
        "description": "MongoDB Web Status",
        "details": "MongoDB web-based status interface (deprecated).",
        "security": "MEDIUM RISK - Database monitoring",
        "link": "https://www.mongodb.com/"
    },
    7000: {
        "description": "Cassandra Internode",
        "details": "Apache Cassandra inter-node communication.",
        "security": "HIGH RISK - NoSQL database cluster",
        "link": "https://cassandra.apache.org/"
    },
    7001: {
        "description": "Cassandra SSL Internode",
        "details": "Cassandra encrypted inter-node communication.",
        "security": "MEDIUM RISK - Encrypted database cluster",
        "link": "https://cassandra.apache.org/"
    },
    9042: {
        "description": "Cassandra CQL Native",
        "details": "Cassandra Query Language native protocol.",
        "security": "HIGH RISK - Database query interface",
        "link": "https://cassandra.apache.org/"
    },
    9160: {
        "description": "Cassandra Thrift",
        "details": "Cassandra Thrift RPC interface (deprecated).",
        "security": "HIGH RISK - Database RPC interface",
        "link": "https://cassandra.apache.org/"
    },
    8086: {
        "description": "InfluxDB HTTP",
        "details": "InfluxDB time-series database HTTP API.",
        "security": "MEDIUM RISK - Time-series database",
        "link": "https://www.influxdata.com/"
    },
    8088: {
        "description": "InfluxDB Backup/Restore",
        "details": "InfluxDB backup and restore service.",
        "security": "HIGH RISK - Database backup service",
        "link": "https://www.influxdata.com/"
    },
    7474: {
        "description": "Neo4j HTTP",
        "details": "Neo4j graph database HTTP interface.",
        "security": "MEDIUM RISK - Graph database",
        "link": "https://neo4j.com/"
    },
    7473: {
        "description": "Neo4j HTTPS",
        "details": "Neo4j graph database HTTPS interface.",
        "security": "SECURE - Encrypted graph database",
        "link": "https://neo4j.com/"
    },
    7687: {
        "description": "Neo4j Bolt",
        "details": "Neo4j Bolt binary protocol.",
        "security": "MEDIUM RISK - Graph database protocol",
        "link": "https://neo4j.com/"
    },
    9200: {
        "description": "Elasticsearch (duplicate - will be updated)",
        "details": "Elasticsearch search and analytics engine.",
        "security": "HIGH RISK - Search engine",
        "link": "https://www.elastic.co/"
    },
    6379: {
        "description": "Redis",
        "details": "Redis in-memory data structure store.",
        "security": "HIGH RISK - In-memory database, often no auth",
        "link": "https://redis.io/"
    },
    
    # Security & Authentication Services (15 ports)
    389: {
        "description": "LDAP",
        "details": "Lightweight Directory Access Protocol.",
        "security": "MEDIUM RISK - Directory service",
        "link": "https://ldap.com/"
    },
    636: {
        "description": "LDAPS",
        "details": "LDAP over SSL/TLS (secure LDAP).",
        "security": "SECURE - Encrypted directory service",
        "link": "https://ldap.com/"
    },
    88: {
        "description": "Kerberos",
        "details": "Kerberos authentication protocol.",
        "security": "SECURE - Authentication protocol",
        "link": "https://web.mit.edu/kerberos/"
    },
    464: {
        "description": "Kerberos Password Change",
        "details": "Kerberos password change service.",
        "security": "SECURE - Password management",
        "link": "https://web.mit.edu/kerberos/"
    },
    750: {
        "description": "Kerberos Admin",
        "details": "Kerberos administrative service.",
        "security": "HIGH RISK - Authentication administration",
        "link": "https://web.mit.edu/kerberos/"
    },
    1812: {
        "description": "RADIUS Authentication",
        "details": "Remote Authentication Dial-In User Service.",
        "security": "MEDIUM RISK - Network authentication",
        "link": "https://tools.ietf.org/html/rfc2865"
    },
    1813: {
        "description": "RADIUS Accounting",
        "details": "RADIUS accounting and auditing service.",
        "security": "MEDIUM RISK - Network accounting",
        "link": "https://tools.ietf.org/html/rfc2866"
    },
    1645: {
        "description": "RADIUS (Legacy)",
        "details": "Legacy RADIUS authentication port.",
        "security": "MEDIUM RISK - Legacy network authentication",
        "link": "https://tools.ietf.org/html/rfc2865"
    },
    1646: {
        "description": "RADIUS Accounting (Legacy)",
        "details": "Legacy RADIUS accounting port.",
        "security": "MEDIUM RISK - Legacy network accounting",
        "link": "https://tools.ietf.org/html/rfc2866"
    },
    1949: {
        "description": "TACACS+",
        "details": "Terminal Access Controller Access Control System Plus.",
        "security": "MEDIUM RISK - Network device authentication",
        "link": "https://tools.ietf.org/html/rfc8907"
    },
    8200: {
        "description": "HashiCorp Vault",
        "details": "HashiCorp Vault secrets management API.",
        "security": "HIGH RISK - Secrets management",
        "link": "https://www.vaultproject.io/"
    },
    8201: {
        "description": "HashiCorp Vault Agent",
        "details": "Vault agent for secret retrieval and caching.",
        "security": "MEDIUM RISK - Secrets agent",
        "link": "https://www.vaultproject.io/"
    },
    4646: {
        "description": "HashiCorp Nomad",
        "details": "HashiCorp Nomad job scheduler API.",
        "security": "HIGH RISK - Workload orchestration",
        "link": "https://www.nomadproject.io/"
    },
    8500: {
        "description": "HashiCorp Consul",
        "details": "HashiCorp Consul service discovery and configuration.",
        "security": "HIGH RISK - Service mesh control plane",
        "link": "https://www.consul.io/"
    },
    8600: {
        "description": "HashiCorp Consul DNS",
        "details": "Consul DNS interface for service discovery.",
        "security": "MEDIUM RISK - Service discovery DNS",
        "link": "https://www.consul.io/"
    },
    
    # Development & CI/CD Tools (20 ports)
    8090: {
        "description": "Atlassian Confluence",
        "details": "Confluence wiki and collaboration platform.",
        "security": "MEDIUM RISK - Collaboration platform",
        "link": "https://www.atlassian.com/software/confluence"
    },
    8060: {
        "description": "Atlassian JIRA",
        "details": "JIRA issue tracking and project management.",
        "security": "MEDIUM RISK - Project management",
        "link": "https://www.atlassian.com/software/jira"
    },
    7990: {
        "description": "Atlassian Bitbucket",
        "details": "Bitbucket Git repository management.",
        "security": "MEDIUM RISK - Source code management",
        "link": "https://www.atlassian.com/software/bitbucket"
    },
    8080: {
        "description": "Jenkins (duplicate - will be updated)",
        "details": "Jenkins automation server.",
        "security": "HIGH RISK - CI/CD automation",
        "link": "https://www.jenkins.io/"
    },
    50000: {
        "description": "Jenkins Agent (duplicate - will be updated)",
        "details": "Jenkins build agent communication.",
        "security": "HIGH RISK - Build agent communication",
        "link": "https://www.jenkins.io/"
    },
    9000: {
        "description": "SonarQube",
        "details": "SonarQube code quality analysis platform.",
        "security": "MEDIUM RISK - Code analysis platform",
        "link": "https://www.sonarqube.org/"
    },
    8081: {
        "description": "Nexus Repository (duplicate - will be updated)",
        "details": "Sonatype Nexus artifact repository.",
        "security": "MEDIUM RISK - Artifact repository",
        "link": "https://www.sonatype.com/nexus"
    },
    8082: {
        "description": "Artifactory",
        "details": "JFrog Artifactory artifact repository.",
        "security": "MEDIUM RISK - Artifact repository",
        "link": "https://jfrog.com/artifactory/"
    },
    3001: {
        "description": "Grafana Enterprise/React Dev",
        "details": "Grafana Enterprise or React development server.",
        "security": "MEDIUM RISK - Development/monitoring service",
        "link": "https://grafana.com/"
    },
    3030: {
        "description": "Cockpit Web Console",
        "details": "Red Hat Cockpit web-based server administration.",
        "security": "HIGH RISK - System administration interface",
        "link": "https://cockpit-project.org/"
    },
    9080: {
        "description": "Glassfish Admin",
        "details": "Oracle Glassfish application server administration.",
        "security": "HIGH RISK - Application server admin",
        "link": "https://javaee.github.io/glassfish/"
    },
    4848: {
        "description": "Glassfish Admin Console",
        "details": "Glassfish administrative web console.",
        "security": "HIGH RISK - Application server console",
        "link": "https://javaee.github.io/glassfish/"
    },
    8009: {
        "description": "Apache Tomcat AJP",
        "details": "Tomcat Apache JServ Protocol connector.",
        "security": "MEDIUM RISK - Application server protocol",
        "link": "https://tomcat.apache.org/"
    },
    8005: {
        "description": "Tomcat Shutdown",
        "details": "Apache Tomcat shutdown port.",
        "security": "HIGH RISK - Application server control",
        "link": "https://tomcat.apache.org/"
    },
    9990: {
        "description": "JBoss/WildFly Management",
        "details": "JBoss/WildFly application server management.",
        "security": "HIGH RISK - Application server management",
        "link": "https://wildfly.org/"
    },
    9999: {
        "description": "JBoss/WildFly Admin Console",
        "details": "JBoss/WildFly administrative console.",
        "security": "HIGH RISK - Application server console",
        "link": "https://wildfly.org/"
    },
    4040: {
        "description": "Apache Spark UI",
        "details": "Apache Spark web UI for job monitoring.",
        "security": "MEDIUM RISK - Big data processing UI",
        "link": "https://spark.apache.org/"
    },
    7077: {
        "description": "Apache Spark Master",
        "details": "Spark cluster master node communication.",
        "security": "HIGH RISK - Big data cluster master",
        "link": "https://spark.apache.org/"
    },
    7337: {
        "description": "Apache Spark Worker",
        "details": "Spark cluster worker node communication.",
        "security": "MEDIUM RISK - Big data worker node",
        "link": "https://spark.apache.org/"
    },
    18080: {
        "description": "Spark History Server",
        "details": "Spark application history web interface.",
        "security": "MEDIUM RISK - Job history interface",
        "link": "https://spark.apache.org/"
    },
    
    # Gaming & Entertainment (10 ports)
    25565: {
        "description": "Minecraft Server",
        "details": "Minecraft game server default port.",
        "security": "LOW RISK - Game server",
        "link": "https://www.minecraft.net/"
    },
    25575: {
        "description": "Minecraft RCON",
        "details": "Minecraft remote console protocol.",
        "security": "MEDIUM RISK - Game server administration",
        "link": "https://wiki.vg/RCON"
    },
    7777: {
        "description": "Terraria Server",
        "details": "Terraria game server default port.",
        "security": "LOW RISK - Game server",
        "link": "https://terraria.org/"
    },
    7784: {
        "description": "Factorio Server",
        "details": "Factorio game server default port.",
        "security": "LOW RISK - Game server",
        "link": "https://www.factorio.com/"
    },
    2456: {
        "description": "Valheim Server",
        "details": "Valheim dedicated game server.",
        "security": "LOW RISK - Game server",
        "link": "https://store.steampowered.com/app/892970/Valheim/"
    },
    2457: {
        "description": "Valheim Server Query",
        "details": "Valheim server query and discovery.",
        "security": "LOW RISK - Game server query",
        "link": "https://store.steampowered.com/app/892970/Valheim/"
    },
    28015: {
        "description": "Rust Game Server",
        "details": "Rust survival game server.",
        "security": "LOW RISK - Game server",
        "link": "https://rust.facepunch.com/"
    },
    28016: {
        "description": "Rust RCON",
        "details": "Rust game server remote console.",
        "security": "MEDIUM RISK - Game server administration",
        "link": "https://rust.facepunch.com/"
    },
    19132: {
        "description": "Minecraft Bedrock",
        "details": "Minecraft Bedrock Edition server.",
        "security": "LOW RISK - Game server",
        "link": "https://www.minecraft.net/"
    },
    64738: {
        "description": "Mumble Voice Chat",
        "details": "Mumble voice communication server.",
        "security": "LOW RISK - Voice communication",
        "link": "https://www.mumble.info/"
    },
    
    # IoT & Smart Home (15 ports)
    8123: {
        "description": "Home Assistant",
        "details": "Home Assistant smart home automation platform.",
        "security": "MEDIUM RISK - Smart home controller",
        "link": "https://www.home-assistant.io/"
    },
    8086: {
        "description": "Home Assistant Supervisor (duplicate - will be updated)",
        "details": "Home Assistant Supervisor API.",
        "security": "HIGH RISK - Smart home management",
        "link": "https://www.home-assistant.io/"
    },
    1880: {
        "description": "Node-RED",
        "details": "Node-RED flow-based programming platform.",
        "security": "HIGH RISK - IoT programming platform",
        "link": "https://nodered.org/"
    },
    8080: {
        "description": "openHAB (duplicate - will be updated)",
        "details": "openHAB smart home automation platform.",
        "security": "MEDIUM RISK - Smart home automation",
        "link": "https://www.openhab.org/"
    },
    8443: {
        "description": "openHAB HTTPS",
        "details": "openHAB secure web interface.",
        "security": "SECURE - Encrypted smart home interface",
        "link": "https://www.openhab.org/"
    },
    8083: {
        "description": "Domoticz (duplicate - will be updated)",
        "details": "Domoticz home automation system.",
        "security": "MEDIUM RISK - Home automation",
        "link": "https://domoticz.com/"
    },
    8084: {
        "description": "Domoticz SSL",
        "details": "Domoticz secure web interface.",
        "security": "SECURE - Encrypted home automation",
        "link": "https://domoticz.com/"
    },
    5000: {
        "description": "Synology DSM/UPnP",
        "details": "Synology DiskStation Manager or UPnP service.",
        "security": "HIGH RISK - NAS administration",
        "link": "https://www.synology.com/"
    },
    5001: {
        "description": "Synology DSM HTTPS",
        "details": "Synology DiskStation Manager secure interface.",
        "security": "MEDIUM RISK - Encrypted NAS administration",
        "link": "https://www.synology.com/"
    },
    1400: {
        "description": "Sonos Control",
        "details": "Sonos wireless speaker control protocol.",
        "security": "LOW RISK - Audio device control",
        "link": "https://www.sonos.com/"
    },
    6600: {
        "description": "Music Player Daemon",
        "details": "Music Player Daemon (MPD) audio server.",
        "security": "LOW RISK - Music streaming server",
        "link": "https://www.musicpd.org/"
    },
    8200: {
        "description": "Fibaro Home Center (duplicate - will be updated)",
        "details": "Fibaro Home Center smart home controller.",
        "security": "MEDIUM RISK - Smart home controller",
        "link": "https://www.fibaro.com/"
    },
    9443: {
        "description": "Portainer HTTPS",
        "details": "Portainer Docker management interface (HTTPS).",
        "security": "MEDIUM RISK - Container management",
        "link": "https://www.portainer.io/"
    },
    9000: {
        "description": "Portainer HTTP (duplicate - will be updated)",
        "details": "Portainer Docker management interface.",
        "security": "MEDIUM RISK - Container management",
        "link": "https://www.portainer.io/"
    },
    51826: {
        "description": "WireGuard VPN",
        "details": "WireGuard VPN protocol (default port).",
        "security": "SECURE - VPN tunnel",
        "link": "https://www.wireguard.com/"
    },
    
    # Network Infrastructure (20 ports)
    69: {
        "description": "TFTP - Trivial File Transfer Protocol",
        "details": "Simple file transfer protocol, often used for network booting.",
        "security": "HIGH RISK - No authentication, plaintext",
        "link": "https://tools.ietf.org/html/rfc1350"
    },
    514: {
        "description": "Syslog",
        "details": "System logging protocol for network devices.",
        "security": "MEDIUM RISK - Log aggregation, plaintext",
        "link": "https://tools.ietf.org/html/rfc3164"
    },
    6514: {
        "description": "Syslog over TLS",
        "details": "Secure syslog over TLS encryption.",
        "security": "SECURE - Encrypted logging",
        "link": "https://tools.ietf.org/html/rfc5425"
    },
    123: {
        "description": "NTP - Network Time Protocol",
        "details": "Network time synchronization protocol.",
        "security": "LOW RISK - Time synchronization",
        "link": "https://tools.ietf.org/html/rfc5905"
    },
    67: {
        "description": "DHCP Server",
        "details": "Dynamic Host Configuration Protocol server.",
        "security": "MEDIUM RISK - IP address assignment",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    68: {
        "description": "DHCP Client",
        "details": "DHCP client communication port.",
        "security": "LOW RISK - IP address requests",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    546: {
        "description": "DHCPv6 Client",
        "details": "DHCPv6 client for IPv6 address assignment.",
        "security": "LOW RISK - IPv6 address requests",
        "link": "https://tools.ietf.org/html/rfc3315"
    },
    547: {
        "description": "DHCPv6 Server",
        "details": "DHCPv6 server for IPv6 address assignment.",
        "security": "MEDIUM RISK - IPv6 address assignment",
        "link": "https://tools.ietf.org/html/rfc3315"
    },
    520: {
        "description": "RIP - Routing Information Protocol",
        "details": "Distance-vector routing protocol.",
        "security": "HIGH RISK - Network routing, often unauthenticated",
        "link": "https://tools.ietf.org/html/rfc2453"
    },
    521: {
        "description": "RIPng for IPv6",
        "details": "RIP next generation for IPv6 networks.",
        "security": "MEDIUM RISK - IPv6 routing protocol",
        "link": "https://tools.ietf.org/html/rfc2080"
    },
    179: {
        "description": "BGP - Border Gateway Protocol",
        "details": "Internet backbone routing protocol.",
        "security": "HIGH RISK - Critical internet routing",
        "link": "https://tools.ietf.org/html/rfc4271"
    },
    646: {
        "description": "LDP - Label Distribution Protocol",
        "details": "MPLS label distribution protocol.",
        "security": "HIGH RISK - MPLS network routing",
        "link": "https://tools.ietf.org/html/rfc5036"
    },
    1701: {
        "description": "L2TP - Layer 2 Tunneling Protocol",
        "details": "VPN tunneling protocol over UDP.",
        "security": "MEDIUM RISK - VPN tunneling",
        "link": "https://tools.ietf.org/html/rfc2661"
    },
    4500: {
        "description": "IPSec NAT-T",
        "details": "IPSec NAT traversal for VPN through NAT.",
        "security": "SECURE - VPN NAT traversal",
        "link": "https://tools.ietf.org/html/rfc3947"
    },
    500: {
        "description": "IKE - Internet Key Exchange",
        "details": "IPSec key exchange protocol.",
        "security": "SECURE - VPN key exchange",
        "link": "https://tools.ietf.org/html/rfc7296"
    },
    1194: {
        "description": "OpenVPN",
        "details": "OpenVPN SSL/TLS-based VPN protocol.",
        "security": "SECURE - SSL VPN",
        "link": "https://openvpn.net/"
    },
    443: {
        "description": "HTTPS (duplicate - will be updated)",
        "details": "HTTP over TLS/SSL secure web traffic.",
        "security": "SECURE - Encrypted web traffic",
        "link": "https://tools.ietf.org/html/rfc2818"
    },
    853: {
        "description": "DNS over TLS",
        "details": "DNS queries over TLS encryption.",
        "security": "SECURE - Encrypted DNS",
        "link": "https://tools.ietf.org/html/rfc7858"
    },
    8053: {
        "description": "DNS over HTTPS (Alternative)",
        "details": "DNS queries over HTTPS (alternative port).",
        "security": "SECURE - Encrypted DNS over HTTPS",
        "link": "https://tools.ietf.org/html/rfc8484"
    },
    5060: {
        "description": "SIP - Session Initiation Protocol",
        "details": "Voice over IP signaling protocol.",
        "security": "MEDIUM RISK - VoIP signaling",
        "link": "https://tools.ietf.org/html/rfc3261"
    },
    
    # Legacy & Specialized Protocols (25 ports)
    513: {
        "description": "rlogin",
        "details": "Remote login protocol (insecure legacy).",
        "security": "HIGH RISK - Legacy remote login, plaintext",
        "link": "https://tools.ietf.org/html/rfc1282"
    },
    512: {
        "description": "rexec",
        "details": "Remote execution protocol (insecure legacy).",
        "security": "HIGH RISK - Legacy remote execution",
        "link": "https://en.wikipedia.org/wiki/Remote_Process_Execution"
    },
    514: {
        "description": "rsh (duplicate - will be updated)",
        "details": "Remote shell protocol (insecure legacy).",
        "security": "HIGH RISK - Legacy remote shell",
        "link": "https://en.wikipedia.org/wiki/Remote_Shell"
    },
    515: {
        "description": "LPD - Line Printer Daemon",
        "details": "Network printing protocol.",
        "security": "MEDIUM RISK - Network printing service",
        "link": "https://tools.ietf.org/html/rfc1179"
    },
    631: {
        "description": "CUPS - Common Unix Printing System",
        "details": "Internet Printing Protocol (IPP).",
        "security": "MEDIUM RISK - Network printing",
        "link": "https://www.cups.org/"
    },
    9100: {
        "description": "HP JetDirect",
        "details": "HP printer network interface.",
        "security": "MEDIUM RISK - Network printer",
        "link": "https://www.hp.com/"
    },
    515: {
        "description": "LPR/LPD (duplicate - will be updated)",
        "details": "Line printer remote/daemon protocol.",
        "security": "MEDIUM RISK - Network printing",
        "link": "https://tools.ietf.org/html/rfc1179"
    },
    170: {
        "description": "Network PostScript",
        "details": "Network PostScript printing protocol.",
        "security": "LOW RISK - PostScript printing",
        "link": "https://en.wikipedia.org/wiki/PostScript"
    },
    2000: {
        "description": "Cisco SCCP",
        "details": "Cisco Skinny Client Control Protocol.",
        "security": "MEDIUM RISK - IP telephony protocol",
        "link": "https://www.cisco.com/"
    },
    5004: {
        "description": "RTP - Real-time Transport Protocol",
        "details": "Audio/video streaming protocol.",
        "security": "LOW RISK - Media streaming",
        "link": "https://tools.ietf.org/html/rfc3550"
    },
    5005: {
        "description": "RTP Control Protocol",
        "details": "RTCP for RTP session control.",
        "security": "LOW RISK - Media control protocol",
        "link": "https://tools.ietf.org/html/rfc3550"
    },
    554: {
        "description": "RTSP - Real Time Streaming Protocol",
        "details": "Network control protocol for streaming servers.",
        "security": "MEDIUM RISK - Streaming media control",
        "link": "https://tools.ietf.org/html/rfc2326"
    },
    1755: {
        "description": "Windows Media Services",
        "details": "Microsoft Media Server streaming protocol.",
        "security": "MEDIUM RISK - Microsoft media streaming",
        "link": "https://docs.microsoft.com/en-us/windows/win32/wmformat/windows-media-services"
    },
    7070: {
        "description": "RealServer/QuickTime",
        "details": "Real Networks streaming or QuickTime streaming.",
        "security": "MEDIUM RISK - Media streaming server",
        "link": "https://en.wikipedia.org/wiki/RealNetworks"
    },
    8000: {
        "description": "iRadio/SHOUTcast",
        "details": "Internet radio streaming protocol.",
        "security": "LOW RISK - Audio streaming",
        "link": "https://www.shoutcast.com/"
    },
    8001: {
        "description": "VCOM Tunnel",
        "details": "VCOM tunnel or alternative HTTP service.",
        "security": "MEDIUM RISK - Tunnel or web service",
        "link": "https://en.wikipedia.org/wiki/VCOM"
    },
    990: {
        "description": "FTPS Implicit",
        "details": "FTP over SSL/TLS (implicit encryption).",
        "security": "SECURE - Encrypted file transfer",
        "link": "https://tools.ietf.org/html/rfc4217"
    },
    989: {
        "description": "FTPS Data",
        "details": "FTPS data channel for encrypted file transfer.",
        "security": "SECURE - Encrypted file transfer data",
        "link": "https://tools.ietf.org/html/rfc4217"
    },
    220: {
        "description": "IMAP3",
        "details": "Internet Message Access Protocol version 3.",
        "security": "MEDIUM RISK - Legacy email protocol",
        "link": "https://tools.ietf.org/html/rfc1203"
    },
    585: {
        "description": "IMAP4-SSL",
        "details": "IMAP4 over SSL (deprecated, use 993).",
        "security": "SECURE - Encrypted email access",
        "link": "https://tools.ietf.org/html/rfc2595"
    },
    465: {
        "description": "SMTP over SSL (deprecated)",
        "details": "SMTP over SSL (deprecated, use STARTTLS on 587).",
        "security": "SECURE - Encrypted email submission",
        "link": "https://tools.ietf.org/html/rfc8314"
    },
    366: {
        "description": "ODMR - On-Demand Mail Relay",
        "details": "On-demand mail relay for intermittent connections.",
        "security": "MEDIUM RISK - Mail relay protocol",
        "link": "https://tools.ietf.org/html/rfc2645"
    },
    1109: {
        "description": "KPOP - Kerberized POP",
        "details": "Kerberos-authenticated POP3.",
        "security": "SECURE - Authenticated email access",
        "link": "https://tools.ietf.org/html/rfc1734"
    },
    4190: {
        "description": "Sieve Mail Filtering",
        "details": "ManageSieve protocol for mail filtering rules.",
        "security": "MEDIUM RISK - Mail filtering management",
        "link": "https://tools.ietf.org/html/rfc5804"
    },
    1080: {
        "description": "SOCKS Proxy",
        "details": "SOCKS proxy protocol for TCP/UDP relay.",
        "security": "HIGH RISK - Proxy service, can be abused",
        "link": "https://tools.ietf.org/html/rfc1928"
    },
    
    # Backup & Storage Services (10 ports)
    10000: {
        "description": "Webmin",
        "details": "Web-based system administration interface.",
        "security": "HIGH RISK - System administration",
        "link": "https://www.webmin.com/"
    },
    20000: {
        "description": "Usermin (duplicate - will be updated)",
        "details": "Web-based user account management.",
        "security": "MEDIUM RISK - User administration",
        "link": "https://www.webmin.com/usermin.html"
    },
    2049: {
        "description": "NFS - Network File System",
        "details": "Network file sharing protocol.",
        "security": "HIGH RISK - Network file access",
        "link": "https://tools.ietf.org/html/rfc7530"
    },
    2048: {
        "description": "NFS Lock Manager",
        "details": "NFS file locking service.",
        "security": "MEDIUM RISK - File locking service",
        "link": "https://tools.ietf.org/html/rfc1813"
    },
    111: {
        "description": "RPC Portmapper",
        "details": "Remote Procedure Call port mapping service.",
        "security": "HIGH RISK - RPC service discovery",
        "link": "https://tools.ietf.org/html/rfc1833"
    },
    445: {
        "description": "SMB - Server Message Block",
        "details": "Windows file and printer sharing.",
        "security": "HIGH RISK - Windows file sharing",
        "link": "https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview"
    },
    139: {
        "description": "NetBIOS Session Service",
        "details": "NetBIOS session layer for Windows networking.",
        "security": "MEDIUM RISK - Legacy Windows networking",
        "link": "https://tools.ietf.org/html/rfc1002"
    },
    137: {
        "description": "NetBIOS Name Service",
        "details": "NetBIOS name resolution service.",
        "security": "MEDIUM RISK - Windows name resolution",
        "link": "https://tools.ietf.org/html/rfc1002"
    },
    138: {
        "description": "NetBIOS Datagram Service",
        "details": "NetBIOS datagram distribution service.",
        "security": "MEDIUM RISK - Windows networking",
        "link": "https://tools.ietf.org/html/rfc1002"
    },
    2121: {
        "description": "CCProxy/Alternative FTP",
        "details": "CCProxy server or alternative FTP service.",
        "security": "MEDIUM RISK - Proxy or file transfer",
        "link": "https://www.youngzsoft.net/ccproxy/"
    },
    
    # Virtualization & Cloud Native (15 ports)
    8443: {
        "description": "VMware vSphere (duplicate - will be updated)",
        "details": "VMware vCenter Server HTTPS interface.",
        "security": "HIGH RISK - Virtualization management",
        "link": "https://www.vmware.com/"
    },
    902: {
        "description": "VMware ESXi",
        "details": "VMware ESXi hypervisor management.",
        "security": "HIGH RISK - Hypervisor management",
        "link": "https://www.vmware.com/"
    },
    903: {
        "description": "VMware Console",
        "details": "VMware virtual machine console access.",
        "security": "MEDIUM RISK - VM console access",
        "link": "https://www.vmware.com/"
    },
    8080: {
        "description": "vSphere Web Client (duplicate - will be updated)",
        "details": "VMware vSphere Web Client interface.",
        "security": "HIGH RISK - Virtualization web interface",
        "link": "https://www.vmware.com/"
    },
    5900: {
        "description": "VNC - Virtual Network Computing",
        "details": "Remote desktop protocol.",
        "security": "HIGH RISK - Remote desktop access",
        "link": "https://www.realvnc.com/"
    },
    5901: {
        "description": "VNC Display 1",
        "details": "VNC remote desktop display 1.",
        "security": "HIGH RISK - Remote desktop access",
        "link": "https://www.realvnc.com/"
    },
    3389: {
        "description": "RDP - Remote Desktop Protocol",
        "details": "Microsoft Remote Desktop Protocol.",
        "security": "HIGH RISK - Windows remote desktop",
        "link": "https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol"
    },
    3390: {
        "description": "RDP Alternative",
        "details": "Alternative RDP port for multiple sessions.",
        "security": "HIGH RISK - Windows remote desktop",
        "link": "https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol"
    },
    18004: {
        "description": "Hyper-V VM Management",
        "details": "Microsoft Hyper-V virtual machine management.",
        "security": "HIGH RISK - Hypervisor management",
        "link": "https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/"
    },
    2179: {
        "description": "Hyper-V VMBus",
        "details": "Hyper-V VMBus communication channel.",
        "security": "MEDIUM RISK - VM communication",
        "link": "https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/"
    },
    8006: {
        "description": "Proxmox VE",
        "details": "Proxmox Virtual Environment web interface.",
        "security": "HIGH RISK - Virtualization management",
        "link": "https://www.proxmox.com/"
    },
    8007: {
        "description": "Proxmox Backup Server",
        "details": "Proxmox Backup Server web interface.",
        "security": "HIGH RISK - Backup server management",
        "link": "https://www.proxmox.com/"
    },
    5985: {
        "description": "WinRM HTTP",
        "details": "Windows Remote Management over HTTP.",
        "security": "HIGH RISK - Windows remote management",
        "link": "https://docs.microsoft.com/en-us/windows/win32/winrm/portal"
    },
    5986: {
        "description": "WinRM HTTPS",
        "details": "Windows Remote Management over HTTPS.",
        "security": "MEDIUM RISK - Encrypted Windows management",
        "link": "https://docs.microsoft.com/en-us/windows/win32/winrm/portal"
    },
    16509: {
        "description": "libvirt",
        "details": "libvirt virtualization management API.",
        "security": "HIGH RISK - Virtualization API",
        "link": "https://libvirt.org/"
    },
    
    # Monitoring & Observability (20 ports)
    162: {
        "description": "SNMP Trap (duplicate - will be updated)",
        "details": "SNMP trap notifications from network devices.",
        "security": "MEDIUM RISK - Network monitoring",
        "link": "https://www.paessler.com/snmp"
    },
    8125: {
        "description": "StatsD",
        "details": "StatsD metrics collection daemon.",
        "security": "MEDIUM RISK - Metrics collection",
        "link": "https://github.com/statsd/statsd"
    },
    8126: {
        "description": "StatsD Admin",
        "details": "StatsD administrative interface.",
        "security": "MEDIUM RISK - Metrics administration",
        "link": "https://github.com/statsd/statsd"
    },
    2003: {
        "description": "Graphite Carbon",
        "details": "Graphite Carbon metrics ingestion.",
        "security": "MEDIUM RISK - Metrics storage",
        "link": "https://graphite.readthedocs.io/"
    },
    2004: {
        "description": "Graphite Carbon Relay",
        "details": "Graphite Carbon relay for metrics distribution.",
        "security": "MEDIUM RISK - Metrics relay",
        "link": "https://graphite.readthedocs.io/"
    },
    7002: {
        "description": "Graphite Web",
        "details": "Graphite web interface for metrics visualization.",
        "security": "MEDIUM RISK - Metrics dashboard",
        "link": "https://graphite.readthedocs.io/"
    },
    8086: {
        "description": "InfluxDB (duplicate - will be updated)",
        "details": "InfluxDB time-series database HTTP API.",
        "security": "MEDIUM RISK - Time-series database",
        "link": "https://www.influxdata.com/"
    },
    8089: {
        "description": "InfluxDB UDP",
        "details": "InfluxDB UDP input for high-volume metrics.",
        "security": "MEDIUM RISK - Metrics ingestion",
        "link": "https://www.influxdata.com/"
    },
    3003: {
        "description": "Grafana Alternative",
        "details": "Alternative Grafana dashboard port.",
        "security": "MEDIUM RISK - Monitoring dashboard",
        "link": "https://grafana.com/"
    },
    9094: {
        "description": "Prometheus Pushgateway Alternative",
        "details": "Alternative Prometheus push gateway.",
        "security": "MEDIUM RISK - Metrics push service",
        "link": "https://prometheus.io/"
    },
    8428: {
        "description": "VictoriaMetrics",
        "details": "VictoriaMetrics time-series database.",
        "security": "MEDIUM RISK - Metrics database",
        "link": "https://victoriametrics.com/"
    },
    9428: {
        "description": "VictoriaMetrics Cluster",
        "details": "VictoriaMetrics cluster communication.",
        "security": "MEDIUM RISK - Metrics cluster",
        "link": "https://victoriametrics.com/"
    },
    9966: {
        "description": "Zabbix Agent",
        "details": "Zabbix monitoring agent.",
        "security": "MEDIUM RISK - Monitoring agent",
        "link": "https://www.zabbix.com/"
    },
    10050: {
        "description": "Zabbix Agent (Official)",
        "details": "Official Zabbix agent port.",
        "security": "MEDIUM RISK - Monitoring agent",
        "link": "https://www.zabbix.com/"
    },
    10051: {
        "description": "Zabbix Server",
        "details": "Zabbix monitoring server.",
        "security": "HIGH RISK - Monitoring server",
        "link": "https://www.zabbix.com/"
    },
    8080: {
        "description": "Zabbix Web (duplicate - will be updated)",
        "details": "Zabbix web monitoring interface.",
        "security": "MEDIUM RISK - Monitoring dashboard",
        "link": "https://www.zabbix.com/"
    },
    5666: {
        "description": "NRPE - Nagios Remote Plugin Executor",
        "details": "Nagios remote plugin execution service.",
        "security": "MEDIUM RISK - Monitoring plugin executor",
        "link": "https://www.nagios.org/"
    },
    5667: {
        "description": "NSCA - Nagios Service Check Acceptor",
        "details": "Nagios passive check results acceptor.",
        "security": "MEDIUM RISK - Monitoring check results",
        "link": "https://www.nagios.org/"
    },
    12201: {
        "description": "GELF - Graylog Extended Log Format",
        "details": "Graylog log message input protocol.",
        "security": "MEDIUM RISK - Log aggregation",
        "link": "https://www.graylog.org/"
    },
    9000: {
        "description": "Graylog Web Interface (duplicate - will be updated)",
        "details": "Graylog log management web interface.",
        "security": "MEDIUM RISK - Log management dashboard",
        "link": "https://www.graylog.org/"
    },
    
    # Blockchain & Cryptocurrency (10 ports)
    8545: {
        "description": "Ethereum JSON-RPC",
        "details": "Ethereum blockchain JSON-RPC API.",
        "security": "HIGH RISK - Blockchain node access",
        "link": "https://ethereum.org/"
    },
    8546: {
        "description": "Ethereum WebSocket",
        "details": "Ethereum WebSocket API for real-time data.",
        "security": "HIGH RISK - Blockchain WebSocket API",
        "link": "https://ethereum.org/"
    },
    30303: {
        "description": "Ethereum P2P",
        "details": "Ethereum peer-to-peer network protocol.",
        "security": "MEDIUM RISK - Blockchain P2P network",
        "link": "https://ethereum.org/"
    },
    8333: {
        "description": "Bitcoin Core",
        "details": "Bitcoin Core peer-to-peer network.",
        "security": "MEDIUM RISK - Bitcoin P2P network",
        "link": "https://bitcoin.org/"
    },
    8332: {
        "description": "Bitcoin RPC",
        "details": "Bitcoin Core JSON-RPC interface.",
        "security": "HIGH RISK - Bitcoin node RPC access",
        "link": "https://bitcoin.org/"
    },
    9735: {
        "description": "Lightning Network",
        "details": "Bitcoin Lightning Network protocol.",
        "security": "MEDIUM RISK - Bitcoin payment channel",
        "link": "https://lightning.network/"
    },
    18444: {
        "description": "Bitcoin Testnet",
        "details": "Bitcoin testnet P2P network.",
        "security": "LOW RISK - Bitcoin test network",
        "link": "https://bitcoin.org/"
    },
    18332: {
        "description": "Bitcoin Testnet RPC",
        "details": "Bitcoin testnet JSON-RPC interface.",
        "security": "MEDIUM RISK - Bitcoin test RPC",
        "link": "https://bitcoin.org/"
    },
    26656: {
        "description": "Tendermint P2P",
        "details": "Tendermint blockchain consensus P2P.",
        "security": "MEDIUM RISK - Blockchain consensus",
        "link": "https://tendermint.com/"
    },
    26657: {
        "description": "Tendermint RPC",
        "details": "Tendermint blockchain RPC interface.",
        "security": "HIGH RISK - Blockchain RPC access",
        "link": "https://tendermint.com/"
    },
    
    # Enterprise Applications & ERP Systems (15 ports)
    8000: {
        "description": "SAP Internet Communication Manager",
        "details": "SAP ICM HTTP service for enterprise applications.",
        "security": "HIGH RISK - SAP enterprise system",
        "link": "https://www.sap.com/"
    },
    8443: {
        "description": "SAP HTTPS Service",
        "details": "SAP secure HTTP service for enterprise applications.",
        "security": "MEDIUM RISK - Encrypted SAP service",
        "link": "https://www.sap.com/"
    },
    3200: {
        "description": "SAP Gateway Service",
        "details": "SAP Gateway communication service.",
        "security": "HIGH RISK - SAP gateway service",
        "link": "https://www.sap.com/"
    },
    3300: {
        "description": "SAP Application Server",
        "details": "SAP application server communication.",
        "security": "HIGH RISK - SAP application layer",
        "link": "https://www.sap.com/"
    },
    50013: {
        "description": "SAP HANA SQL",
        "details": "SAP HANA in-memory database SQL interface.",
        "security": "HIGH RISK - Enterprise database",
        "link": "https://www.sap.com/products/hana.html"
    },
    50014: {
        "description": "SAP HANA HTTP",
        "details": "SAP HANA HTTP interface for web services.",
        "security": "HIGH RISK - Enterprise database web interface",
        "link": "https://www.sap.com/products/hana.html"
    },
    1527: {
        "description": "Oracle TNS Listener Alternative",
        "details": "Alternative Oracle database listener port.",
        "security": "HIGH RISK - Oracle database",
        "link": "https://www.oracle.com/"
    },
    1528: {
        "description": "Oracle Connection Manager",
        "details": "Oracle Connection Manager for database access.",
        "security": "HIGH RISK - Oracle connection management",
        "link": "https://www.oracle.com/"
    },
    1158: {
        "description": "Oracle OEMCTL",
        "details": "Oracle Enterprise Manager Control utility.",
        "security": "HIGH RISK - Oracle management",
        "link": "https://www.oracle.com/"
    },
    7001: {
        "description": "Oracle WebLogic Admin (duplicate - will be updated)",
        "details": "Oracle WebLogic Server administration console.",
        "security": "HIGH RISK - Application server admin",
        "link": "https://www.oracle.com/middleware/weblogic/"
    },
    7002: {
        "description": "Oracle WebLogic Admin SSL",
        "details": "Oracle WebLogic Server secure administration.",
        "security": "MEDIUM RISK - Encrypted app server admin",
        "link": "https://www.oracle.com/middleware/weblogic/"
    },
    1414: {
        "description": "IBM MQ/WebSphere MQ",
        "details": "IBM Message Queue middleware.",
        "security": "HIGH RISK - Enterprise message queue",
        "link": "https://www.ibm.com/products/mq"
    },
    9443: {
        "description": "IBM WebSphere Admin Console",
        "details": "IBM WebSphere Application Server admin console.",
        "security": "HIGH RISK - Application server management",
        "link": "https://www.ibm.com/products/websphere-application-server"
    },
    9060: {
        "description": "IBM WebSphere HTTP",
        "details": "IBM WebSphere Application Server HTTP transport.",
        "security": "MEDIUM RISK - Application server HTTP",
        "link": "https://www.ibm.com/products/websphere-application-server"
    },
    9080: {
        "description": "IBM WebSphere HTTP Alternative",
        "details": "Alternative IBM WebSphere HTTP port.",
        "security": "MEDIUM RISK - Application server alternative",
        "link": "https://www.ibm.com/products/websphere-application-server"
    },
    
    # Microsoft Enterprise Services (15 ports)
    1433: {
        "description": "SQL Server (duplicate - will be updated)",
        "details": "Microsoft SQL Server Database Engine.",
        "security": "HIGH RISK - Enterprise database",
        "link": "https://www.microsoft.com/sql-server/"
    },
    1434: {
        "description": "SQL Server Browser",
        "details": "SQL Server Browser service for instance discovery.",
        "security": "MEDIUM RISK - Database discovery service",
        "link": "https://www.microsoft.com/sql-server/"
    },
    1435: {
        "description": "SQL Server AlwaysOn",
        "details": "SQL Server AlwaysOn Availability Groups.",
        "security": "HIGH RISK - Database clustering",
        "link": "https://www.microsoft.com/sql-server/"
    },
    5022: {
        "description": "SQL Server Service Broker",
        "details": "SQL Server Service Broker messaging.",
        "security": "MEDIUM RISK - Database messaging",
        "link": "https://www.microsoft.com/sql-server/"
    },
    4022: {
        "description": "SQL Server Mirroring",
        "details": "SQL Server database mirroring endpoint.",
        "security": "HIGH RISK - Database replication",
        "link": "https://www.microsoft.com/sql-server/"
    },
    2382: {
        "description": "SQL Server Analysis Services",
        "details": "SQL Server Analysis Services (SSAS).",
        "security": "HIGH RISK - Business intelligence service",
        "link": "https://www.microsoft.com/sql-server/"
    },
    2383: {
        "description": "SQL Server Reporting Services",
        "details": "SQL Server Reporting Services (SSRS).",
        "security": "MEDIUM RISK - Reporting service",
        "link": "https://www.microsoft.com/sql-server/"
    },
    1024: {
        "description": "Microsoft Exchange RPC",
        "details": "Microsoft Exchange Server RPC communication.",
        "security": "HIGH RISK - Email server management",
        "link": "https://www.microsoft.com/microsoft-365/exchange/"
    },
    593: {
        "description": "Microsoft RPC Endpoint Mapper",
        "details": "Microsoft RPC endpoint mapper service.",
        "security": "HIGH RISK - RPC service discovery",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    135: {
        "description": "Microsoft RPC Locator",
        "details": "Microsoft RPC endpoint mapper.",
        "security": "HIGH RISK - Windows RPC service",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    1720: {
        "description": "H.323/NetMeeting",
        "details": "H.323 call signaling or NetMeeting.",
        "security": "MEDIUM RISK - Video conferencing protocol",
        "link": "https://www.itu.int/rec/T-REC-H.323/"
    },
    1503: {
        "description": "Windows Live Messenger",
        "details": "Windows Live Messenger service (legacy).",
        "security": "LOW RISK - Legacy messaging service",
        "link": "https://en.wikipedia.org/wiki/Windows_Live_Messenger"
    },
    8530: {
        "description": "Windows Server Update Services",
        "details": "Microsoft WSUS update distribution service.",
        "security": "HIGH RISK - System update service",
        "link": "https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/"
    },
    8531: {
        "description": "WSUS SSL",
        "details": "Windows Server Update Services over SSL.",
        "security": "MEDIUM RISK - Encrypted update service",
        "link": "https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/"
    },
    1801: {
        "description": "Microsoft Message Queuing",
        "details": "Microsoft Message Queuing (MSMQ) service.",
        "security": "MEDIUM RISK - Windows message queuing",
        "link": "https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms711472(v=vs.85)"
    },
    
    # Industrial Control Systems & SCADA (12 ports)
    2404: {
        "description": "IEC 61850 MMS",
        "details": "IEC 61850 Manufacturing Message Specification for power systems.",
        "security": "HIGH RISK - Power system communication",
        "link": "https://en.wikipedia.org/wiki/IEC_61850"
    },
    19999: {
        "description": "DNP3 Secure Authentication",
        "details": "DNP3 with Secure Authentication for critical infrastructure.",
        "security": "MEDIUM RISK - Authenticated SCADA protocol",
        "link": "https://en.wikipedia.org/wiki/DNP3"
    },
    47808: {
        "description": "BACnet/IP",
        "details": "Building Automation and Control Networks over IP.",
        "security": "MEDIUM RISK - Building automation protocol",
        "link": "https://en.wikipedia.org/wiki/BACnet"
    },
    1911: {
        "description": "Niagara Fox Protocol",
        "details": "Tridium Niagara Fox protocol for building automation.",
        "security": "HIGH RISK - Building automation system",
        "link": "https://www.tridium.com/"
    },
    1962: {
        "description": "PCWorx",
        "details": "Phoenix Contact PCWorx automation protocol.",
        "security": "HIGH RISK - Industrial automation",
        "link": "https://www.phoenixcontact.com/"
    },
    9600: {
        "description": "OMRON FINS",
        "details": "OMRON Factory Interface Network Service protocol.",
        "security": "HIGH RISK - Industrial PLC communication",
        "link": "https://industrial.omron.us/"
    },
    34962: {
        "description": "Profinet/DCP",
        "details": "Profinet Discovery and Configuration Protocol.",
        "security": "HIGH RISK - Industrial Ethernet protocol",
        "link": "https://www.profibus.com/"
    },
    34963: {
        "description": "Profinet Real-Time",
        "details": "Profinet real-time communication protocol.",
        "security": "HIGH RISK - Industrial real-time protocol",
        "link": "https://www.profibus.com/"
    },
    34964: {
        "description": "Profinet Context Manager",
        "details": "Profinet Context Manager protocol.",
        "security": "HIGH RISK - Industrial network management",
        "link": "https://www.profibus.com/"
    },
    55000: {
        "description": "Schneider Electric Unity",
        "details": "Schneider Electric Unity Pro PLC protocol.",
        "security": "HIGH RISK - PLC programming interface",
        "link": "https://www.schneider-electric.com/"
    },
    55001: {
        "description": "Schneider Electric Modicon",
        "details": "Schneider Electric Modicon PLC communication.",
        "security": "HIGH RISK - PLC communication",
        "link": "https://www.schneider-electric.com/"
    },
    55003: {
        "description": "Schneider Electric SoMachine",
        "details": "Schneider Electric SoMachine automation platform.",
        "security": "HIGH RISK - Automation platform",
        "link": "https://www.schneider-electric.com/"
    },
    
    # Cloud Provider Services (20 ports)
    9418: {
        "description": "Git Protocol",
        "details": "Git version control protocol (read-only).",
        "security": "MEDIUM RISK - Source code access",
        "link": "https://git-scm.com/"
    },
    9419: {
        "description": "Git Protocol SSL",
        "details": "Git protocol over SSL/TLS.",
        "security": "SECURE - Encrypted source control",
        "link": "https://git-scm.com/"
    },
    2222: {
        "description": "SSH Alternative/GitLab",
        "details": "Alternative SSH port or GitLab SSH service.",
        "security": "SECURE - SSH alternative port",
        "link": "https://about.gitlab.com/"
    },
    8060: {
        "description": "Atlassian Jira (duplicate - will be updated)",
        "details": "Atlassian Jira project management.",
        "security": "MEDIUM RISK - Project management platform",
        "link": "https://www.atlassian.com/software/jira"
    },
    8065: {
        "description": "Mattermost",
        "details": "Mattermost team collaboration platform.",
        "security": "MEDIUM RISK - Team messaging platform",
        "link": "https://mattermost.com/"
    },
    4567: {
        "description": "Sinatra/Rack Development",
        "details": "Ruby Sinatra framework or Rack development server.",
        "security": "LOW RISK - Development framework",
        "link": "https://sinatrarb.com/"
    },
    3000: {
        "description": "Node.js/React Development (duplicate - will be updated)",
        "details": "Node.js Express or React development server.",
        "security": "LOW RISK - Development server",
        "link": "https://nodejs.org/"
    },
    3001: {
        "description": "Next.js Development (duplicate - will be updated)",
        "details": "Next.js React development server.",
        "security": "LOW RISK - React development",
        "link": "https://nextjs.org/"
    },
    8000: {
        "description": "Django Development (duplicate - will be updated)",
        "details": "Django Python web framework development.",
        "security": "LOW RISK - Python development",
        "link": "https://www.djangoproject.com/"
    },
    8080: {
        "description": "Spring Boot (duplicate - will be updated)",
        "details": "Spring Boot Java development server.",
        "security": "LOW RISK - Java development",
        "link": "https://spring.io/projects/spring-boot"
    },
    5000: {
        "description": "Flask Development (duplicate - will be updated)",
        "details": "Flask Python development server.",
        "security": "LOW RISK - Python development",
        "link": "https://flask.palletsprojects.com/"
    },
    8501: {
        "description": "Streamlit",
        "details": "Streamlit data science web application framework.",
        "security": "LOW RISK - Data science development",
        "link": "https://streamlit.io/"
    },
    8888: {
        "description": "Jupyter Notebook",
        "details": "Jupyter Notebook interactive computing environment.",
        "security": "HIGH RISK - Code execution environment",
        "link": "https://jupyter.org/"
    },
    8889: {
        "description": "Jupyter Lab",
        "details": "JupyterLab next-generation notebook interface.",
        "security": "HIGH RISK - Code execution environment",
        "link": "https://jupyter.org/"
    },
    8050: {
        "description": "Dash Plotly",
        "details": "Plotly Dash analytical web application framework.",
        "security": "LOW RISK - Data visualization development",
        "link": "https://plotly.com/dash/"
    },
    7000: {
        "description": "Jekyll Development (duplicate - will be updated)",
        "details": "Jekyll static site generator development server.",
        "security": "LOW RISK - Static site development",
        "link": "https://jekyllrb.com/"
    },
    4000: {
        "description": "Hugo Development",
        "details": "Hugo static site generator development server.",
        "security": "LOW RISK - Static site development",
        "link": "https://gohugo.io/"
    },
    1313: {
        "description": "Hugo Default Port",
        "details": "Hugo static site generator default port.",
        "security": "LOW RISK - Static site development",
        "link": "https://gohugo.io/"
    },
    8080: {
        "description": "Webpack Dev Server (duplicate - will be updated)",
        "details": "Webpack development server for frontend builds.",
        "security": "LOW RISK - Frontend development",
        "link": "https://webpack.js.org/"
    },
    35729: {
        "description": "LiveReload",
        "details": "LiveReload development tool for auto-refresh.",
        "security": "LOW RISK - Development tool",
        "link": "http://livereload.com/"
    },
    
    # Scientific & Research Computing (8 ports)
    8787: {
        "description": "RStudio Server",
        "details": "RStudio Server for R statistical computing.",
        "security": "MEDIUM RISK - Statistical computing environment",
        "link": "https://www.rstudio.com/"
    },
    8786: {
        "description": "Shiny Server",
        "details": "R Shiny Server for interactive web applications.",
        "security": "MEDIUM RISK - R web application server",
        "link": "https://shiny.rstudio.com/"
    },
    29418: {
        "description": "Gerrit Code Review",
        "details": "Gerrit code review system for Git repositories.",
        "security": "MEDIUM RISK - Code review platform",
        "link": "https://www.gerritcodereview.com/"
    },
    8080: {
        "description": "Gerrit Web Interface (duplicate - will be updated)",
        "details": "Gerrit code review web interface.",
        "security": "MEDIUM RISK - Code review web UI",
        "link": "https://www.gerritcodereview.com/"
    },
    7001: {
        "description": "MATLAB License Manager (duplicate - will be updated)",
        "details": "MATLAB license server.",
        "security": "MEDIUM RISK - Software licensing",
        "link": "https://www.mathworks.com/"
    },
    1947: {
        "description": "SentinelLM License Manager",
        "details": "Sentinel License Manager for software licensing.",
        "security": "MEDIUM RISK - Software license server",
        "link": "https://www.gemalto.com/"
    },
    7070: {
        "description": "ANSYS License Manager",
        "details": "ANSYS engineering simulation license server.",
        "security": "MEDIUM RISK - Engineering software licensing",
        "link": "https://www.ansys.com/"
    },
    1999: {
        "description": "Cisco AuthProxy",
        "details": "Cisco authentication proxy service.",
        "security": "HIGH RISK - Network device authentication",
        "link": "https://www.cisco.com/"
    },
    
    # Multimedia & Streaming Services (12 ports)
    1755: {
        "description": "Microsoft Media Server (duplicate - will be updated)",
        "details": "Microsoft Windows Media Services streaming.",
        "security": "MEDIUM RISK - Media streaming",
        "link": "https://docs.microsoft.com/en-us/windows/win32/wmformat/"
    },
    8554: {
        "description": "RTSP Alternative",
        "details": "Real Time Streaming Protocol alternative port.",
        "security": "MEDIUM RISK - Media streaming control",
        "link": "https://tools.ietf.org/html/rfc2326"
    },
    10080: {
        "description": "MyQ Print Server",
        "details": "MyQ print management server.",
        "security": "MEDIUM RISK - Print management system",
        "link": "https://www.myq-solution.com/"
    },
    9090: {
        "description": "Openfire Admin Console (duplicate - will be updated)",
        "details": "Openfire XMPP server administration.",
        "security": "HIGH RISK - XMPP server administration",
        "link": "https://www.igniterealtime.org/projects/openfire/"
    },
    5222: {
        "description": "XMPP Client Connection",
        "details": "Extensible Messaging and Presence Protocol client.",
        "security": "MEDIUM RISK - XMPP messaging",
        "link": "https://xmpp.org/"
    },
    5223: {
        "description": "XMPP Client SSL",
        "details": "XMPP client connection over SSL.",
        "security": "SECURE - Encrypted XMPP messaging",
        "link": "https://xmpp.org/"
    },
    5269: {
        "description": "XMPP Server-to-Server",
        "details": "XMPP server-to-server communication.",
        "security": "MEDIUM RISK - XMPP federation",
        "link": "https://xmpp.org/"
    },
    5280: {
        "description": "XMPP BOSH",
        "details": "XMPP BOSH (Bidirectional-streams Over Synchronous HTTP).",
        "security": "MEDIUM RISK - XMPP over HTTP",
        "link": "https://xmpp.org/"
    },
    8010: {
        "description": "XMPP File Transfer Proxy",
        "details": "XMPP file transfer proxy service.",
        "security": "MEDIUM RISK - XMPP file sharing",
        "link": "https://xmpp.org/"
    },
    7777: {
        "description": "Oracle iSQL*Plus (duplicate - will be updated)",
        "details": "Oracle iSQL*Plus web interface (legacy).",
        "security": "HIGH RISK - Legacy Oracle web interface",
        "link": "https://www.oracle.com/"
    },
    1521: {
        "description": "Oracle Listener (duplicate - will be updated)",
        "details": "Oracle Database listener service.",
        "security": "HIGH RISK - Oracle database",
        "link": "https://www.oracle.com/"
    },
    8002: {
        "description": "Teradata Database",
        "details": "Teradata enterprise data warehouse database.",
        "security": "HIGH RISK - Enterprise data warehouse",
        "link": "https://www.teradata.com/"
    },
    
    # Network Attached Storage & File Services (8 ports)
    548: {
        "description": "AFP - Apple Filing Protocol",
        "details": "Apple Filing Protocol for macOS file sharing.",
        "security": "MEDIUM RISK - Apple file sharing",
        "link": "https://developer.apple.com/library/archive/documentation/Networking/Conceptual/AFP/"
    },
    2049: {
        "description": "NFS (duplicate - will be updated)",
        "details": "Network File System for Unix/Linux file sharing.",
        "security": "HIGH RISK - Network file sharing",
        "link": "https://tools.ietf.org/html/rfc7530"
    },
    5353: {
        "description": "Bonjour/mDNS (duplicate - will be updated)",
        "details": "Apple Bonjour service discovery protocol.",
        "security": "LOW RISK - Service discovery",
        "link": "https://developer.apple.com/bonjour/"
    },
    5000: {
        "description": "QNAP NAS (duplicate - will be updated)",
        "details": "QNAP Network Attached Storage web interface.",
        "security": "HIGH RISK - NAS administration",
        "link": "https://www.qnap.com/"
    },
    8080: {
        "description": "QNAP File Station (duplicate - will be updated)",
        "details": "QNAP File Station web interface.",
        "security": "MEDIUM RISK - File management interface",
        "link": "https://www.qnap.com/"
    },
    443: {
        "description": "QNAP NAS HTTPS (duplicate - will be updated)",
        "details": "QNAP NAS secure web interface.",
        "security": "MEDIUM RISK - Encrypted NAS administration",
        "link": "https://www.qnap.com/"
    },
    9981: {
        "description": "Tvheadend",
        "details": "Tvheadend TV streaming server.",
        "security": "MEDIUM RISK - TV streaming server",
        "link": "https://tvheadend.org/"
    },
    9982: {
        "description": "Tvheadend HTSP",
        "details": "Tvheadend Home TV Streaming Protocol.",
        "security": "MEDIUM RISK - TV streaming protocol",
        "link": "https://tvheadend.org/"
    },
    
    # Additional Enterprise & Specialized Services (remaining ports to complete 100+)
    8140: {
        "description": "Puppet Master",
        "details": "Puppet configuration management master server.",
        "security": "HIGH RISK - Infrastructure automation",
        "link": "https://puppet.com/"
    },
    8141: {
        "description": "Puppet Certificate Authority",
        "details": "Puppet CA service for certificate management.",
        "security": "HIGH RISK - Certificate authority",
        "link": "https://puppet.com/"
    },
    4505: {
        "description": "SaltStack Publisher",
        "details": "SaltStack configuration management publisher.",
        "security": "HIGH RISK - Infrastructure automation",
        "link": "https://saltproject.io/"
    },
    4506: {
        "description": "SaltStack Return",
        "details": "SaltStack return server for job results.",
        "security": "HIGH RISK - Infrastructure automation",
        "link": "https://saltproject.io/"
    },
    5985: {
        "description": "WinRM HTTP (duplicate - will be updated)",
        "details": "Windows Remote Management HTTP.",
        "security": "HIGH RISK - Windows remote management",
        "link": "https://docs.microsoft.com/en-us/windows/win32/winrm/"
    },
    5986: {
        "description": "WinRM HTTPS (duplicate - will be updated)",
        "details": "Windows Remote Management HTTPS.",
        "security": "MEDIUM RISK - Encrypted Windows management",
        "link": "https://docs.microsoft.com/en-us/windows/win32/winrm/"
    },
    9997: {
        "description": "Splunk Web",
        "details": "Splunk Enterprise web interface.",
        "security": "HIGH RISK - Security analytics platform",
        "link": "https://www.splunk.com/"
    },
    9998: {
        "description": "Splunk Deployment Server",
        "details": "Splunk deployment server for app distribution.",
        "security": "HIGH RISK - Security tool deployment",
        "link": "https://www.splunk.com/"
    },
    8089: {
        "description": "Splunk Management (duplicate - will be updated)",
        "details": "Splunk management and API interface.",
        "security": "HIGH RISK - Security analytics API",
        "link": "https://www.splunk.com/"
    },
    514: {
        "description": "Splunk Syslog (duplicate - will be updated)",
        "details": "Splunk syslog input receiver.",
        "security": "MEDIUM RISK - Log collection",
        "link": "https://www.splunk.com/"
    },
    8191: {
        "description": "Tandberg Video Conferencing",
        "details": "Tandberg/Cisco video conferencing system.",
        "security": "MEDIUM RISK - Video conferencing",
        "link": "https://www.cisco.com/"
    },
    1719: {
        "description": "H.323 Gatekeeper",
        "details": "H.323 gatekeeper registration and discovery.",
        "security": "MEDIUM RISK - VoIP gatekeeper",
        "link": "https://www.itu.int/rec/T-REC-H.323/"
    },
    5060: {
        "description": "SIP (duplicate - will be updated)",
        "details": "Session Initiation Protocol for VoIP.",
        "security": "MEDIUM RISK - VoIP signaling",
        "link": "https://tools.ietf.org/html/rfc3261"
    },
    5061: {
        "description": "SIP-TLS",
        "details": "SIP over TLS for secure VoIP signaling.",
        "security": "SECURE - Encrypted VoIP signaling",
        "link": "https://tools.ietf.org/html/rfc3261"
    },
    1720: {
        "description": "H.323 (duplicate - will be updated)",
        "details": "H.323 call signaling for video conferencing.",
        "security": "MEDIUM RISK - Video conferencing protocol",
        "link": "https://www.itu.int/rec/T-REC-H.323/"
    },
    5004: {
        "description": "RTP (duplicate - will be updated)",
        "details": "Real-time Transport Protocol for media streams.",
        "security": "LOW RISK - Media streaming",
        "link": "https://tools.ietf.org/html/rfc3550"
    },
    10162: {
        "description": "SNMP-TLS",
        "details": "SNMP over TLS for secure network management.",
        "security": "SECURE - Encrypted network management",
        "link": "https://tools.ietf.org/html/rfc6353"
    },
    10161: {
        "description": "SNMP-DTLS",
        "details": "SNMP over DTLS for secure network management.",
        "security": "SECURE - Encrypted network monitoring",
        "link": "https://tools.ietf.org/html/rfc6353"
    },
    8194: {
        "description": "Bloomberg Terminal",
        "details": "Bloomberg Professional Service terminal.",
        "security": "HIGH RISK - Financial data service",
        "link": "https://www.bloomberg.com/professional/"
    },
    8195: {
        "description": "Bloomberg FIX Gateway",
        "details": "Bloomberg Financial Information eXchange gateway.",
        "security": "HIGH RISK - Financial trading protocol",
        "link": "https://www.bloomberg.com/"
    },
    7496: {
        "description": "Interactive Brokers TWS",
        "details": "Interactive Brokers Trader Workstation API.",
        "security": "HIGH RISK - Trading platform API",
        "link": "https://www.interactivebrokers.com/"
    },
    4001: {
        "description": "Financial Trading System (duplicate - will be updated)",
        "details": "Generic financial trading system port.",
        "security": "HIGH RISK - Financial trading",
        "link": "https://en.wikipedia.org/wiki/Electronic_trading_platform"
    },
    4002: {
        "description": "Financial Market Data",
        "details": "Financial market data feed service.",
        "security": "HIGH RISK - Market data distribution",
        "link": "https://en.wikipedia.org/wiki/Market_data"
    },
    8765: {
        "description": "Ultraseek",
        "details": "Ultraseek search engine (legacy).",
        "security": "LOW RISK - Legacy search engine",
        "link": "https://en.wikipedia.org/wiki/Ultraseek"
    },
    7777: {
        "description": "Game Server Generic (duplicate - will be updated)",
        "details": "Generic game server port (multiple games).",
        "security": "LOW RISK - Game server",
        "link": "https://en.wikipedia.org/wiki/Game_server"
    },
    27015: {
        "description": "Source Engine Games",
        "details": "Valve Source Engine game server (CS:GO, TF2, etc.).",
        "security": "LOW RISK - Game server",
        "link": "https://developer.valvesoftware.com/"
    },
    27016: {
        "description": "Source Engine GOTV",
        "details": "Source Engine GOTV spectator service.",
        "security": "LOW RISK - Game spectating",
        "link": "https://developer.valvesoftware.com/"
    },
    27017: {
        "description": "MongoDB (duplicate - will be updated)",
        "details": "MongoDB NoSQL database default port.",
        "security": "HIGH RISK - Document database",
        "link": "https://www.mongodb.com/"
    },
    64738: {
        "description": "Mumble Voice Chat (duplicate - will be updated)",
        "details": "Mumble voice communication server.",
        "security": "LOW RISK - Voice communication",
        "link": "https://www.mumble.info/"
    },
    25826: {
        "description": "collectd",
        "details": "collectd system statistics collection daemon.",
        "security": "MEDIUM RISK - System monitoring",
        "link": "https://collectd.org/"
    },
    8200: {
        "description": "HashiCorp Vault (duplicate - will be updated)",
        "details": "HashiCorp Vault secrets management.",
        "security": "HIGH RISK - Secrets management",
        "link": "https://www.vaultproject.io/"
    },
    
    # Common Ports from TOP_750_PORTS - Missing Essential Services (100 ports)
    # Core Internet Services
    211: {
        "description": "RFC 911 - Network System",
        "details": "RFC 911 network system protocol (rarely used).",
        "security": "LOW RISK - Legacy protocol",
        "link": "https://tools.ietf.org/html/rfc911"
    },
    212: {
        "description": "ANET",
        "details": "ANET protocol for network communication.",
        "security": "MEDIUM RISK - Network protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    254: {
        "description": "RFC 3692-style Experiment",
        "details": "Reserved for RFC 3692-style protocol experiments.",
        "security": "LOW RISK - Experimental protocol",
        "link": "https://tools.ietf.org/html/rfc3692"
    },
    255: {
        "description": "RFC 3692-style Experiment 2",
        "details": "Reserved for RFC 3692-style protocol experiments.",
        "security": "LOW RISK - Experimental protocol",
        "link": "https://tools.ietf.org/html/rfc3692"
    },
    256: {
        "description": "2DEV",
        "details": "2DEV protocol for device communication.",
        "security": "MEDIUM RISK - Device protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    259: {
        "description": "ESRO",
        "details": "Efficient Short Remote Operations protocol.",
        "security": "MEDIUM RISK - Remote operations",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    264: {
        "description": "BGMP",
        "details": "Border Gateway Multicast Protocol.",
        "security": "HIGH RISK - Routing protocol",
        "link": "https://tools.ietf.org/html/rfc3973"
    },
    280: {
        "description": "HTTP-mgmt",
        "details": "HTTP management protocol.",
        "security": "MEDIUM RISK - HTTP management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    301: {
        "description": "Link",
        "details": "Link protocol for network connections.",
        "security": "MEDIUM RISK - Network linking",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    306: {
        "description": "Location Service",
        "details": "Location service for network resources.",
        "security": "MEDIUM RISK - Location service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    311: {
        "description": "AppleShare IP WebAdmin",
        "details": "Apple file sharing web administration.",
        "security": "MEDIUM RISK - Apple file sharing admin",
        "link": "https://support.apple.com/"
    },
    340: {
        "description": "PAWSERV",
        "details": "Perf Analysis Workbench server.",
        "security": "MEDIUM RISK - Performance analysis",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    406: {
        "description": "IMSP",
        "details": "Interactive Mail Support Protocol.",
        "security": "MEDIUM RISK - Mail support protocol",
        "link": "https://tools.ietf.org/html/rfc2060"
    },
    407: {
        "description": "TIMBUKTU",
        "details": "Timbuktu remote control software.",
        "security": "HIGH RISK - Remote control software",
        "link": "https://en.wikipedia.org/wiki/Timbuktu_(software)"
    },
    416: {
        "description": "Silverplatter",
        "details": "Silverplatter information retrieval system.",
        "security": "LOW RISK - Information retrieval",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    417: {
        "description": "ONP",
        "details": "Onyx Network Protocol.",
        "security": "MEDIUM RISK - Network protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    425: {
        "description": "ICAD-EL",
        "details": "ICAD-EL CAD/CAM software protocol.",
        "security": "MEDIUM RISK - CAD/CAM software",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    427: {
        "description": "Service Location Protocol",
        "details": "SLP for service discovery in IP networks.",
        "security": "MEDIUM RISK - Service discovery",
        "link": "https://tools.ietf.org/html/rfc2608"
    },
    458: {
        "description": "Apple QuickTime",
        "details": "Apple QuickTime streaming server.",
        "security": "MEDIUM RISK - Media streaming",
        "link": "https://support.apple.com/quicktime"
    },
    481: {
        "description": "Ph service",
        "details": "Ph directory service protocol.",
        "security": "MEDIUM RISK - Directory service",
        "link": "https://tools.ietf.org/html/rfc2378"
    },
    497: {
        "description": "Retrospect",
        "details": "Retrospect backup software agent.",
        "security": "MEDIUM RISK - Backup software",
        "link": "https://www.retrospect.com/"
    },
    541: {
        "description": "UUCP-rlogin",
        "details": "UUCP remote login service.",
        "security": "HIGH RISK - Legacy remote login",
        "link": "https://en.wikipedia.org/wiki/UUCP"
    },
    545: {
        "description": "OSI-COTS",
        "details": "OSI Connection-Oriented Transport Service.",
        "security": "MEDIUM RISK - Transport protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    
    # System and Database Ports (1000-2000 range)
    1000: {
        "description": "Cadlock/KCMS",
        "details": "Cadlock license server or KCMS color management.",
        "security": "MEDIUM RISK - License/color management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1001: {
        "description": "Web/HTTP Alternative",
        "details": "Alternative web server port.",
        "security": "MEDIUM RISK - Alternative web service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1002: {
        "description": "Windows Messenger",
        "details": "Windows Messenger service (legacy).",
        "security": "LOW RISK - Legacy messaging",
        "link": "https://support.microsoft.com/"
    },
    1007: {
        "description": "Unknown Service",
        "details": "Unassigned port commonly scanned.",
        "security": "UNKNOWN - Unassigned port",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1009: {
        "description": "Unknown Service 2",
        "details": "Unassigned port commonly scanned.",
        "security": "UNKNOWN - Unassigned port",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1010: {
        "description": "ThinLinc Web Access",
        "details": "ThinLinc remote desktop web access.",
        "security": "MEDIUM RISK - Remote desktop access",
        "link": "https://www.cendio.com/"
    },
    1011: {
        "description": "Unknown Service 3",
        "details": "Unassigned port commonly scanned.",
        "security": "UNKNOWN - Unassigned port",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1021: {
        "description": "RFC3692 Experiment",
        "details": "Reserved for experimental protocols.",
        "security": "LOW RISK - Experimental use",
        "link": "https://tools.ietf.org/html/rfc3692"
    },
    1022: {
        "description": "RFC3692 Experiment 2",
        "details": "Reserved for experimental protocols.",
        "security": "LOW RISK - Experimental use",
        "link": "https://tools.ietf.org/html/rfc3692"
    },
    1023: {
        "description": "Reserved",
        "details": "Reserved port, end of well-known ports range.",
        "security": "LOW RISK - Reserved port",
        "link": "https://tools.ietf.org/html/rfc6335"
    },
    1024: {
        "description": "Dynamic Port Start (duplicate - will be updated)",
        "details": "Start of dynamic/private port range.",
        "security": "MEDIUM RISK - Dynamic port range",
        "link": "https://tools.ietf.org/html/rfc6335"
    },
    1025: {
        "description": "Microsoft RPC",
        "details": "Microsoft RPC endpoint mapper (dynamic).",
        "security": "HIGH RISK - Windows RPC",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    1026: {
        "description": "Windows Messenger Service",
        "details": "Windows network messenger (legacy).",
        "security": "MEDIUM RISK - Windows networking",
        "link": "https://support.microsoft.com/"
    },
    1027: {
        "description": "ICQ/AOL IM",
        "details": "ICQ or AOL Instant Messenger service.",
        "security": "LOW RISK - Legacy instant messaging",
        "link": "https://www.icq.com/"
    },
    1028: {
        "description": "MS Exchange",
        "details": "Microsoft Exchange Server communication.",
        "security": "HIGH RISK - Email server",
        "link": "https://www.microsoft.com/microsoft-365/exchange/"
    },
    1029: {
        "description": "Solid Mux Server",
        "details": "Solid database multiplexer server.",
        "security": "HIGH RISK - Database multiplexer",
        "link": "https://www.openlinksw.com/"
    },
    1030: {
        "description": "BBN IAD",
        "details": "BBN Integrated Access Device protocol.",
        "security": "MEDIUM RISK - Network access device",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    
    # Application and Web Services (2000-3000 range) 
    2001: {
        "description": "Cisco SCCP/Skinny",
        "details": "Cisco Skinny Client Control Protocol alternative port.",
        "security": "MEDIUM RISK - Cisco IP phone protocol",
        "link": "https://www.cisco.com/"
    },
    2002: {
        "description": "Globe/EFS",
        "details": "Globe network file system or EFS.",
        "security": "MEDIUM RISK - Network file system",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2005: {
        "description": "Encrypted Login",
        "details": "Berkeley encrypted login service.",
        "security": "SECURE - Encrypted login",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2006: {
        "description": "Invokana",
        "details": "Invokana application protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2007: {
        "description": "Dectalk",
        "details": "Digital speech synthesis protocol.",
        "security": "LOW RISK - Speech synthesis",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2008: {
        "description": "Conf",
        "details": "Conference calling protocol.",
        "security": "MEDIUM RISK - Conference calling",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2009: {
        "description": "News",
        "details": "Network news protocol.",
        "security": "LOW RISK - News protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2010: {
        "description": "Search",
        "details": "Network search protocol.",
        "security": "MEDIUM RISK - Search protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2013: {
        "description": "RAID CC",
        "details": "RAID Controller Control protocol.",
        "security": "HIGH RISK - Storage controller",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2020: {
        "description": "Xinupageserver",
        "details": "Xinupageserver paging protocol.",
        "security": "MEDIUM RISK - Paging service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2021: {
        "description": "ServServ",
        "details": "Server service protocol.",
        "security": "MEDIUM RISK - Server service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2022: {
        "description": "Down",
        "details": "Down network protocol.",
        "security": "MEDIUM RISK - Network protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2030: {
        "description": "Device2",
        "details": "Device communication protocol v2.",
        "security": "MEDIUM RISK - Device communication",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2033: {
        "description": "GLOGGER",
        "details": "General logging protocol.",
        "security": "MEDIUM RISK - Logging service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2034: {
        "description": "SCOREMGR",
        "details": "Score manager protocol.",
        "security": "MEDIUM RISK - Score management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2035: {
        "description": "IMSLDOC",
        "details": "IMSL documentation protocol.",
        "security": "LOW RISK - Documentation service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2038: {
        "description": "Objectmanager",
        "details": "Object manager protocol.",
        "security": "MEDIUM RISK - Object management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2040: {
        "description": "lam",
        "details": "LAM message passing protocol.",
        "security": "MEDIUM RISK - Message passing",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2041: {
        "description": "interbase",
        "details": "InterBase database server.",
        "security": "HIGH RISK - Database server",
        "link": "https://www.embarcadero.com/products/interbase"
    },
    2042: {
        "description": "isis",
        "details": "ISIS distributed information system.",
        "security": "MEDIUM RISK - Information system",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2043: {
        "description": "isis-bcast",
        "details": "ISIS broadcast protocol.",
        "security": "MEDIUM RISK - Broadcast protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2045: {
        "description": "RADIUS Proxy",
        "details": "RADIUS authentication proxy.",
        "security": "MEDIUM RISK - Authentication proxy",
        "link": "https://tools.ietf.org/html/rfc2865"
    },
    2046: {
        "description": "sdfunc",
        "details": "SDF function protocol.",
        "security": "MEDIUM RISK - Function protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2047: {
        "description": "dls",
        "details": "Data Location Service.",
        "security": "MEDIUM RISK - Data location",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2065: {
        "description": "DLSw",
        "details": "Data Link Switching protocol.",
        "security": "MEDIUM RISK - Data link switching",
        "link": "https://tools.ietf.org/html/rfc1434"
    },
    2068: {
        "description": "HTTP Alternative",
        "details": "Alternative HTTP port.",
        "security": "MEDIUM RISK - Alternative web service",
        "link": "https://tools.ietf.org/html/rfc2616"
    },
    2099: {
        "description": "H.323 AnnexE",
        "details": "H.323 Annex E protocol.",
        "security": "MEDIUM RISK - Video conferencing",
        "link": "https://www.itu.int/rec/T-REC-H.323/"
    },
    2100: {
        "description": "OSU-NMS",
        "details": "OSU Network Management System.",
        "security": "MEDIUM RISK - Network management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2103: {
        "description": "Zephyr-clt",
        "details": "Zephyr notification client.",
        "security": "MEDIUM RISK - Notification client",
        "link": "https://zephyr.1ts.org/"
    },
    2105: {
        "description": "EKSHELL",
        "details": "Emacs Kshell protocol.",
        "security": "MEDIUM RISK - Emacs shell",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2106: {
        "description": "EKLOGIN",
        "details": "Emacs Klogin protocol.",
        "security": "MEDIUM RISK - Emacs login",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2107: {
        "description": "BinTec-ADMIN",
        "details": "BinTec administration protocol.",
        "security": "HIGH RISK - Device administration",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2111: {
        "description": "KNETD",
        "details": "Kerberos network daemon.",
        "security": "MEDIUM RISK - Kerberos daemon",
        "link": "https://web.mit.edu/kerberos/"
    },
    2119: {
        "description": "GSIGATEKEEPER",
        "details": "GSI gatekeeper protocol.",
        "security": "MEDIUM RISK - GSI gatekeeper",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2126: {
        "description": "PktCable-COPS",
        "details": "PacketCable COPS protocol.",
        "security": "MEDIUM RISK - Cable protocol",
        "link": "https://www.cablelabs.com/"
    },
    2135: {
        "description": "Grid Resource Information Service",
        "details": "Grid computing resource information.",
        "security": "MEDIUM RISK - Grid computing",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2144: {
        "description": "Live Vault",
        "details": "Live Vault backup service.",
        "security": "MEDIUM RISK - Backup service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2160: {
        "description": "APC PowerChute",
        "details": "APC PowerChute UPS management.",
        "security": "HIGH RISK - UPS management",
        "link": "https://www.apc.com/"
    },
    2161: {
        "description": "APC Agent",
        "details": "APC monitoring agent.",
        "security": "MEDIUM RISK - UPS monitoring",
        "link": "https://www.apc.com/"
    },
    
    # Development and Remote Access (3000-4000 range)
    3002: {
        "description": "EXLM Agent",
        "details": "EXLM license manager agent.",
        "security": "MEDIUM RISK - License management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3004: {
        "description": "CSOFTRAGENT",
        "details": "CSoft license agent.",
        "security": "MEDIUM RISK - License agent",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3005: {
        "description": "Geniuslm",
        "details": "Genius license manager.",
        "security": "MEDIUM RISK - License manager",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3006: {
        "description": "ii-admin",
        "details": "Instant Internet admin protocol.",
        "security": "HIGH RISK - Internet administration",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3007: {
        "description": "Lotus Mail Tracking",
        "details": "Lotus mail tracking agent.",
        "security": "MEDIUM RISK - Mail tracking",
        "link": "https://www.ibm.com/products/domino"
    },
    3011: {
        "description": "Trusted Web",
        "details": "Trusted web client protocol.",
        "security": "MEDIUM RISK - Trusted web protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3013: {
        "description": "Gilat Sky Surfer",
        "details": "Gilat satellite internet protocol.",
        "security": "MEDIUM RISK - Satellite internet",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3017: {
        "description": "Event Listener",
        "details": "Event listener protocol.",
        "security": "MEDIUM RISK - Event monitoring",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3031: {
        "description": "AgentVU",
        "details": "AgentVU monitoring protocol.",
        "security": "MEDIUM RISK - Monitoring agent",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3052: {
        "description": "PowerChute",
        "details": "APC PowerChute network shutdown.",
        "security": "HIGH RISK - UPS network shutdown",
        "link": "https://www.apc.com/"
    },
    3071: {
        "description": "ContinuStor",
        "details": "ContinuStor backup protocol.",
        "security": "MEDIUM RISK - Backup protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3077: {
        "description": "Orbix Locator SSL",
        "details": "Orbix CORBA locator over SSL.",
        "security": "SECURE - Encrypted CORBA",
        "link": "https://www.microfocus.com/"
    },
    3128: {
        "description": "Squid Web Proxy",
        "details": "Squid HTTP proxy cache server.",
        "security": "MEDIUM RISK - Web proxy cache",
        "link": "http://www.squid-cache.org/"
    },
    3168: {
        "description": "POWERONNUD",
        "details": "PowerON network utility daemon.",
        "security": "MEDIUM RISK - Network utility",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3211: {
        "description": "Avsecuremgmt",
        "details": "Avocent secure management.",
        "security": "HIGH RISK - Secure management",
        "link": "https://www.vertiv.com/"
    },
    3221: {
        "description": "XNMP",
        "details": "XML Network Management Protocol.",
        "security": "MEDIUM RISK - Network management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3260: {
        "description": "iSCSI Target",
        "details": "Internet Small Computer Systems Interface.",
        "security": "HIGH RISK - Storage area network",
        "link": "https://tools.ietf.org/html/rfc7143"
    },
    3261: {
        "description": "Winshadow",
        "details": "WinShadow remote control.",
        "security": "HIGH RISK - Remote control software",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3268: {
        "description": "Active Directory Global Catalog",
        "details": "Microsoft Active Directory global catalog.",
        "security": "HIGH RISK - Directory service",
        "link": "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/"
    },
    3269: {
        "description": "Active Directory Global Catalog SSL",
        "details": "AD global catalog over SSL/TLS.",
        "security": "MEDIUM RISK - Encrypted directory service",
        "link": "https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/"
    },
    3283: {
        "description": "Net Assistant",
        "details": "Apple Net Assistant remote desktop.",
        "security": "HIGH RISK - Remote desktop",
        "link": "https://support.apple.com/"
    },
    
    # More TOP_750 Essential Services (Final batch)
    3301: {
        "description": "Nest Protocol",
        "details": "Nest home automation protocol.",
        "security": "MEDIUM RISK - Home automation",
        "link": "https://nest.com/"
    },
    3322: {
        "description": "Active Networks",
        "details": "Active networks protocol.",
        "security": "MEDIUM RISK - Active networking",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3323: {
        "description": "Active Net Connector",
        "details": "Active network connector service.",
        "security": "MEDIUM RISK - Network connector",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3324: {
        "description": "Active Net Admin",
        "details": "Active network administration.",
        "security": "HIGH RISK - Network administration",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3325: {
        "description": "Active Central",
        "details": "Active central management.",
        "security": "HIGH RISK - Central management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3333: {
        "description": "DEC Notes",
        "details": "DEC Notes collaboration software.",
        "security": "MEDIUM RISK - Collaboration software",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3351: {
        "description": "Btrieve",
        "details": "Pervasive Btrieve database engine.",
        "security": "HIGH RISK - Database engine",
        "link": "https://www.pervasive.com/"
    },
    3367: {
        "description": "Content Server",
        "details": "Content management server.",
        "security": "MEDIUM RISK - Content management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3369: {
        "description": "Content Manager",
        "details": "Content management protocol.",
        "security": "MEDIUM RISK - Content management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3370: {
        "description": "UDT OS",
        "details": "UDT operating system protocol.",
        "security": "MEDIUM RISK - Operating system",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3371: {
        "description": "CRYPTOCard",
        "details": "CRYPTOCard authentication protocol.",
        "security": "SECURE - Authentication token",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3372: {
        "description": "MCS Messaging",
        "details": "MCS messaging service.",
        "security": "MEDIUM RISK - Messaging service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3404: {
        "description": "HACE-LM",
        "details": "HACE license manager.",
        "security": "MEDIUM RISK - License manager",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3476: {
        "description": "NPPMP",
        "details": "Network Printing Protocol Management.",
        "security": "MEDIUM RISK - Print management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3493: {
        "description": "Network Object Broker",
        "details": "Network object broker protocol.",
        "security": "MEDIUM RISK - Object broker",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3517: {
        "description": "802.11 WiMax",
        "details": "WiMAX network protocol.",
        "security": "MEDIUM RISK - Wireless networking",
        "link": "https://www.wimaxforum.org/"
    },
    3527: {
        "description": "BEEP XML",
        "details": "BEEP XML messaging protocol.",
        "security": "MEDIUM RISK - XML messaging",
        "link": "https://tools.ietf.org/html/rfc3080"
    },
    3546: {
        "description": "LAN Rover",
        "details": "LAN Rover remote access.",
        "security": "HIGH RISK - Remote access",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3551: {
        "description": "Apcupsd",
        "details": "APC UPS daemon.",
        "security": "MEDIUM RISK - UPS monitoring",
        "link": "http://www.apcupsd.org/"
    },
    3580: {
        "description": "IANA-RIR-TRANS",
        "details": "IANA RIR transfer protocol.",
        "security": "MEDIUM RISK - Registry transfer",
        "link": "https://www.iana.org/"
    },
    3659: {
        "description": "Apple Remote Desktop",
        "details": "Apple Remote Desktop VNC service.",
        "security": "HIGH RISK - Remote desktop",
        "link": "https://support.apple.com/remote-desktop/"
    },
    3689: {
        "description": "DAAP - iTunes",
        "details": "Digital Audio Access Protocol (iTunes sharing).",
        "security": "LOW RISK - Media sharing",
        "link": "https://support.apple.com/itunes/"
    },
    3690: {
        "description": "Subversion",
        "details": "Apache Subversion version control.",
        "security": "MEDIUM RISK - Version control",
        "link": "https://subversion.apache.org/"
    },
    3703: {
        "description": "Adobe Server 1",
        "details": "Adobe application server.",
        "security": "MEDIUM RISK - Adobe application",
        "link": "https://www.adobe.com/"
    },
    3737: {
        "description": "WinVNC",
        "details": "WinVNC remote desktop service.",
        "security": "HIGH RISK - Remote desktop",
        "link": "https://www.realvnc.com/"
    },
    3766: {
        "description": "SSL VPN",
        "details": "SSL VPN service.",
        "security": "SECURE - VPN service",
        "link": "https://en.wikipedia.org/wiki/SSL_VPN"
    },
    3784: {
        "description": "BFD Control",
        "details": "Bidirectional Forwarding Detection control.",
        "security": "MEDIUM RISK - Network monitoring",
        "link": "https://tools.ietf.org/html/rfc5880"
    },
    3800: {
        "description": "pwgpsi",
        "details": "Printer Working Group Protocol Service.",
        "security": "MEDIUM RISK - Printer service",
        "link": "https://www.pwg.org/"
    },
    3801: {
        "description": "IBM Manager",
        "details": "IBM management protocol.",
        "security": "HIGH RISK - IBM management",
        "link": "https://www.ibm.com/"
    },
    3809: {
        "description": "apocd",
        "details": "APO Change Director.",
        "security": "MEDIUM RISK - Change management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3814: {
        "description": "netboot-pxe",
        "details": "Network boot PXE service.",
        "security": "HIGH RISK - Network booting",
        "link": "https://en.wikipedia.org/wiki/Preboot_Execution_Environment"
    },
    3826: {
        "description": "WarMUX",
        "details": "WarMUX game server.",
        "security": "LOW RISK - Game server",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3827: {
        "description": "netmpi",
        "details": "Network MPI (Message Passing Interface).",
        "security": "MEDIUM RISK - Parallel computing",
        "link": "https://www.mpi-forum.org/"
    },
    3828: {
        "description": "neteh",
        "details": "Network event handler.",
        "security": "MEDIUM RISK - Event handling",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3851: {
        "description": "SpectraGuard",
        "details": "SpectraGuard security protocol.",
        "security": "MEDIUM RISK - Security protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3869: {
        "description": "OVSAM-MGMT",
        "details": "OVSAM management protocol.",
        "security": "HIGH RISK - System management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3871: {
        "description": "AVOCENT-DSRVR",
        "details": "Avocent directory server.",
        "security": "HIGH RISK - Directory server",
        "link": "https://www.vertiv.com/"
    },
    3878: {
        "description": "FOTOGCAD",
        "details": "FotoG CAD protocol.",
        "security": "MEDIUM RISK - CAD application",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3880: {
        "description": "IGRS",
        "details": "Intelligent Grouping and Resource Sharing.",
        "security": "MEDIUM RISK - Resource sharing",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3889: {
        "description": "SteelCentral",
        "details": "Riverbed SteelCentral monitoring.",
        "security": "MEDIUM RISK - Network monitoring",
        "link": "https://www.riverbed.com/"
    },
    3905: {
        "description": "mupdate",
        "details": "Cyrus IMAP mupdate protocol.",
        "security": "MEDIUM RISK - IMAP management",
        "link": "https://www.cyrusimap.org/"
    },
    3914: {
        "description": "listcrt-port",
        "details": "List certificate port.",
        "security": "MEDIUM RISK - Certificate service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3918: {
        "description": "pktcablemmcops",
        "details": "PacketCable multimedia COPS.",
        "security": "MEDIUM RISK - Cable multimedia",
        "link": "https://www.cablelabs.com/"
    },
    3920: {
        "description": "exasoftport1",
        "details": "Exasoft application port.",
        "security": "MEDIUM RISK - Application service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3945: {
        "description": "EMCADS",
        "details": "EMC Automated Data Storage.",
        "security": "HIGH RISK - Storage management",
        "link": "https://www.dell.com/emc"
    },
    3971: {
        "description": "LANrev Agent",
        "details": "LANrev system management agent.",
        "security": "HIGH RISK - System management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3986: {
        "description": "MAPPER-WS_ETHD",
        "details": "MAPPER workstation ethernet.",
        "security": "MEDIUM RISK - Workstation service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    3995: {
        "description": "ISC Bind",
        "details": "ISC BIND DNS server control.",
        "security": "HIGH RISK - DNS server control",
        "link": "https://www.isc.org/bind/"
    },
    3998: {
        "description": "DNX",
        "details": "Distributed Nagios Executor.",
        "security": "MEDIUM RISK - Monitoring executor",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    
    # Completing TOP_750_PORTS Coverage - All Remaining Ports (172 ports)
    # Essential System Services
    222: {
        "description": "Berkeley rsh-spx",
        "details": "Berkeley remote shell with encryption.",
        "security": "HIGH RISK - Remote shell service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    
    # Dynamic Port Range 1031-1099 (Common Windows/Enterprise Services)
    1031: {
        "description": "Windows Dynamic RPC",
        "details": "Windows dynamic RPC endpoint.",
        "security": "HIGH RISK - Windows RPC service",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    1032: {
        "description": "Windows Dynamic RPC 2",
        "details": "Windows dynamic RPC endpoint.",
        "security": "HIGH RISK - Windows RPC service",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/"
    },
    1033: {
        "description": "Local InfoFusion",
        "details": "Local InfoFusion service.",
        "security": "MEDIUM RISK - Information service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1034: {
        "description": "ZinfoLock",
        "details": "ZinfoLock service.",
        "security": "MEDIUM RISK - Locking service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1035: {
        "description": "Multi-Tech Systems",
        "details": "Multi-Tech Systems protocol.",
        "security": "MEDIUM RISK - Hardware protocol",
        "link": "https://www.multitech.com/"
    },
    1036: {
        "description": "NSSTP",
        "details": "Nebula Secure Segment Transfer Protocol.",
        "security": "MEDIUM RISK - Secure transfer",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1037: {
        "description": "AMS",
        "details": "AMS application management service.",
        "security": "MEDIUM RISK - Application management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1038: {
        "description": "MTQP",
        "details": "Message Tracking Query Protocol.",
        "security": "MEDIUM RISK - Message tracking",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1039: {
        "description": "SIP",
        "details": "Session Initiation Protocol (alternative port).",
        "security": "MEDIUM RISK - VoIP signaling",
        "link": "https://tools.ietf.org/html/rfc3261"
    },
    1040: {
        "description": "NETSAINT",
        "details": "NetSaint network monitoring (predecessor to Nagios).",
        "security": "MEDIUM RISK - Network monitoring",
        "link": "https://www.nagios.org/"
    },
    1041: {
        "description": "DANF-AK2",
        "details": "DANF-AK2 protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1042: {
        "description": "AFROG",
        "details": "AFROG protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1043: {
        "description": "BOINC Client",
        "details": "Berkeley Open Infrastructure for Network Computing.",
        "security": "LOW RISK - Distributed computing",
        "link": "https://boinc.berkeley.edu/"
    },
    1044: {
        "description": "DCUTILITY",
        "details": "Data center utility protocol.",
        "security": "MEDIUM RISK - Data center management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1045: {
        "description": "Fpitp",
        "details": "Fingerprint identification transfer protocol.",
        "security": "MEDIUM RISK - Biometric protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1046: {
        "description": "WebFilter",
        "details": "Web content filtering service.",
        "security": "MEDIUM RISK - Web filtering",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1047: {
        "description": "Sun Netra",
        "details": "Sun Netra ct800/ct400 server management.",
        "security": "HIGH RISK - Server management",
        "link": "https://www.oracle.com/"
    },
    1048: {
        "description": "Sun Netra Backup",
        "details": "Sun Netra ct backup service.",
        "security": "HIGH RISK - Backup management",
        "link": "https://www.oracle.com/"
    },
    1049: {
        "description": "Tobit David Replica",
        "details": "Tobit David mail replication.",
        "security": "MEDIUM RISK - Mail replication",
        "link": "https://www.tobit.com/"
    },
    1051: {
        "description": "Optima VNET",
        "details": "Optima virtual network service.",
        "security": "MEDIUM RISK - Virtual networking",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1052: {
        "description": "DDT",
        "details": "Dynamic DNS Tools protocol.",
        "security": "MEDIUM RISK - DNS tools",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1053: {
        "description": "Remote Assistant",
        "details": "Remote assistance protocol.",
        "security": "HIGH RISK - Remote assistance",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1054: {
        "description": "BRVREAD",
        "details": "BRVREAD service.",
        "security": "MEDIUM RISK - Read service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1055: {
        "description": "ANSYS License Manager",
        "details": "ANSYS engineering software licensing.",
        "security": "MEDIUM RISK - Software licensing",
        "link": "https://www.ansys.com/"
    },
    1056: {
        "description": "VFO",
        "details": "VFO protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1057: {
        "description": "STARTRON",
        "details": "STARTRON protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1058: {
        "description": "NILSINV",
        "details": "NILS inventory protocol.",
        "security": "MEDIUM RISK - Inventory management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1059: {
        "description": "NIMREG",
        "details": "NIM registry protocol.",
        "security": "MEDIUM RISK - Registry service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1060: {
        "description": "POLESTAR",
        "details": "POLESTAR protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1061: {
        "description": "KIOSK",
        "details": "KIOSK protocol.",
        "security": "MEDIUM RISK - Kiosk management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1062: {
        "description": "Veracity",
        "details": "Veracity protocol.",
        "security": "MEDIUM RISK - Verification service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1063: {
        "description": "KYOCERANETDEV",
        "details": "Kyocera network device management.",
        "security": "MEDIUM RISK - Printer management",
        "link": "https://www.kyocera.com/"
    },
    1064: {
        "description": "JSTEL",
        "details": "JSTEL protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1065: {
        "description": "SYSCOMLAN",
        "details": "SYSCOM LAN protocol.",
        "security": "MEDIUM RISK - LAN management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1066: {
        "description": "FPO-FNS",
        "details": "FPO-FNS protocol.",
        "security": "MEDIUM RISK - File service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1067: {
        "description": "Installation Bootstrap",
        "details": "Installation bootstrap protocol.",
        "security": "HIGH RISK - System installation",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1068: {
        "description": "Installation Bootstrap Reply",
        "details": "Installation bootstrap reply service.",
        "security": "HIGH RISK - System installation",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1069: {
        "description": "COGNEX-INSIGHT",
        "details": "Cognex machine vision system.",
        "security": "MEDIUM RISK - Industrial vision system",
        "link": "https://www.cognex.com/"
    },
    1070: {
        "description": "GMR-UPDATE",
        "details": "GMR update service.",
        "security": "MEDIUM RISK - Update service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1071: {
        "description": "BSQUARE-VOIP",
        "details": "BSQUARE VoIP protocol.",
        "security": "MEDIUM RISK - VoIP service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1072: {
        "description": "CARDAX",
        "details": "CARDAX security system.",
        "security": "HIGH RISK - Security access control",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1073: {
        "description": "BridgeControl",
        "details": "Bridge control protocol.",
        "security": "HIGH RISK - Network bridge control",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1074: {
        "description": "FASTLynx",
        "details": "FASTLynx file transfer.",
        "security": "MEDIUM RISK - File transfer",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1075: {
        "description": "RDRMSHC",
        "details": "RDRMSHC protocol.",
        "security": "MEDIUM RISK - Remote service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1076: {
        "description": "DAB STI-C",
        "details": "Digital Audio Broadcasting Studio-Transmitter Interface.",
        "security": "MEDIUM RISK - Broadcasting protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1077: {
        "description": "IMGames",
        "details": "IMGames online gaming protocol.",
        "security": "LOW RISK - Gaming service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1078: {
        "description": "eManageCstp",
        "details": "eManage CSTP protocol.",
        "security": "MEDIUM RISK - Management protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1079: {
        "description": "ASPROVATalk",
        "details": "ASPROVA talk protocol.",
        "security": "MEDIUM RISK - Communication protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1081: {
        "description": "PVUNIWIEN",
        "details": "PVUNIWIEN protocol.",
        "security": "MEDIUM RISK - University protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1082: {
        "description": "AMT-ESD-PROT",
        "details": "AMT ESD protocol.",
        "security": "MEDIUM RISK - ESD protection",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1083: {
        "description": "Anasoft License Manager",
        "details": "Anasoft license management.",
        "security": "MEDIUM RISK - Software licensing",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1084: {
        "description": "Anasoft License Manager SSL",
        "details": "Anasoft secure license management.",
        "security": "SECURE - Encrypted licensing",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1085: {
        "description": "WebObjects",
        "details": "Apple WebObjects application server.",
        "security": "MEDIUM RISK - Application server",
        "link": "https://en.wikipedia.org/wiki/WebObjects"
    },
    1086: {
        "description": "CPL Scrambler Logging",
        "details": "CPL scrambler logging service.",
        "security": "MEDIUM RISK - Logging service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1087: {
        "description": "CPL Scrambler Internal",
        "details": "CPL scrambler internal service.",
        "security": "MEDIUM RISK - Internal service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1088: {
        "description": "CPL Scrambler External",
        "details": "CPL scrambler external service.",
        "security": "MEDIUM RISK - External service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1089: {
        "description": "FF Annunciation",
        "details": "FF annunciation protocol.",
        "security": "MEDIUM RISK - Notification service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1090: {
        "description": "FF FieldBus Message Specification",
        "details": "Foundation Fieldbus messaging.",
        "security": "HIGH RISK - Industrial fieldbus",
        "link": "https://www.fieldbus.org/"
    },
    1091: {
        "description": "FF System Management",
        "details": "Foundation Fieldbus system management.",
        "security": "HIGH RISK - Industrial system management",
        "link": "https://www.fieldbus.org/"
    },
    1092: {
        "description": "OBRPD",
        "details": "OBRPD protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1093: {
        "description": "PROOFD",
        "details": "PROOF daemon for ROOT data analysis.",
        "security": "MEDIUM RISK - Data analysis",
        "link": "https://root.cern.ch/"
    },
    1094: {
        "description": "ROOTD",
        "details": "ROOT daemon for particle physics data.",
        "security": "MEDIUM RISK - Scientific data",
        "link": "https://root.cern.ch/"
    },
    1095: {
        "description": "NICELink",
        "details": "NICE systems link protocol.",
        "security": "MEDIUM RISK - NICE systems",
        "link": "https://www.nice.com/"
    },
    1096: {
        "description": "Common Name Resolution Protocol",
        "details": "CNRP name resolution protocol.",
        "security": "MEDIUM RISK - Name resolution",
        "link": "https://tools.ietf.org/html/rfc3367"
    },
    1097: {
        "description": "Sun Cluster Manager",
        "details": "Sun Cluster Manager protocol.",
        "security": "HIGH RISK - Cluster management",
        "link": "https://www.oracle.com/"
    },
    1098: {
        "description": "RMI Activation",
        "details": "Java RMI activation daemon.",
        "security": "HIGH RISK - Java RMI service",
        "link": "https://docs.oracle.com/javase/8/docs/platform/rmi/"
    },
    1102: {
        "description": "Adobe Server 3",
        "details": "Adobe application server 3.",
        "security": "MEDIUM RISK - Adobe application",
        "link": "https://www.adobe.com/"
    },
    1104: {
        "description": "XRL",
        "details": "XRL protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1105: {
        "description": "FTRANHC",
        "details": "FTRANHC protocol.",
        "security": "MEDIUM RISK - Transfer protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1106: {
        "description": "ISOIPSIGUA",
        "details": "ISOIPSIGUA protocol.",
        "security": "MEDIUM RISK - ISO protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1107: {
        "description": "ISOIPSIGUA Discovery",
        "details": "ISOIPSIGUA discovery service.",
        "security": "MEDIUM RISK - Discovery service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1108: {
        "description": "Ratio MRP",
        "details": "Ratio Message Routing Protocol.",
        "security": "MEDIUM RISK - Message routing",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    
    # Continuing TOP_750 Coverage - Ports 1110-1600
    1110: {
        "description": "WebAdmin Start",
        "details": "Web-based administration startup.",
        "security": "HIGH RISK - Web administration",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1111: {
        "description": "LMS Socket",
        "details": "License Management System socket.",
        "security": "MEDIUM RISK - License management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1112: {
        "description": "Intelligent Communication Protocol",
        "details": "ICP intelligent communication.",
        "security": "MEDIUM RISK - Communication protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1113: {
        "description": "Licklider Transmission Protocol",
        "details": "LTP for delay-tolerant networking.",
        "security": "MEDIUM RISK - Network transmission",
        "link": "https://tools.ietf.org/html/rfc5326"
    },
    1114: {
        "description": "Mini SQL",
        "details": "Mini SQL database server.",
        "security": "HIGH RISK - Database server",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1117: {
        "description": "ARDUS Multicast Transfer",
        "details": "ARDUS multicast transfer protocol.",
        "security": "MEDIUM RISK - Multicast transfer",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1119: {
        "description": "Battle.net Chat/Game",
        "details": "Blizzard Battle.net chat and game protocol.",
        "security": "LOW RISK - Gaming platform",
        "link": "https://us.battle.net/"
    },
    1121: {
        "description": "Availant-MGR",
        "details": "Availant manager protocol.",
        "security": "MEDIUM RISK - Management service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1122: {
        "description": "availant-htrans",
        "details": "Availant HTTP transfer.",
        "security": "MEDIUM RISK - HTTP transfer",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1123: {
        "description": "Murray Protocol",
        "details": "Murray communication protocol.",
        "security": "MEDIUM RISK - Communication protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1124: {
        "description": "HP VMware License Manager",
        "details": "HP VMware licensing service.",
        "security": "MEDIUM RISK - Virtualization licensing",
        "link": "https://www.vmware.com/"
    },
    1126: {
        "description": "HP VMware License Manager 2",
        "details": "HP VMware licensing service alternate.",
        "security": "MEDIUM RISK - Virtualization licensing",
        "link": "https://www.vmware.com/"
    },
    1130: {
        "description": "CAC App Service",
        "details": "CAC application service.",
        "security": "MEDIUM RISK - Application service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1131: {
        "description": "CAC App Service Discovery",
        "details": "CAC application service discovery.",
        "security": "MEDIUM RISK - Service discovery",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1132: {
        "description": "KVM-via-IP",
        "details": "Keyboard, Video, Mouse over IP.",
        "security": "HIGH RISK - Remote KVM access",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1137: {
        "description": "TRIM Workgroup Service",
        "details": "TRIM enterprise content management.",
        "security": "MEDIUM RISK - Content management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1138: {
        "description": "encrypted admin requests",
        "details": "Encrypted administration requests.",
        "security": "SECURE - Encrypted administration",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1141: {
        "description": "MXM Server",
        "details": "MXM management server.",
        "security": "HIGH RISK - Management server",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1145: {
        "description": "X9 iCMTS",
        "details": "X9 iCMTS cable modem management.",
        "security": "HIGH RISK - Cable modem management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1147: {
        "description": "CaclvmDaemon",
        "details": "CA CLVM daemon.",
        "security": "HIGH RISK - Volume management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1148: {
        "description": "Elfiq Bandwidth Manager",
        "details": "Elfiq bandwidth management.",
        "security": "HIGH RISK - Bandwidth management",
        "link": "https://www.elfiq.com/"
    },
    1149: {
        "description": "BlueZone Network Manager",
        "details": "BlueZone network management.",
        "security": "HIGH RISK - Network management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1151: {
        "description": "Unify Object Broker",
        "details": "Unify object broker service.",
        "security": "MEDIUM RISK - Object broker",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1152: {
        "description": "Winpopup-lan",
        "details": "Windows popup LAN messenger.",
        "security": "LOW RISK - LAN messaging",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1154: {
        "description": "Community Service",
        "details": "Community service protocol.",
        "security": "MEDIUM RISK - Community service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1163: {
        "description": "SmartDialer",
        "details": "SmartDialer communication.",
        "security": "MEDIUM RISK - Communication service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1164: {
        "description": "QSM Proxy",
        "details": "QSM proxy service.",
        "security": "MEDIUM RISK - Proxy service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1165: {
        "description": "QSM GUI",
        "details": "QSM graphical user interface.",
        "security": "MEDIUM RISK - GUI service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1166: {
        "description": "QSM Remote",
        "details": "QSM remote service.",
        "security": "HIGH RISK - Remote service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1169: {
        "description": "TRIPWIRE",
        "details": "Tripwire intrusion detection.",
        "security": "HIGH RISK - Security monitoring",
        "link": "https://www.tripwire.com/"
    },
    1174: {
        "description": "FNET Remote Procedure Call",
        "details": "FNET RPC service.",
        "security": "HIGH RISK - RPC service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1175: {
        "description": "Dossier",
        "details": "Dossier information service.",
        "security": "MEDIUM RISK - Information service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1183: {
        "description": "LL Surfup HTTP",
        "details": "LL Surfup HTTP service.",
        "security": "MEDIUM RISK - HTTP service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1185: {
        "description": "Catchpole Port",
        "details": "Catchpole service port.",
        "security": "MEDIUM RISK - Application service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1186: {
        "description": "MySQL Cluster Manager",
        "details": "MySQL cluster management service.",
        "security": "HIGH RISK - Database cluster management",
        "link": "https://www.mysql.com/"
    },
    1187: {
        "description": "Alias Service",
        "details": "Alias name service.",
        "security": "MEDIUM RISK - Name service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1192: {
        "description": "ClusterProbe",
        "details": "Cluster probe service.",
        "security": "HIGH RISK - Cluster monitoring",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1198: {
        "description": "CAJO Discovery",
        "details": "CAJO discovery service.",
        "security": "MEDIUM RISK - Service discovery",
        "link": "https://cajo.dev.java.net/"
    },
    1199: {
        "description": "DMIDI",
        "details": "DMIDI digital music interface.",
        "security": "LOW RISK - Music interface",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1201: {
        "description": "Nucleus Sand",
        "details": "Nucleus Sand database.",
        "security": "HIGH RISK - Database service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1213: {
        "description": "MPC LIFENET",
        "details": "MPC LIFENET protocol.",
        "security": "MEDIUM RISK - Network protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1216: {
        "description": "ETEBAC 5",
        "details": "ETEBAC 5 electronic banking.",
        "security": "HIGH RISK - Banking protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1217: {
        "description": "HPSS-NDAPI",
        "details": "HP Storage System Network Data API.",
        "security": "HIGH RISK - Storage API",
        "link": "https://www.hpss-collaboration.org/"
    },
    1218: {
        "description": "AeroFlight-ADs",
        "details": "AeroFlight advertisement service.",
        "security": "MEDIUM RISK - Advertisement service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1233: {
        "description": "Universal Time daemon",
        "details": "Universal time synchronization daemon.",
        "security": "LOW RISK - Time synchronization",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1236: {
        "description": "bvcontrol",
        "details": "BV control protocol.",
        "security": "HIGH RISK - Device control",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1244: {
        "description": "FastSuite",
        "details": "FastSuite communication protocol.",
        "security": "MEDIUM RISK - Communication protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1247: {
        "description": "VisionPyramid",
        "details": "VisionPyramid protocol.",
        "security": "MEDIUM RISK - Vision system",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1248: {
        "description": "hermes",
        "details": "Hermes messaging system.",
        "security": "MEDIUM RISK - Messaging system",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1259: {
        "description": "OPENNL-VOICE",
        "details": "OpenNL voice communication.",
        "security": "MEDIUM RISK - Voice communication",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1271: {
        "description": "eXcuse License Manager",
        "details": "eXcuse software license manager.",
        "security": "MEDIUM RISK - License management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1272: {
        "description": "CSPMySQL",
        "details": "CSP MySQL interface.",
        "security": "HIGH RISK - Database interface",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1277: {
        "description": "mqs",
        "details": "Message queue service.",
        "security": "MEDIUM RISK - Message queuing",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1287: {
        "description": "RouteMatch Communications",
        "details": "RouteMatch transportation communications.",
        "security": "MEDIUM RISK - Transportation system",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1296: {
        "description": "dproxy",
        "details": "DNS proxy service.",
        "security": "MEDIUM RISK - DNS proxy",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1300: {
        "description": "H323 Host Call Secure",
        "details": "H.323 secure host call signaling.",
        "security": "SECURE - Encrypted H.323",
        "link": "https://www.itu.int/rec/T-REC-H.323/"
    },
    1301: {
        "description": "CI3-Software-1",
        "details": "CI3 software protocol.",
        "security": "MEDIUM RISK - Software protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1309: {
        "description": "Chameleon",
        "details": "Chameleon protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1310: {
        "description": "Husky",
        "details": "Husky protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1311: {
        "description": "RxMon",
        "details": "RxMon monitoring protocol.",
        "security": "MEDIUM RISK - Monitoring service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1322: {
        "description": "Novation",
        "details": "Novation protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1328: {
        "description": "EWALL",
        "details": "EWALL firewall service.",
        "security": "HIGH RISK - Firewall management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1334: {
        "description": "writesrv",
        "details": "Write service protocol.",
        "security": "MEDIUM RISK - Write service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1352: {
        "description": "Lotus Notes",
        "details": "IBM Lotus Notes communication.",
        "security": "MEDIUM RISK - Notes messaging",
        "link": "https://www.ibm.com/products/domino"
    },
    1417: {
        "description": "Timbuktu Service 1",
        "details": "Timbuktu remote control service 1.",
        "security": "HIGH RISK - Remote control",
        "link": "https://en.wikipedia.org/wiki/Timbuktu_(software)"
    },
    
    # Final TOP_750 Ports - Completing Coverage
    1443: {
        "description": "Integrated Management Facility",
        "details": "IBM Integrated Management Facility.",
        "security": "HIGH RISK - System management",
        "link": "https://www.ibm.com/"
    },
    1455: {
        "description": "ESL License Manager",
        "details": "ESL software license manager.",
        "security": "MEDIUM RISK - License management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1461: {
        "description": "IBM Wireless LAN",
        "details": "IBM wireless LAN management.",
        "security": "MEDIUM RISK - Wireless management",
        "link": "https://www.ibm.com/"
    },
    1500: {
        "description": "VLSI License Manager",
        "details": "VLSI software license manager.",
        "security": "MEDIUM RISK - License management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1501: {
        "description": "Satellite-data Acquisition System 3",
        "details": "SDDACS satellite data acquisition.",
        "security": "HIGH RISK - Satellite system",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1524: {
        "description": "ingress",
        "details": "Ingress network service.",
        "security": "HIGH RISK - Network ingress",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1580: {
        "description": "tn-tl-r1",
        "details": "TN-TL-R1 protocol.",
        "security": "MEDIUM RISK - Protocol service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1583: {
        "description": "simbaexpress",
        "details": "Simba Express protocol.",
        "security": "MEDIUM RISK - Express protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1594: {
        "description": "sixtrak",
        "details": "SixTrak protocol.",
        "security": "MEDIUM RISK - Tracking protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1600: {
        "description": "issd",
        "details": "ISS daemon.",
        "security": "MEDIUM RISK - ISS service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1641: {
        "description": "InVision",
        "details": "InVision application service.",
        "security": "MEDIUM RISK - Application service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1658: {
        "description": "sixnetudr",
        "details": "SixNet UDR protocol.",
        "security": "MEDIUM RISK - UDR protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1666: {
        "description": "netview-aix-6",
        "details": "IBM NetView for AIX 6.",
        "security": "HIGH RISK - Network management",
        "link": "https://www.ibm.com/"
    },
    1687: {
        "description": "nsjtp-ctrl",
        "details": "NSJ time protocol control.",
        "security": "MEDIUM RISK - Time protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1688: {
        "description": "nsjtp-data",
        "details": "NSJ time protocol data.",
        "security": "MEDIUM RISK - Time protocol data",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1700: {
        "description": "mps-raft",
        "details": "MPS RAFT protocol.",
        "security": "MEDIUM RISK - RAFT protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1717: {
        "description": "fj-hdnet",
        "details": "Fujitsu HD network protocol.",
        "security": "MEDIUM RISK - Fujitsu protocol",
        "link": "https://www.fujitsu.com/"
    },
    1718: {
        "description": "h323gatedisc",
        "details": "H.323 gate discovery protocol.",
        "security": "MEDIUM RISK - H.323 discovery",
        "link": "https://www.itu.int/rec/T-REC-H.323/"
    },
    1721: {
        "description": "caicci",
        "details": "CA icci protocol.",
        "security": "MEDIUM RISK - CA protocol",
        "link": "https://www.broadcom.com/"
    },
    1761: {
        "description": "landesk-rc",
        "details": "LANDesk remote control.",
        "security": "HIGH RISK - Remote control",
        "link": "https://www.landesk.com/"
    },
    1782: {
        "description": "hp-hcip",
        "details": "HP Host Control Interface Protocol.",
        "security": "HIGH RISK - HP host control",
        "link": "https://www.hpe.com/"
    },
    1783: {
        "description": "Fujitsu Device Control",
        "details": "Fujitsu device control protocol.",
        "security": "HIGH RISK - Device control",
        "link": "https://www.fujitsu.com/"
    },
    1805: {
        "description": "ENTTP",
        "details": "Enterprise Number To Name Protocol.",
        "security": "MEDIUM RISK - Name resolution",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1839: {
        "description": "netopia-vo1",
        "details": "Netopia voice protocol 1.",
        "security": "MEDIUM RISK - Voice protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1840: {
        "description": "netopia-vo2",
        "details": "Netopia voice protocol 2.",
        "security": "MEDIUM RISK - Voice protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1862: {
        "description": "MySQL Cluster Data Node",
        "details": "MySQL Cluster data node communication.",
        "security": "HIGH RISK - Database cluster",
        "link": "https://www.mysql.com/"
    },
    1863: {
        "description": "MSNP",
        "details": "Microsoft Notification Protocol (MSN Messenger).",
        "security": "MEDIUM RISK - Instant messaging",
        "link": "https://en.wikipedia.org/wiki/Microsoft_Notification_Protocol"
    },
    1864: {
        "description": "Paradym-31",
        "details": "Paradym-31 port.",
        "security": "MEDIUM RISK - Application port",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1875: {
        "description": "westell-stats",
        "details": "Westell statistics service.",
        "security": "MEDIUM RISK - Statistics service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1914: {
        "description": "elm-momentum",
        "details": "ELM momentum protocol.",
        "security": "MEDIUM RISK - Momentum protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1971: {
        "description": "netop-school",
        "details": "NetOp School remote control.",
        "security": "HIGH RISK - Educational remote control",
        "link": "https://www.netop.com/"
    },
    1972: {
        "description": "intersys-cache",
        "details": "InterSystems Cache database.",
        "security": "HIGH RISK - Database service",
        "link": "https://www.intersystems.com/"
    },
    1974: {
        "description": "drp",
        "details": "DRP protocol.",
        "security": "MEDIUM RISK - Protocol service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    1984: {
        "description": "bb",
        "details": "BB protocol.",
        "security": "MEDIUM RISK - Application protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    
    # Extended TOP_750+ Coverage - Next Batch
    2170: {
        "description": "EyeTV",
        "details": "EyeTV video streaming service.",
        "security": "MEDIUM RISK - Video streaming",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2190: {
        "description": "TiVoConnect Beacon",
        "details": "TiVo Connect beacon service.",
        "security": "MEDIUM RISK - Media service",
        "link": "https://www.tivo.com/"
    },
    2191: {
        "description": "TvBus",
        "details": "TvBus streaming protocol.",
        "security": "MEDIUM RISK - TV streaming",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2196: {
        "description": "NVIDIA GRID",
        "details": "NVIDIA GRID GPU virtualization.",
        "security": "HIGH RISK - GPU virtualization",
        "link": "https://www.nvidia.com/"
    },
    2200: {
        "description": "ICI",
        "details": "ICI protocol.",
        "security": "MEDIUM RISK - ICI protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2251: {
        "description": "DIGI-PAR",
        "details": "Digi parallel port service.",
        "security": "HIGH RISK - Hardware interface",
        "link": "https://www.digi.com/"
    },
    2260: {
        "description": "APC Agent",
        "details": "APC UPS monitoring agent.",
        "security": "HIGH RISK - UPS management",
        "link": "https://www.apc.com/"
    },
    2288: {
        "description": "NETML",
        "details": "NETML protocol.",
        "security": "MEDIUM RISK - Network protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2366: {
        "description": "qip-login",
        "details": "QIP login service.",
        "security": "HIGH RISK - Authentication",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2393: {
        "description": "Microsoft OLAP",
        "details": "Microsoft OLAP services 1.",
        "security": "HIGH RISK - Database analytics",
        "link": "https://docs.microsoft.com/en-us/analysis-services/"
    },
    2394: {
        "description": "Microsoft OLAP",
        "details": "Microsoft OLAP services 2.",
        "security": "HIGH RISK - Database analytics",
        "link": "https://docs.microsoft.com/en-us/analysis-services/"
    },
    2399: {
        "description": "FileMaker Pro",
        "details": "FileMaker Pro database server.",
        "security": "HIGH RISK - Database server",
        "link": "https://www.filemaker.com/"
    },
    2401: {
        "description": "cvspserver",
        "details": "CVS (Concurrent Versions System) server.",
        "security": "HIGH RISK - Version control",
        "link": "https://www.cvs.org/"
    },
    2492: {
        "description": "groove",
        "details": "Microsoft Groove collaboration.",
        "security": "MEDIUM RISK - Collaboration software",
        "link": "https://docs.microsoft.com/en-us/groove/"
    },
    2500: {
        "description": "Resource Monitoring Service",
        "details": "Resource monitoring and management.",
        "security": "HIGH RISK - System monitoring",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2522: {
        "description": "WinDB",
        "details": "WinDB database service.",
        "security": "HIGH RISK - Database service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2525: {
        "description": "MS V-Worlds",
        "details": "Microsoft V-Worlds virtual environment.",
        "security": "MEDIUM RISK - Virtual worlds",
        "link": "https://www.microsoft.com/"
    },
    2557: {
        "description": "nicetec-mgmt",
        "details": "Nicetec management protocol.",
        "security": "HIGH RISK - Device management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2601: {
        "description": "zebra",
        "details": "Zebra routing protocol.",
        "security": "HIGH RISK - Network routing",
        "link": "https://www.zebra.org/"
    },
    2602: {
        "description": "ripd",
        "details": "RIP routing daemon.",
        "security": "HIGH RISK - Network routing",
        "link": "https://www.zebra.org/"
    },
    2604: {
        "description": "ospfd",
        "details": "OSPF routing daemon.",
        "security": "HIGH RISK - Network routing",
        "link": "https://www.zebra.org/"
    },
    2605: {
        "description": "bgpd",
        "details": "BGP routing daemon.",
        "security": "HIGH RISK - Network routing",
        "link": "https://www.zebra.org/"
    },
    2607: {
        "description": "connection",
        "details": "Connection service.",
        "security": "MEDIUM RISK - Connection service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2608: {
        "description": "wag-service",
        "details": "WAG service protocol.",
        "security": "MEDIUM RISK - WAG service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2638: {
        "description": "Sybase SQL Anywhere",
        "details": "Sybase SQL Anywhere database server.",
        "security": "HIGH RISK - Database server",
        "link": "https://www.sap.com/products/sybase-sql-anywhere.html"
    },
    2701: {
        "description": "SMS RCInfo",
        "details": "SMS Remote Control Information.",
        "security": "HIGH RISK - Remote control",
        "link": "https://docs.microsoft.com/en-us/mem/configmgr/"
    },
    2702: {
        "description": "SMS Remote Control",
        "details": "SMS Remote Control Agent.",
        "security": "HIGH RISK - Remote control",
        "link": "https://docs.microsoft.com/en-us/mem/configmgr/"
    },
    2710: {
        "description": "SSO Service",
        "details": "Single Sign-On service.",
        "security": "HIGH RISK - Authentication",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2717: {
        "description": "PN RequesterB",
        "details": "PN Requester B protocol.",
        "security": "MEDIUM RISK - Request protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2718: {
        "description": "PN RequesterC",
        "details": "PN Requester C protocol.",
        "security": "MEDIUM RISK - Request protocol",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2725: {
        "description": "MSOLAP PTP2",
        "details": "Microsoft SQL Server Analysis Services PTP2.",
        "security": "HIGH RISK - Database analytics",
        "link": "https://docs.microsoft.com/en-us/analysis-services/"
    },
    2800: {
        "description": "acc-raid",
        "details": "ACC RAID management.",
        "security": "HIGH RISK - Storage management",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2809: {
        "description": "corbaloc",
        "details": "CORBA location service.",
        "security": "MEDIUM RISK - CORBA service",
        "link": "https://www.omg.org/corba/"
    },
    2811: {
        "description": "GSI FTP",
        "details": "Grid Security Infrastructure FTP.",
        "security": "HIGH RISK - Secure file transfer",
        "link": "https://www.globus.org/"
    },
    2875: {
        "description": "DXMESSAGE",
        "details": "DX Message service.",
        "security": "MEDIUM RISK - Message service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2909: {
        "description": "Funk Dialout",
        "details": "Funk dialout service.",
        "security": "HIGH RISK - Dialout service",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2910: {
        "description": "TDAccess",
        "details": "TDAccess protocol.",
        "security": "HIGH RISK - Access control",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    },
    2920: {
        "description": "roboED",
        "details": "RoboED educational robotics.",
        "security": "MEDIUM RISK - Educational software",
        "link": "https://www.iana.org/assignments/service-names-port-numbers/"
    }
}


def get_port_description(port):
    """Get enhanced description for a given port number"""
    port_info = PORT_DESCRIPTIONS.get(port)
    if port_info:
        return port_info
    else:
        return {
            "description": f"Port {port}",
            "details": "Unknown service or application-specific port.",
            "security": "UNKNOWN RISK - Investigate further",
            "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
        }


def get_port_security_level(port):
    """Get security risk level for a port (HIGH RISK, MEDIUM RISK, LOW RISK, SECURE, UNKNOWN)"""
    port_info = PORT_DESCRIPTIONS.get(port)
    if port_info and 'security' in port_info:
        security_text = port_info['security']
        if 'HIGH RISK' in security_text:
            return 'HIGH RISK'
        elif 'MEDIUM RISK' in security_text:
            return 'MEDIUM RISK'
        elif 'LOW RISK' in security_text:
            return 'LOW RISK'
        elif 'SECURE' in security_text:
            return 'SECURE'
    return 'UNKNOWN RISK'


def get_all_ports():
    """Get list of all ports in the database"""
    return list(PORT_DESCRIPTIONS.keys())


def search_ports_by_service(service_name):
    """Search for ports by service name or description"""
    results = []
    service_name_lower = service_name.lower()
    
    for port, info in PORT_DESCRIPTIONS.items():
        description = info.get('description', '').lower()
        details = info.get('details', '').lower()
        
        if (service_name_lower in description or 
            service_name_lower in details):
            results.append((port, info))
    
    return results


if __name__ == "__main__":
    # Example usage and testing
    print("Port Descriptions Database")
    print("=" * 40)
    
    # Test some common ports
    test_ports = [22, 80, 443, 445, 3389, 1433, 8080]
    
    for port in test_ports:
        info = get_port_description(port)
        risk = get_port_security_level(port)
        print(f"Port {port}: {info['description']} [{risk}]")
    
    print(f"\nTotal ports in database: {len(get_all_ports())}")
    
    # Test search function
    print("\nSearching for 'SSH' related ports:")
    ssh_ports = search_ports_by_service('ssh')
    for port, info in ssh_ports:
        print(f"  Port {port}: {info['description']}")
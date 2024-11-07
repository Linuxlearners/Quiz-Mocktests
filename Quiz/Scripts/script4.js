let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = 
[
    {
        "question": "Max uses the 'ping' command to gather information about a target. What is he primarily trying to determine?",
        "options": [
            "Network latency",
            "Open ports",
            "Active services",
            "User account status"
        ],
        "answer": "Network latency"
    },
    {
        "question": "During a NetBIOS enumeration, what command can be used to view the current sessions on a machine?",
        "options": [
            "net session",
            "net share",
            "net view",
            "net use"
        ],
        "answer": "net session"
    },
    {
        "question": "An attacker uses the 'ldapsearch' command to perform enumeration. Which of the following parameters would help retrieve user email addresses?",
        "options": [
            "uid",
            "mail",
            "cn",
            "objectClass"
        ],
        "answer": "mail"
    },
    {
        "question": "Max discovers a misconfigured DNS server allowing unauthorized zone transfers. What could this lead to?",
        "options": [
            "Data leakage",
            "Increased network performance",
            "Enhanced security",
            "Password guessing attacks"
        ],
        "answer": "Data leakage"
    },
    {
        "question": "What type of information can be obtained from an NTP server when performing enumeration?",
        "options": [
            "List of active users",
            "System uptime and time configuration",
            "Open ports on the server",
            "User account details"
        ],
        "answer": "System uptime and time configuration"
    },
    {
        "question": "During an LDAP enumeration, which command would help in listing all entries in the directory?",
        "options": [
            "ldapsearch -x",
            "ldapsearch -b",
            "ldapsearch -H",
            "ldapsearch -D"
        ],
        "answer": "ldapsearch -b"
    },
    {
        "question": "An organization’s SNMP service is exposed to the public. What is the primary security concern?",
        "options": [
            "Increased service availability",
            "Unauthorized access to sensitive device information",
            "Network performance degradation",
            "Interruption of service"
        ],
        "answer": "Unauthorized access to sensitive device information"
    },
    {
        "question": "Max uses 'fping' to ping multiple hosts simultaneously. What is the advantage of using this tool?",
        "options": [
            "It provides detailed service information",
            "It can quickly assess the availability of many hosts",
            "It allows for packet capture",
            "It identifies network traffic patterns"
        ],
        "answer": "It can quickly assess the availability of many hosts"
    },
    {
        "question": "What kind of information can a successful NFS enumeration provide to an attacker?",
        "options": [
            "Exported files and directories",
            "User login credentials",
            "Network traffic patterns",
            "Open database connections"
        ],
        "answer": "Exported files and directories"
    },
    {
        "question": "During enumeration, which command is used to identify the Windows services running on a target?",
        "options": [
            "netstat",
            "sc query",
            "tasklist",
            "ipconfig"
        ],
        "answer": "sc query"
    },
    {
        "question": "When enumerating an SMTP server, what does the 'EXPN' command do?",
        "options": [
            "Expands a mailing list",
            "Validates an email address",
            "Displays the server's capabilities",
            "Retrieves user account details"
        ],
        "answer": "Expands a mailing list"
    },
    {
        "question": "Max finds that a target's LDAP server is using SSL (LDAPS). What is the significance of this?",
        "options": [
            "It encrypts communication between the client and server",
            "It speeds up directory queries",
            "It reduces server load",
            "It allows anonymous access"
        ],
        "answer": "It encrypts communication between the client and server"
    },
    {
        "question": "What is the primary purpose of a 'traceroute' command in network enumeration?",
        "options": [
            "Identify open ports on a target",
            "Map the path packets take to a destination",
            "Gather user account information",
            "Capture live network traffic"
        ],
        "answer": "Map the path packets take to a destination"
    },
    {
        "question": "During a DNS enumeration, Max notices a CNAME record pointing to an external domain. What does this typically indicate?",
        "options": [
            "A subdomain alias",
            "A misconfigured DNS server",
            "An external mail server",
            "A security risk"
        ],
        "answer": "A subdomain alias"
    },
    {
        "question": "An attacker uses the command 'showmount -e' against an NFS server. What information is he attempting to obtain?",
        "options": [
            "List of exported NFS shares",
            "Active connections",
            "User sessions",
            "Open ports"
        ],
        "answer": "List of exported NFS shares"
    },
    {
        "question": "What is one of the primary security concerns with exposing SNMPv1 to the public internet?",
        "options": [
            "Data is encrypted",
            "Weak community strings can be exploited",
            "Improved performance",
            "Automatic device discovery"
        ],
        "answer": "Weak community strings can be exploited"
    },
    {
        "question": "Max discovers that an LDAP server allows anonymous binding. What is the risk associated with this configuration?",
        "options": [
            "Improved performance",
            "Access to sensitive directory information",
            "Enhanced security measures",
            "No risk"
        ],
        "answer": "Access to sensitive directory information"
    },
    {
        "question": "What type of attack could be executed through unauthorized DNS zone transfers?",
        "options": [
            "Social engineering",
            "Data leakage",
            "Phishing",
            "Credential stuffing"
        ],
        "answer": "Data leakage"
    },
    {
        "question": "An attacker successfully retrieves a list of users from an LDAP server. What is the next logical step in the attack?",
        "options": [
            "Attempt password guessing attacks",
            "Monitor network traffic",
            "Identify network vulnerabilities",
            "Perform a Denial of Service attack"
        ],
        "answer": "Attempt password guessing attacks"
    },
    {
        "question": "During an enumeration of a web application, what type of data can be revealed through directory brute-forcing?",
        "options": [
            "Sensitive file paths",
            "User credentials",
            "Network device configurations",
            "System logs"
        ],
        "answer": "Sensitive file paths"
    },
    {
        "question": "Max uses 'nmap' with the '-O' option. What is he trying to accomplish?",
        "options": [
            "Service version detection",
            "Operating system detection",
            "Network mapping",
            "Packet capture"
        ],
        "answer": "Operating system detection"
    },
    {
        "question": "In the context of enumeration, what does a service's 'banner' refer to?",
        "options": [
            "The welcome message presented by a service",
            "The security protocols in use",
            "The encryption method employed",
            "The response time of the service"
        ],
        "answer": "The welcome message presented by a service"
    },
    {
        "question": "An attacker is using a tool to perform DNS enumeration and discovers a 'TXT' record. What kind of information might this record contain?",
        "options": [
            "Verification records for domain ownership",
            "IP address mappings",
            "Mail exchange servers",
            "User account information"
        ],
        "answer": "Verification records for domain ownership"
    },
    {
        "question": "What is one effective method to mitigate the risks associated with NetBIOS enumeration?",
        "options": [
            "Disabling NetBIOS over TCP/IP",
            "Allowing anonymous access",
            "Exposing NetBIOS services to the internet",
            "Using default configurations"
        ],
        "answer": "Disabling NetBIOS over TCP/IP"
    },
    {
        "question": "During enumeration, what is the significance of the 'class' attribute in LDAP?",
        "options": [
            "Defines the object type within the directory",
            "Indicates user permissions",
            "Specifies password complexity requirements",
            "Tracks access logs"
        ],
        "answer": "Defines the object type within the directory"
    },
    {
        "question": "An attacker performs a brute-force attack on an LDAP server. What type of data is he most likely trying to obtain?",
        "options": [
            "Usernames and passwords",
            "Configuration settings",
            "Network shares",
            "Email addresses"
        ],
        "answer": "Usernames and passwords"
    },
    {
        "question": "During enumeration, what does the 'telnet' command typically check for when connecting to a remote service?",
        "options": [
            "Open ports",
            "Service responses",
            "User credentials",
            "Firewall rules"
        ],
        "answer": "Service responses"
    },
    {
        "question": "Max is using 'enum4linux' to enumerate information from a Windows system. What type of information can this tool provide?",
        "options": [
            "User accounts and shares",
            "Active processes",
            "Network configurations",
            "Firewall rules"
        ],
        "answer": "User accounts and shares"
    },
    {
        "question": "An attacker uses the 'whois' command against a domain. What information might he discover?",
        "options": [
            "Registered owner and contact information",
            "Open ports",
            "Running services",
            "Email addresses of users"
        ],
        "answer": "Registered owner and contact information"
    },
    {
        "question": "During an SMTP enumeration, Max uses the 'MAIL FROM' command. What is he attempting to verify?",
        "options": [
            "The server's ability to send emails",
            "The validity of a specific email address",
            "The server's configuration",
            "User permissions"
        ],
        "answer": "The validity of a specific email address"
    },
    {
        "question": "While enumerating NFS shares, an attacker discovers an export with 'no_root_squash' option. What does this indicate?",
        "options": [
            "Root users have restricted access",
            "Root users have full access to the share",
            "The share is read-only",
            "The share is hidden"
        ],
        "answer": "Root users have full access to the share"
    },
    {
        "question": "What is the purpose of the 'nslookup -type=AXFR' command?",
        "options": [
            "Perform a DNS lookup",
            "Initiate a zone transfer",
            "Retrieve MX records",
            "Check DNS server health"
        ],
        "answer": "Initiate a zone transfer"
    },
    {
        "question": "Max discovers an LDAP server responding with sensitive user information. What could be a countermeasure to prevent this?",
        "options": [
            "Disabling LDAP completely",
            "Implementing access controls",
            "Using default configurations",
            "Allowing anonymous access"
        ],
        "answer": "Implementing access controls"
    },
    {
        "question": "During a penetration test, Lisa identifies that a company uses 'basic' authentication for LDAP. What is a major risk of this method?",
        "options": [
            "Data is transmitted in plaintext",
            "Increased server load",
            "Higher response times",
            "Improper error handling"
        ],
        "answer": "Data is transmitted in plaintext"
    },
    {
        "question": "What type of information can be revealed by the 'snmpwalk' command?",
        "options": [
            "Configuration settings of SNMP-enabled devices",
            "User account details from LDAP",
            "Active network connections",
            "Network shares"
        ],
        "answer": "Configuration settings of SNMP-enabled devices"
    },
    {
        "question": "An attacker finds that an organization's DNS server allows recursive queries. What risk does this pose?",
        "options": [
            "Unauthorized access to internal data",
            "Increased latency",
            "Data encryption issues",
            "Session hijacking"
        ],
        "answer": "Unauthorized access to internal data"
    },
    {
        "question": "In the context of enumeration, what does the term 'service fingerprinting' refer to?",
        "options": [
            "Identifying the type of service running on a port",
            "Gathering user credentials",
            "Mapping out network structures",
            "Enumerating user accounts"
        ],
        "answer": "Identifying the type of service running on a port"
    },
    {
        "question": "Max performs a DNS enumeration and discovers multiple CNAME records. What is the significance of these records?",
        "options": [
            "They indicate aliases for other domain names",
            "They specify mail exchange servers",
            "They provide information on subdomains",
            "They show IP address mappings"
        ],
        "answer": "They indicate aliases for other domain names"
    },
    {
        "question": "What is a potential consequence of using default SNMP community strings?",
        "options": [
            "Enhanced security",
            "Increased data integrity",
            "Easy access for attackers",
            "Reduced network traffic"
        ],
        "answer": "Easy access for attackers"
    },
    {
        "question": "During an enumeration exercise, Lisa uses the command 'ldapsearch'. What type of data is she most likely trying to retrieve?",
        "options": [
            "User account information",
            "Network device configurations",
            "Email server settings",
            "Firewall rules"
        ],
        "answer": "User account information"
    },
    {
        "question": "Max notices that a server responds to both ICMP and SNMP requests. What type of information can he gather from these protocols?",
        "options": [
            "Network statistics and performance metrics",
            "User login attempts",
            "Firewall configurations",
            "File system integrity"
        ],
        "answer": "Network statistics and performance metrics"
    },
    {
        "question": "What is the primary risk of using an unsecured NTP server?",
        "options": [
            "Time synchronization issues",
            "Unauthorized data access",
            "Denial of Service attacks",
            "Reflection attacks"
        ],
        "answer": "Reflection attacks"
    },
    {
        "question": "During enumeration, an attacker finds that a service is exposing its version number in the response. What can this information be used for?",
        "options": [
            "Identifying vulnerabilities specific to that version",
            "Bypassing firewall rules",
            "Gathering user credentials",
            "Encrypting data transmissions"
        ],
        "answer": "Identifying vulnerabilities specific to that version"
    },
    {
        "question": "What does a successful SNMP enumeration reveal about network devices?",
        "options": [
            "User account passwords",
            "Network topologies and configurations",
            "Running applications",
            "Data transmission rates"
        ],
        "answer": "Network topologies and configurations"
    },
    {
        "question": "Lisa uses the command 'showmount -e <NFS server>'. What type of information is she likely to discover?",
        "options": [
            "Available NFS exports",
            "User sessions",
            "Active connections",
            "Firewall rules"
        ],
        "answer": "Available NFS exports"
    },
    {
        "question": "In LDAP enumeration, what is the purpose of using the '(objectClass=*)' filter?",
        "options": [
            "To retrieve all objects in the directory",
            "To find specific user attributes",
            "To count the number of entries",
            "To sort results"
        ],
        "answer": "To retrieve all objects in the directory"
    },
    {
        "question": "An attacker successfully performs a zone transfer on a DNS server. What type of attack does this indicate?",
        "options": [
            "Data leakage",
            "Credential stuffing",
            "Denial of Service",
            "Session hijacking"
        ],
        "answer": "Data leakage"
    },
    {
        "question": "While conducting an enumeration, Max uses 'tcpdump' to capture packets. What type of data is he looking to analyze?",
        "options": [
            "Live network traffic",
            "User account details",
            "Application logs",
            "Database queries"
        ],
        "answer": "Live network traffic"
    },
    {
        "question": "What does the term 'domain squatting' refer to in the context of DNS enumeration?",
        "options": [
            "Registering domain names similar to existing ones to capture traffic",
            "Performing DNS spoofing",
            "Obtaining sensitive information from DNS records",
            "Creating fake websites to impersonate legitimate ones"
        ],
        "answer": "Registering domain names similar to existing ones to capture traffic"
    },
    {
        "question": "Max performs an enumeration on a target's SMTP service. Which command can he use to check for valid email addresses?",
        "options": [
            "EXPN",
            "VRFY",
            "RCPT",
            "SEND"
        ],
        "answer": "VRFY"
    },
    {
        "question": "An attacker discovers that a server's SNMP is open to the public with no restrictions. What is the most significant risk?",
        "options": [
            "Unauthorized access to network information",
            "Service denial",
            "Poor performance",
            "Increased bandwidth usage"
        ],
        "answer": "Unauthorized access to network information"
    },
    {
        "question": "An attacker performs a NetBIOS enumeration using the 'net view' command against a target IP address. What information is he attempting to gather?",
        "options": [
            "Network shares",
            "User account details",
            "Running processes",
            "Open ports"
        ],
        "answer": "Network shares"
    },
    {
        "question": "During an SNMP enumeration, an attacker retrieves the OID for CPU utilization from a network device. What does OID stand for?",
        "options": [
            "Object Identifier",
            "Open Interface Descriptor",
            "Operational Identifier",
            "Object Information Data"
        ],
        "answer": "Object Identifier"
    },
    {
        "question": "While conducting LDAP enumeration, Lisa discovers that the LDAP server is configured with 'anonymous' access. What is the primary risk associated with this configuration?",
        "options": [
            "Data corruption",
            "Unauthorized access to directory information",
            "Service denial",
            "Increased latency"
        ],
        "answer": "Unauthorized access to directory information"
    },
    {
        "question": "Max performs an NFS enumeration on a target machine using the 'showmount -a' command. What information is he likely trying to obtain?",
        "options": [
            "Active user sessions",
            "NFS exports and their clients",
            "Network protocols in use",
            "Open database connections"
        ],
        "answer": "NFS exports and their clients"
    },
    {
        "question": "What does the term 'LDAP Injection' refer to in the context of enumeration?",
        "options": [
            "Manipulating LDAP queries to gain unauthorized access",
            "Exploiting vulnerabilities in the LDAP server software",
            "Performing brute-force attacks on user accounts",
            "Intercepting LDAP traffic"
        ],
        "answer": "Manipulating LDAP queries to gain unauthorized access"
    },
    {
        "question": "During enumeration, an attacker issues a command to perform a DNS zone transfer. What does a successful zone transfer provide?",
        "options": [
            "A list of all DNS records for a domain",
            "The IP addresses of all network devices",
            "User account information",
            "Configuration details of routers"
        ],
        "answer": "A list of all DNS records for a domain"
    },
    {
        "question": "Max discovers that an organization uses SNMP with weak community strings. What should he recommend as a best practice?",
        "options": [
            "Using 'public' and 'private' as community strings",
            "Implementing strong, unique community strings",
            "Disabling SNMP entirely",
            "Allowing all IP addresses access to SNMP"
        ],
        "answer": "Implementing strong, unique community strings"
    },
    {
        "question": "During an NTP enumeration, an attacker notices that the server allows 'monlist' queries. What is the potential risk of this feature?",
        "options": [
            "Data loss",
            "Exposure of client IP addresses",
            "Network disruption",
            "Service degradation"
        ],
        "answer": "Exposure of client IP addresses"
    },
    {
        "question": "What is the primary function of the 'vrfy' command in SMTP enumeration?",
        "options": [
            "To verify the availability of the SMTP server",
            "To check if a specific email address is valid",
            "To list all users on the server",
            "To identify server response times"
        ],
        "answer": "To check if a specific email address is valid"
    },
    {
        "question": "An organization has a publicly accessible LDAP server. What type of information might an attacker gather through enumeration?",
        "options": [
            "Encrypted passwords",
            "User email addresses and roles",
            "Firewall configurations",
            "VPN access logs"
        ],
        "answer": "User email addresses and roles"
    },
    {
        "question": "Max runs an 'nmap' scan with the '-sV' flag against a target. What is he specifically trying to accomplish?",
        "options": [
            "Operating system detection",
            "Version detection of services",
            "Service fingerprinting",
            "Network mapping"
        ],
        "answer": "Version detection of services"
    },
    {
        "question": "In the context of enumeration, what does the 'userPrincipalName' attribute in an LDAP entry typically represent?",
        "options": [
            "The user's login ID",
            "The user's display name",
            "The user's email address",
            "The user's security token"
        ],
        "answer": "The user's login ID"
    },
    {
        "question": "While performing DNS enumeration, Lisa discovers an 'MX' record. What type of information does this record provide?",
        "options": [
            "Mail exchange servers for the domain",
            "A list of all IP addresses associated with the domain",
            "Name servers for the domain",
            "Host addresses"
        ],
        "answer": "Mail exchange servers for the domain"
    },
    {
        "question": "What is the significance of using 'dig ANY <domain>' during DNS enumeration?",
        "options": [
            "It retrieves all types of DNS records",
            "It specifically queries MX records",
            "It performs a zone transfer",
            "It checks for DNS server availability"
        ],
        "answer": "It retrieves all types of DNS records"
    },
    {
        "question": "During enumeration, an attacker notices that a DNS server responds to queries for internal IP addresses. What is this an indication of?",
        "options": [
            "Poorly configured DNS",
            "An intentional security measure",
            "Secure zone transfers",
            "Encrypted DNS traffic"
        ],
        "answer": "Poorly configured DNS"
    },
    {
        "question": "Max is using 'Wireshark' to capture packets during enumeration. What type of data is he primarily interested in?",
        "options": [
            "Static configurations",
            "Live network traffic",
            "User account details",
            "DNS records"
        ],
        "answer": "Live network traffic"
    },
    {
        "question": "What is a potential impact of LDAP enumeration in a corporate environment?",
        "options": [
            "Denial of service",
            "Increased network speed",
            "Privilege escalation",
            "Data encryption"
        ],
        "answer": "Privilege escalation"
    },
    {
        "question": "During an SNMP enumeration, an attacker discovers the system's uptime. What information does this typically reveal?",
        "options": [
            "System stability",
            "Potential vulnerabilities",
            "Open ports",
            "Network traffic patterns"
        ],
        "answer": "System stability"
    },
    {
        "question": "John uses 'nbtscan' to enumerate NetBIOS shares on a target network. What type of information is he seeking?",
        "options": [
            "User passwords",
            "Open shares on systems",
            "Network configurations",
            "Active directory details"
        ],
        "answer": "Open shares on systems"
    },
    {
        "question": "What is a major concern when performing NTP enumeration on a public server?",
        "options": [
            "Exposing system logs",
            "Time synchronization issues",
            "DDoS amplification attacks",
            "Data interception"
        ],
        "answer": "DDoS amplification attacks"
    },
    {
        "question": "During a DNS enumeration, Max is able to identify subdomains of a target domain. What does this information potentially expose?",
        "options": [
            "Vulnerabilities within the main application",
            "Misconfigured servers",
            "User data",
            "Internal network structure"
        ],
        "answer": "Internal network structure"
    },
    {
        "question": "In the context of enumeration, what does the 'Get-ADUser' command in PowerShell accomplish?",
        "options": [
            "Retrieves information about users in Active Directory",
            "Generates a list of all network devices",
            "Queries the local user database",
            "Lists all installed software"
        ],
        "answer": "Retrieves information about users in Active Directory"
    },
    {
        "question": "An attacker finds that a server's SNMP community string is set to 'private'. What is the most significant risk associated with this?",
        "options": [
            "Exploiting network configurations",
            "Access to sensitive network device information",
            "Gaining user passwords",
            "Disabling SNMP services"
        ],
        "answer": "Access to sensitive network device information"
    },
    {
        "question": "Max discovers that an organization's DNS is poorly configured, allowing unauthorized zone transfers. What type of attack could this facilitate?",
        "options": [
            "Phishing attacks",
            "Information disclosure",
            "Denial of service",
            "Session hijacking"
        ],
        "answer": "Information disclosure"
    },
    {
        "question": "What is one method to prevent LDAP enumeration attacks?",
        "options": [
            "Allowing anonymous binds",
            "Restricting LDAP access to trusted IPs",
            "Using default configurations",
            "Publicly exposing the LDAP service"
        ],
        "answer": "Restricting LDAP access to trusted IPs"
    },
    {
        "question": "An attacker sends multiple requests to a public NTP server to determine its IP address. What type of enumeration is this?",
        "options": [
            "Brute-force enumeration",
            "Passive enumeration",
            "Active enumeration",
            "Service enumeration"
        ],
        "answer": "Active enumeration"
    },
    {
        "question": "Max is a penetration tester working on a web application for a client. He notices that the web server allows uploading of files without proper validation. Max uploads a script disguised as an image, which then runs commands on the server. What type of vulnerability is the server likely affected by?",
        "options": [
            "Remote File Inclusion (RFI)",
            "Local File Inclusion (LFI)",
            "Command Injection",
            "Arbitrary File Upload"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "A company deploys an IDS to detect unusual patterns in network traffic. However, an attacker manages to modify packets to make them appear normal, bypassing the IDS detection rules. Which technique is the attacker using?",
        "options": [
            "Fragmentation attack",
            "Evasion attack",
            "Spoofing",
            "Polymorphism"
        ],
        "answer": "Evasion attack"
    },
    {
        "question": "John is reviewing an application that processes user input in URLs without validating or encoding the input properly. This allows an attacker to alter the execution of the application. Which attack is John trying to defend against?",
        "options": [
            "SQL Injection",
            "Cross-site Scripting (XSS)",
            "Remote Code Execution",
            "CRLF Injection"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "Lisa is performing an enumeration on a Windows server and uses the command 'nbtstat -A <IP address>'. What type of information is she most likely trying to gather?",
        "options": [
            "Open ports",
            "NetBIOS name information",
            "SNMP statistics",
            "LDAP attributes"
        ],
        "answer": "NetBIOS name information"
    },
    {
        "question": "An attacker is using SNMP enumeration to gather information about network devices. He issues the command 'snmpwalk -v 2c -c public <IP address>'. What is he trying to access?",
        "options": [
            "User accounts",
            "Network device configurations",
            "Firewall rules",
            "Open file shares"
        ],
        "answer": "Network device configurations"
    },
    {
        "question": "During an LDAP enumeration, an attacker finds the Base DN for the directory. What does this indicate?",
        "options": [
            "The root of the LDAP structure",
            "A specific user account",
            "An organizational unit",
            "A group of permissions"
        ],
        "answer": "The root of the LDAP structure"
    },
    {
        "question": "A penetration tester uses the command 'showmount -e <NFS server IP>'. What is he trying to enumerate?",
        "options": [
            "Open ports",
            "Shared NFS directories",
            "User accounts",
            "Running processes"
        ],
        "answer": "Shared NFS directories"
    },
    {
        "question": "An attacker uses 'nslookup' to gather information about a target's DNS records. What type of attack might this lead to?",
        "options": [
            "Phishing",
            "DNS Spoofing",
            "SQL Injection",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "DNS Spoofing"
    },
    {
        "question": "Max discovers that an organization is using NTP for time synchronization. What is one potential risk of using an unsecured NTP server?",
        "options": [
            "Exposing user credentials",
            "Data leakage",
            "Reflection attacks",
            "Man-in-the-middle attacks"
        ],
        "answer": "Reflection attacks"
    },
    {
        "question": "During a penetration test, Lisa finds that LDAP services are publicly accessible without authentication. What is the most immediate risk?",
        "options": [
            "Unauthorized data access",
            "Password brute-forcing",
            "Denial of Service attacks",
            "Data integrity issues"
        ],
        "answer": "Unauthorized data access"
    },
    {
        "question": "John is trying to identify all users in a Windows domain using LDAP enumeration. Which filter could he use to retrieve all user accounts?",
        "options": [
            "(objectClass=*)",
            "(objectClass=user)",
            "(userPrincipalName=*)",
            "(cn=*)"
        ],
        "answer": "(objectClass=user)"
    },
    {
        "question": "While analyzing SNMP data, an attacker discovers the community string set to 'public'. What does this signify?",
        "options": [
            "A secure configuration",
            "Default settings that can be exploited",
            "An encrypted data stream",
            "Unauthorized access"
        ],
        "answer": "Default settings that can be exploited"
    },
    {
        "question": "Max uses the tool 'nmap' to scan for SNMP-enabled devices. Which option would allow him to query for SNMP data specifically?",
        "options": [
            "-sS",
            "-sU",
            "-p 161",
            "-O"
        ],
        "answer": "-p 161"
    },
    {
        "question": "During an NTP enumeration, which command can reveal the NTP server's status and configuration?",
        "options": [
            "ntpq -p",
            "ntpdate",
            "ntpstat",
            "showmount"
        ],
        "answer": "ntpq -p"
    },
    {
        "question": "An organization uses an open DNS resolver. An attacker queries the resolver to obtain internal IP addresses. What type of attack is this?",
        "options": [
            "DNS Cache Poisoning",
            "Domain Spoofing",
            "DNS Zone Transfer",
            "Reflection Attack"
        ],
        "answer": "DNS Zone Transfer"
    },
    {
        "question": "Max discovers that a web server is exposing detailed error messages. What is the risk associated with this?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Information Disclosure",
            "Session Hijacking"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "An attacker utilizes the 'dig' command to perform DNS enumeration. Which of the following information can they retrieve?",
        "options": [
            "User passwords",
            "Network topologies",
            "DNS records",
            "SNMP data"
        ],
        "answer": "DNS records"
    },
    {
        "question": "Lisa performs a zone transfer using 'dig @<DNS server IP> <domain> AXFR'. What information is she likely to obtain?",
        "options": [
            "Active users",
            "Complete DNS records for the domain",
            "NTP server settings",
            "Open ports"
        ],
        "answer": "Complete DNS records for the domain"
    },
    {
        "question": "In the context of enumeration, what does 'brute-forcing' usually refer to?",
        "options": [
            "Trying all possible combinations of user accounts and passwords",
            "Identifying open ports through systematic scanning",
            "Enumerating services by sending crafted packets",
            "Exploiting known vulnerabilities"
        ],
        "answer": "Trying all possible combinations of user accounts and passwords"
    },
    {
        "question": "During enumeration, an attacker finds an LDAP directory accessible with anonymous bind. What is a major risk associated with this?",
        "options": [
            "Data theft",
            "Network disruption",
            "Service denial",
            "Unauthorized access to sensitive information"
        ],
        "answer": "Unauthorized access to sensitive information"
    },
    {
        "question": "What does the term 'NetBIOS Name Service (NBNS)' refer to in the context of enumeration?",
        "options": [
            "A protocol for managing IP addresses",
            "A method for resolving NetBIOS names to IP addresses",
            "A tool for scanning networks",
            "A type of encryption service"
        ],
        "answer": "A method for resolving NetBIOS names to IP addresses"
    },
    {
        "question": "In NTP enumeration, what could an attacker achieve by sending a 'monlist' request to an NTP server?",
        "options": [
            "Listing all connected clients",
            "Modifying server settings",
            "Spoofing time data",
            "Disabling the NTP service"
        ],
        "answer": "Listing all connected clients"
    },
    {
        "question": "John discovers that an organization is using outdated SNMP versions. What is a key risk associated with this?",
        "options": [
            "Increased network latency",
            "Vulnerability to unauthorized access",
            "Exposure to malware",
            "Data encryption weaknesses"
        ],
        "answer": "Vulnerability to unauthorized access"
    },
    {
        "question": "During an enumeration exercise, Max finds that an LDAP server exposes user group memberships. What is the potential consequence?",
        "options": [
            "Denial of service",
            "Identity theft",
            "Privilege escalation",
            "Data integrity loss"
        ],
        "answer": "Privilege escalation"
    },
    {
        "question": "A penetration tester is trying to gather information about services running on a target machine. Which tool would be most effective for this purpose?",
        "options": [
            "Wireshark",
            "Nmap",
            "Burp Suite",
            "Metasploit"
        ],
        "answer": "Nmap"
    },
    {
        "question": "An organization has not implemented any countermeasures against LDAP enumeration. What is the most likely outcome?",
        "options": [
            "Reduced attack surface",
            "Unauthorized information disclosure",
            "Improved user access controls",
            "Increased network speed"
        ],
        "answer": "Unauthorized information disclosure"
    },
    {
        "question": "Max performs an enumeration on a network and uses the command 'arp -a' to gather information. What type of information is he trying to retrieve?",
        "options": [
            "IP to MAC address mappings",
            "Active TCP connections",
            "DNS records",
            "Network device configurations"
        ],
        "answer": "IP to MAC address mappings"
    },
    {
        "question": "An attacker is trying to bypass security measures by exploiting how a network protocol processes certain types of packets. What is this technique called?",
        "options": [
            "Packet sniffing",
            "Protocol fuzzing",
            "Vulnerability scanning",
            "Session hijacking"
        ],
        "answer": "Protocol fuzzing"
    },
    {
        "question": "Max discovers that a network has a misconfigured NTP server that allows external queries. What attack vector could he exploit?",
        "options": [
            "Time-based attacks",
            "Reflection attacks",
            "Denial of Service",
            "Data interception"
        ],
        "answer": "Reflection attacks"
    },
    {
        "question": "While enumerating services on a target machine, Lisa finds an open SMTP port. What type of enumeration might she perform next?",
        "options": [
            "User enumeration via VRFY command",
            "Service fingerprinting",
            "Network mapping",
            "DNS enumeration"
        ],
        "answer": "User enumeration via VRFY command"
    },
    {
        "question": "Max encounters a system using outdated SNMP configurations. What is the primary countermeasure he should recommend?",
        "options": [
            "Implementing strong community strings",
            "Upgrading to SNMPv3",
            "Disabling SNMP",
            "Changing network topologies"
        ],
        "answer": "Upgrading to SNMPv3"
    },
    {
        "question": "John is attempting to gather user account information from an organization's public-facing LDAP service. What could he exploit if no restrictions are in place?",
        "options": [
            "Unauthorized account creation",
            "Information disclosure of user attributes",
            "Denial of service on the LDAP server",
            "Password attacks"
        ],
        "answer": "Information disclosure of user attributes"
    }
];

   // Shuffle array function
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
}

// Shuffle questions and options initially
shuffleArray(questions);
questions.forEach(question => shuffleArray(question.options));

const questionStatus = Array(questions.length).fill("unanswered"); // Track status of each question

function loadQuestion() {
    const questionData = questions[currentQuestion];
    document.getElementById("question").innerText = `Q${currentQuestion + 1}: ${questionData.question}`;

    // Shuffle options for the current question
    shuffleArray(questionData.options);

    const optionsContainer = document.getElementById("options");
    optionsContainer.innerHTML = '';
    questionData.options.forEach(option => {
        const button = document.createElement("div");
        button.className = "option";
        button.innerText = option;
        button.onclick = () => checkAnswer(option);
        optionsContainer.appendChild(button);
    });

    updateSidebar();
    updateNavigationButtons();
    updateRemainingQuestions();
}

function checkAnswer(selected) {
    const correctAnswer = questions[currentQuestion].answer;
    const options = document.querySelectorAll(".option");

    options.forEach(option => {
        option.onclick = null; // Disable further clicks
        if (option.innerText === correctAnswer) {
            option.classList.add("correct");
        } else {
            option.classList.add("incorrect");
        }
    });

    if (selected === correctAnswer) {
        correctAnswers++;
        questionStatus[currentQuestion] = "completed";
    } else {
        wrongAnswers++;
        questionStatus[currentQuestion] = "incorrect";
    }
    updateSidebar();
}

function skipQuestion() {
    questionStatus[currentQuestion] = "skipped";
    loadNextQuestion();
}

function loadNextQuestion() {
    currentQuestion++;
    if (currentQuestion < questions.length) {
        loadQuestion();
    } else {
        showFinalScore();
    }
}

function loadPreviousQuestion() {
    if (currentQuestion > 0) {
        currentQuestion--;
        loadQuestion();
    }
}

function restartQuiz() {
    currentQuestion = 0;
    correctAnswers = 0;
    wrongAnswers = 0;
    questionStatus.fill("unanswered"); // Reset question status to "unanswered"
    shuffleArray(questions); // Shuffle questions for the new session
    questions.forEach(question => shuffleArray(question.options)); // Shuffle options for each question
    loadQuestion(); // Load the first question again
    updateSidebar(); // Reset the question status sidebar
}

function updateRemainingQuestions() {
    const totalQuestions = questions.length;
    const remainingQuestions = totalQuestions - currentQuestion - 1;
    document.getElementById("remaining-questions").innerText = remainingQuestions;
}

function updateSidebar() {
    const statusContainer = document.getElementById("status");
    statusContainer.innerHTML = '';
    questions.forEach((_, index) => {
        const bubble = document.createElement("div");
        bubble.className = "bubble";
        bubble.innerText = index + 1;

        // Update bubble color based on question status
        if (questionStatus[index] === "completed") {
            bubble.classList.add("completed");
        } else if (questionStatus[index] === "skipped") {
            bubble.classList.add("skipped");
        } else if (questionStatus[index] === "incorrect") {
            bubble.classList.add("incorrect");
        }

        statusContainer.appendChild(bubble);
    });
}

function updateNavigationButtons() {
    document.getElementById("prev").classList.toggle("hidden", currentQuestion === 0);
    document.getElementById("next").innerText = questionStatus[currentQuestion] === "skipped" ? "Resume" : "Next";
}

// Event listeners for buttons
document.getElementById("next").onclick = () => {
    if (questionStatus[currentQuestion] === "unanswered") {
        skipQuestion();
    } else {
        loadNextQuestion();
    }
};

document.getElementById("prev").onclick = loadPreviousQuestion;

document.getElementById("restart").onclick = restartQuiz;

document.getElementById("submit").onclick = showFinalScore;

function showFinalScore() {
    const resultContainer = document.createElement("div");
    resultContainer.className = "quiz-container";

    resultContainer.innerHTML = `
        <h1>Quiz Completed</h1>
        <p>Questions: ${questions.length}</p>
        <p>Correct: ${correctAnswers}</p>
        <p>Wrong: ${wrongAnswers}</p>
        <p>Total Score: ${correctAnswers} out of ${questions.length}</p>
    `;

    const restartButton = document.createElement("button");
    restartButton.id = "restart";
    restartButton.className = "btn";
    restartButton.innerText = "Restart Quiz";
    restartButton.onclick = restartQuiz;

    resultContainer.appendChild(restartButton);

    document.body.innerHTML = ''; // Clear existing content
    document.body.appendChild(resultContainer); // Add results
}

// Load the first question
loadQuestion();
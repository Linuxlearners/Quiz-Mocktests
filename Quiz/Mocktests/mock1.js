
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "During a security assessment, Alex identifies several outdated systems that have known vulnerabilities. What should be his immediate recommendation?",
        "options": [
            "Upgrade the systems immediately",
            "Isolate them from the network",
            "Perform a full backup",
            "Leave them as is until further notice"
        ],
        "answer": "Isolate them from the network"
    },
    {
        "question": "Rachel is reviewing the ethical implications of hacking. Which principle is paramount in ethical hacking?",
        "options": [
            "Gaining unauthorized access is acceptable",
            "Always report findings to the client",
            "Ethical hacking should be conducted without consent",
            "Exploiting vulnerabilities for personal gain is allowed"
        ],
        "answer": "Always report findings to the client"
    },
    {
        "question": "Which of the following frameworks provides guidelines for penetration testing?",
        "options": [
            "ISO 27001",
            "OWASP",
            "NIST SP 800-115",
            "COBIT"
        ],
        "answer": "NIST SP 800-115"
    },
    {
        "question": "Emma is tasked with gathering information about a competitor's network infrastructure. Which tool is most effective for DNS footprinting?",
        "options": [
            "Nmap",
            "Whois",
            "Dig",
            "Netcat"
        ],
        "answer": "Dig"
    },
    {
        "question": "While using social engineering techniques, James successfully extracts information from an employee. What type of social engineering is this an example of?",
        "options": [
            "Phishing",
            "Pretexting",
            "Baiting",
            "Quizzing"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "Sophia uses search engines to discover sensitive information about her target organization. What technique is she using?",
        "options": [
            "Google hacking",
            "DNS enumeration",
            "Network scanning",
            "OSINT"
        ],
        "answer": "Google hacking"
    },
    {
        "question": "During a network scan, Ryan finds a host that is not responding to ping requests. What technique should he use next?",
        "options": [
            "ARP scan",
            "Port scan",
            "DNS scan",
            "OS fingerprinting"
        ],
        "answer": "ARP scan"
    },
    {
        "question": "What is the purpose of a SYN scan in network scanning?",
        "options": [
            "To establish a connection with a host",
            "To detect firewalls",
            "To identify open ports",
            "To determine the OS type"
        ],
        "answer": "To identify open ports"
    },
    {
        "question": "A penetration tester notices a network firewall is configured to drop all incoming ICMP packets. Which scanning technique can bypass this restriction?",
        "options": [
            "TCP connect scan",
            "SYN scan",
            "UDP scan",
            "FIN scan"
        ],
        "answer": "FIN scan"
    },
    {
        "question": "While performing enumeration, Mark queries an SNMP-enabled device. He retrieves a list of users and their associated privileges. What enumeration technique is he using?",
        "options": [
            "NetBIOS enumeration",
            "SNMP enumeration",
            "LDAP enumeration",
            "SMTP enumeration"
        ],
        "answer": "SNMP enumeration"
    },
    {
        "question": "Lisa is using Nmap with the -sV option. What is she trying to accomplish?",
        "options": [
            "Operating system detection",
            "Service version detection",
            "Host discovery",
            "Vulnerability scanning"
        ],
        "answer": "Service version detection"
    },
    {
        "question": "During an assessment, David discovers an open LDAP port. What could be a potential risk of this configuration?",
        "options": [
            "User password exposure",
            "Database access",
            "Unauthorized file access",
            "Denial of service"
        ],
        "answer": "User password exposure"
    },
    {
        "question": "During a vulnerability assessment, Sam finds a system that is susceptible to buffer overflow attacks. What should he prioritize in his report?",
        "options": [
            "Patch the operating system",
            "Implement input validation",
            "Change user passwords",
            "Install antivirus software"
        ],
        "answer": "Implement input validation"
    },
    {
        "question": "Which tool is primarily used for automated vulnerability scanning?",
        "options": [
            "Wireshark",
            "Nessus",
            "Metasploit",
            "Burp Suite"
        ],
        "answer": "Nessus"
    },
    {
        "question": "What is the first step in conducting a vulnerability assessment?",
        "options": [
            "Identifying assets",
            "Scanning for vulnerabilities",
            "Reporting findings",
            "Mitigating risks"
        ],
        "answer": "Identifying assets"
    },
    {
        "question": "After identifying vulnerabilities, what is the next logical step in a security assessment?",
        "options": [
            "Exploitation",
            "Reporting",
            "Remediation",
            "Risk analysis"
        ],
        "answer": "Reporting"
    },
    {
        "question": "Which of the following is a common vulnerability scanning tool?",
        "options": [
            "Metasploit",
            "Burp Suite",
            "OpenVAS",
            "Wireshark"
        ],
        "answer": "OpenVAS"
    },
    {
        "question": "What type of attack exploits the weakness of inadequate input validation in web applications?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting",
            "Directory Traversal",
            "Command Injection"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "During a system hacking exercise, an ethical hacker gains access to a user account with limited privileges. What is the next step to escalate privileges?",
        "options": [
            "Clearing logs",
            "Searching for vulnerabilities",
            "Installing malware",
            "Changing the user password"
        ],
        "answer": "Searching for vulnerabilities"
    },
    {
        "question": "When maintaining access after a successful exploit, which technique is commonly used?",
        "options": [
            "Rootkits",
            "RATs",
            "Keyloggers",
            "Trojan horses"
        ],
        "answer": "RATs"
    },
    {
        "question": "Which of the following is NOT a common technique used to clear logs on compromised systems?",
        "options": [
            "Using a log cleaning tool",
            "Editing log files directly",
            "Creating fake logs",
            "Transferring logs to an external server"
        ],
        "answer": "Transferring logs to an external server"
    },
    {
        "question": "What type of malware disguises itself as legitimate software?",
        "options": [
            "Virus",
            "Trojan",
            "Worm",
            "Spyware"
        ],
        "answer": "Trojan"
    },
    {
        "question": "In a corporate environment, a keylogger is discovered. What should the IT department do first?",
        "options": [
            "Inform the management",
            "Identify the source of infection",
            "Clean the infected systems",
            "Monitor for further activity"
        ],
        "answer": "Identify the source of infection"
    },
    {
        "question": "What technique is used by APT (Advanced Persistent Threat) actors to maintain access to a network?",
        "options": [
            "Exploiting zero-day vulnerabilities",
            "Using a single point of entry",
            "Employing phishing attacks",
            "Deploying backdoors"
        ],
        "answer": "Deploying backdoors"
    },
    {
        "question": "What is the main purpose of a denial-of-service (DoS) attack?",
        "options": [
            "To steal data",
            "To disrupt services",
            "To gain unauthorized access",
            "To manipulate data"
        ],
        "answer": "To disrupt services"
    },
    {
        "question": "Which of the following tools is used for network sniffing?",
        "options": [
            "Wireshark",
            "Nessus",
            "Metasploit",
            "OpenVAS"
        ],
        "answer": "Wireshark"
    },
    {
        "question": "An attacker conducts a DHCP spoofing attack to intercept network traffic. What is the primary goal of this attack?",
        "options": [
            "Gain unauthorized access to a system",
            "Redirect traffic to a malicious site",
            "Eavesdrop on user communications",
            "Steal sensitive data"
        ],
        "answer": "Eavesdrop on user communications"
    },
    {
        "question": "During a social engineering exercise, an attacker impersonates a company technician. What technique is being used?",
        "options": [
            "Phishing",
            "Pretexting",
            "Baiting",
            "Tailgating"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "What type of attack involves an attacker manipulating the DNS resolution process?",
        "options": [
            "DNS Spoofing",
            "ARP Spoofing",
            "Man-in-the-Middle",
            "Session Hijacking"
        ],
        "answer": "DNS Spoofing"
    },
    {
        "question": "Which of the following is a method of exploiting a SQL injection vulnerability?",
        "options": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' AND 'a'='a'",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is the primary purpose of an Intrusion Detection System (IDS)?",
        "options": [
            "To prevent unauthorized access",
            "To monitor network traffic for suspicious activity",
            "To provide encryption for sensitive data",
            "To manage user permissions"
        ],
        "answer": "To monitor network traffic for suspicious activity"
    },
    {
        "question": "Which type of firewall filters traffic based on the state of the connection?",
        "options": [
            "Packet filtering firewall",
            "Stateful inspection firewall",
            "Application-layer firewall",
            "Next-generation firewall"
        ],
        "answer": "Stateful inspection firewall"
    },
    {
        "question": "What is a honeypot primarily used for?",
        "options": [
            "To secure sensitive data",
            "To distract attackers and gather intelligence",
            "To improve network performance",
            "To provide user authentication"
        ],
        "answer": "To distract attackers and gather intelligence"
    },
    {
        "question": "In the context of cloud security, what does the term 'shared responsibility model' refer to?",
        "options": [
            "Cloud providers manage all security aspects",
            "Customers are responsible for physical security only",
            "Both cloud providers and customers share security responsibilities",
            "Security is not a concern in the cloud"
        ],
        "answer": "Both cloud providers and customers share security responsibilities"
    },
    {
        "question": "What is the primary function of cryptography in information security?",
        "options": [
            "To enhance performance",
            "To provide data integrity",
            "To secure communications",
            "To simplify user access"
        ],
        "answer": "To secure communications"
    },
    {
        "question": "Which of the following encryption algorithms is considered symmetric?",
        "options": [
            "RSA",
            "AES",
            "DSA",
            "ECC"
        ],
        "answer": "AES"
    },
    {
        "question": "What type of malware is designed to gain unauthorized access to a system and remain hidden?",
        "options": [
            "Adware",
            "Spyware",
            "Ransomware",
            "Rootkit"
        ],
        "answer": "Rootkit"
    },
    {
        "question": "Which of the following is a method used to detect a session hijacking attack?",
        "options": [
            "Implementing strong encryption",
            "Session timeout policies",
            "Using a single sign-on solution",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "In which type of attack does the attacker intercept and modify communications between two parties without their knowledge?",
        "options": [
            "Replay attack",
            "Man-in-the-Middle attack",
            "Phishing attack",
            "Brute force attack"
        ],
        "answer": "Man-in-the-Middle attack"
    },
    {
        "question": "Which of the following practices is recommended for mitigating the risk of SQL injection?",
        "options": [
            "Using prepared statements",
            "Validating user input",
            "Escaping special characters",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "A company is concerned about the risk of data loss due to accidental deletion. What security measure should they implement?",
        "options": [
            "Access controls",
            "Data encryption",
            "Regular backups",
            "Network segmentation"
        ],
        "answer": "Regular backups"
    },
    {
        "question": "What is the purpose of a digital signature?",
        "options": [
            "To encrypt data",
            "To verify the authenticity of a message",
            "To compress files",
            "To provide data redundancy"
        ],
        "answer": "To verify the authenticity of a message"
    },
    {
        "question": "During an incident response process, what is the first step that should be taken?",
        "options": [
            "Contain the incident",
            "Eradicate the threat",
            "Identify the incident",
            "Recover from the incident"
        ],
        "answer": "Identify the incident"
    },
    {
        "question": "In a corporate environment, what is the best practice for password management?",
        "options": [
            "Use the same password for all accounts",
            "Change passwords regularly and use complex combinations",
            "Share passwords with coworkers for convenience",
            "Store passwords in a text file"
        ],
        "answer": "Change passwords regularly and use complex combinations"
    },
    {
        "question": "What type of attack involves overwhelming a target system with traffic to render it unusable?",
        "options": [
            "DDoS attack",
            "Phishing attack",
            "SQL injection",
            "Brute force attack"
        ],
        "answer": "DDoS attack"
    },
    {
        "question": "Which of the following is a method used to secure wireless networks?",
        "options": [
            "WEP encryption",
            "Using MAC address filtering",
            "Disabling SSID broadcasting",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "Which cryptographic algorithm uses two different keys for encryption and decryption?",
        "options": [
            "Symmetric key algorithm",
            "Asymmetric key algorithm",
            "Hashing algorithm",
            "Digital signature algorithm"
        ],
        "answer": "Asymmetric key algorithm"
    },
    {
        "question": "What is the main goal of penetration testing?",
        "options": [
            "To exploit vulnerabilities",
            "To identify and evaluate security weaknesses",
            "To create awareness among employees",
            "To install security software"
        ],
        "answer": "To identify and evaluate security weaknesses"
    },
    {
        "question": "During a security audit, an employee is caught accessing unauthorized files. What is this an example of?",
        "options": [
            "Policy violation",
            "Malicious insider threat",
            "Unintentional negligence",
            "Social engineering"
        ],
        "answer": "Policy violation"
    },
    {
        "question": "Which type of attack exploits the trust between a user and a website by impersonating the website?",
        "options": [
            "Phishing",
            "Spear phishing",
            "Vishing",
            "Whaling"
        ],
        "answer": "Phishing"
    },
    {
        "question": "What is the primary function of a web application firewall (WAF)?",
        "options": [
            "To block network attacks",
            "To monitor traffic patterns",
            "To filter and monitor HTTP traffic to and from a web application",
            "To provide intrusion detection"
        ],
        "answer": "To filter and monitor HTTP traffic to and from a web application"
    },
    {
        "question": "What type of malware can replicate itself and spread to other systems without user intervention?",
        "options": [
            "Virus",
            "Worm",
            "Trojan",
            "Ransomware"
        ],
        "answer": "Worm"
    },
    {
        "question": "When securing a network, which of the following is a key principle?",
        "options": [
            "Deny all access by default",
            "Allow all access by default",
            "Restrict access based on user location",
            "Monitor only external traffic"
        ],
        "answer": "Deny all access by default"
    },
    {
        "question": "What is the purpose of a vulnerability assessment?",
        "options": [
            "To exploit known vulnerabilities",
            "To identify and prioritize vulnerabilities",
            "To provide user training",
            "To establish security policies"
        ],
        "answer": "To identify and prioritize vulnerabilities"
    },
    {
        "question": "In a password attack, what is the primary goal of a brute force attack?",
        "options": [
            "To guess passwords using pre-defined lists",
            "To systematically try all possible combinations until the correct one is found",
            "To intercept passwords during transmission",
            "To exploit password reset functionalities"
        ],
        "answer": "To systematically try all possible combinations until the correct one is found"
    },
    {
        "question": "What is the role of the CERT (Computer Emergency Response Team)?",
        "options": [
            "To respond to and mitigate cyber incidents",
            "To conduct penetration tests",
            "To develop security software",
            "To perform regular security audits"
        ],
        "answer": "To respond to and mitigate cyber incidents"
    },
    {
        "question": "Which of the following is a common indicator of a phishing attack?",
        "options": [
            "Generic greetings",
            "Urgent requests for personal information",
            "Poor spelling and grammar",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What type of attack is performed by exploiting a software vulnerability to execute arbitrary code?",
        "options": [
            "Remote Code Execution",
            "Denial of Service",
            "Phishing",
            "SQL Injection"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "What is the function of an antivirus program?",
        "options": [
            "To encrypt files",
            "To detect and remove malware",
            "To monitor network traffic",
            "To back up data"
        ],
        "answer": "To detect and remove malware"
    },
    {
        "question": "Which type of vulnerability allows an attacker to inject malicious code into a web application?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "Denial of Service (DoS)",
            "SQL Injection",
            "Remote File Inclusion"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "A company is implementing a new security policy. Which of the following elements is crucial for user awareness?",
        "options": [
            "Enforcing password complexity requirements",
            "Regularly updating software",
            "Conducting security awareness training",
            "Restricting access to sensitive data"
        ],
        "answer": "Conducting security awareness training"
    },
    {
        "question": "What does the term 'credential stuffing' refer to?",
        "options": [
            "Using stolen credentials to gain unauthorized access",
            "Attempting to bypass authentication systems",
            "Phishing for user credentials",
            "Creating fake accounts"
        ],
        "answer": "Using stolen credentials to gain unauthorized access"
    },
    {
        "question": "Which type of attack is characterized by a coordinated attack from multiple compromised systems?",
        "options": [
            "DDoS attack",
            "SQL Injection",
            "Phishing",
            "Social Engineering"
        ],
        "answer": "DDoS attack"
    },
    {
        "question": "During a security audit, what is the primary purpose of conducting a risk assessment?",
        "options": [
            "To identify vulnerabilities",
            "To quantify potential losses",
            "To establish security policies",
            "To develop incident response plans"
        ],
        "answer": "To quantify potential losses"
    },
    {
        "question": "What is the main characteristic of a ransomware attack?",
        "options": [
            "Stealing personal data",
            "Encrypting data and demanding ransom",
            "Disabling security software",
            "Conducting DDoS attacks"
        ],
        "answer": "Encrypting data and demanding ransom"
    },
    {
        "question": "Which technique is commonly used to bypass firewall protections?",
        "options": [
            "Tunneling",
            "Encryption",
            "IP spoofing",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "In an APT attack, what is the primary objective of the attacker?",
        "options": [
            "Immediate financial gain",
            "Long-term access to the network",
            "Disruption of services",
            "Destruction of data"
        ],
        "answer": "Long-term access to the network"
    },
    {
        "question": "Which of the following is a best practice for email security?",
        "options": [
            "Use two-factor authentication",
            "Open all attachments",
            "Ignore suspicious emails",
            "Use a weak password"
        ],
        "answer": "Use two-factor authentication"
    },
    {
        "question": "During a penetration test, the tester finds an open FTP port. What should he investigate next?",
        "options": [
            "Anonymous login capabilities",
            "Data encryption methods",
            "Firewall configurations",
            "User account permissions"
        ],
        "answer": "Anonymous login capabilities"
    },
    {
        "question": "What is the purpose of a digital certificate?",
        "options": [
            "To encrypt data",
            "To verify the identity of a user or device",
            "To compress files",
            "To provide data redundancy"
        ],
        "answer": "To verify the identity of a user or device"
    },
    {
        "question": "Which of the following is a characteristic of a secure coding practice?",
        "options": [
            "Hardcoding passwords",
            "Using input validation",
            "Ignoring error messages",
            "Exposing sensitive information in logs"
        ],
        "answer": "Using input validation"
    },
    {
        "question": "What does the principle of least privilege entail?",
        "options": [
            "Users should have all permissions",
            "Users should have only the access necessary to perform their job",
            "All users should have the same access level",
            "Access should be granted based on seniority"
        ],
        "answer": "Users should have only the access necessary to perform their job"
    },
    {
        "question": "What type of attack involves intercepting network traffic to steal session tokens?",
        "options": [
            "Replay attack",
            "Man-in-the-Middle attack",
            "Session hijacking",
            "Phishing"
        ],
        "answer": "Session hijacking"
    },
    {
        "question": "What does the acronym 'DLP' stand for in information security?",
        "options": [
            "Data Loss Prevention",
            "Data Leak Protection",
            "Data Lifecycle Policy",
            "Data Log Processing"
        ],
        "answer": "Data Loss Prevention"
    },
    {
        "question": "What is a common symptom of a DDoS attack?",
        "options": [
            "Slow network performance",
            "Unauthorized access to systems",
            "Frequent error messages",
            "Increased file sizes"
        ],
        "answer": "Slow network performance"
    },
    {
        "question": "Which type of phishing attack is highly targeted and often personalized?",
        "options": [
            "Whaling",
            "Spear phishing",
            "Vishing",
            "Baiting"
        ],
        "answer": "Spear phishing"
    },
    {
        "question": "What is the purpose of using a VPN?",
        "options": [
            "To bypass firewall restrictions",
            "To secure communications over the internet",
            "To hide user identities",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "Which of the following is a common method used to protect data at rest?",
        "options": [
            "Data encryption",
            "Regular backups",
            "Access controls",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is the purpose of implementing an incident response plan?",
        "options": [
            "To prevent incidents from occurring",
            "To ensure a swift and effective response to security incidents",
            "To create awareness among employees",
            "To conduct regular security audits"
        ],
        "answer": "To ensure a swift and effective response to security incidents"
    },
    {
        "question": "What type of attack involves sending unsolicited messages over the internet?",
        "options": [
            "Spam",
            "Phishing",
            "Spear phishing",
            "Malware"
        ],
        "answer": "Spam"
    },
    {
        "question": "Which of the following is a key component of a risk management strategy?",
        "options": [
            "Identifying assets and their vulnerabilities",
            "Conducting penetration tests",
            "Creating a backup plan",
            "Establishing user access controls"
        ],
        "answer": "Identifying assets and their vulnerabilities"
    },
    {
        "question": "What is the main purpose of applying security patches to software?",
        "options": [
            "To improve performance",
            "To fix known vulnerabilities",
            "To add new features",
            "To change user interfaces"
        ],
        "answer": "To fix known vulnerabilities"
    },
    {
        "question": "What is a common characteristic of ransomware?",
        "options": [
            "It is self-replicating",
            "It encrypts files and demands payment for decryption",
            "It steals user credentials",
            "It spreads via email attachments"
        ],
        "answer": "It encrypts files and demands payment for decryption"
    },
    {
        "question": "What type of attack uses social engineering to trick users into revealing personal information?",
        "options": [
            "Phishing",
            "DDoS",
            "SQL Injection",
            "Man-in-the-Middle"
        ],
        "answer": "Phishing"
    },
    {
        "question": "Which of the following is a technique used in social engineering?",
        "options": [
            "Pretexting",
            "Spear phishing",
            "Impersonation",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is the primary purpose of a risk assessment?",
        "options": [
            "To identify vulnerabilities in a system",
            "To quantify potential losses and impacts",
            "To establish security policies",
            "To monitor network traffic"
        ],
        "answer": "To quantify potential losses and impacts"
    },
    {
        "question": "Which of the following can be a countermeasure against cross-site scripting (XSS) attacks?",
        "options": [
            "Input validation and sanitization",
            "Using HTTPS only",
            "Regular software updates",
            "Implementing firewalls"
        ],
        "answer": "Input validation and sanitization"
    },
    {
        "question": "What is the main goal of a penetration test?",
        "options": [
            "To break into the system",
            "To find and exploit vulnerabilities",
            "To create awareness among employees",
            "To ensure compliance with regulations"
        ],
        "answer": "To find and exploit vulnerabilities"
    },
    {
        "question": "What is the primary goal of a security policy?",
        "options": [
            "To establish security measures",
            "To prevent unauthorized access",
            "To provide guidelines for employee behavior",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is a common cause of data breaches?",
        "options": [
            "Weak passwords",
            "Unpatched software",
            "Insider threats",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What does the term 'social engineering' refer to?",
        "options": [
            "Manipulating people into divulging confidential information",
            "Using technical exploits to breach security",
            "Analyzing data to identify trends",
            "Encrypting sensitive information"
        ],
        "answer": "Manipulating people into divulging confidential information"
    },
    {
        "question": "During a security audit, a penetration tester discovers a web application that exposes sensitive data via its API. Which vulnerability is likely present?",
        "options": [
            "Improper authentication",
            "Insecure direct object references",
            "Cross-Site Request Forgery (CSRF)",
            "Broken access controls"
        ],
        "answer": "Broken access controls"
    },
    {
        "question": "A company uses a third-party service for cloud storage. What is a major security concern they should consider?",
        "options": [
            "Limited storage capacity",
            "Data encryption in transit",
            "Vendor lock-in",
            "Limited access controls"
        ],
        "answer": "Data encryption in transit"
    },
    {
        "question": "Which of the following techniques can be used to mitigate the risk of session fixation attacks?",
        "options": [
            "Regenerate session tokens upon login",
            "Use HTTP only cookies",
            "Implement strong password policies",
            "Use CAPTCHA on login forms"
        ],
        "answer": "Regenerate session tokens upon login"
    },
    {
        "question": "What type of attack involves manipulating the DNS resolution process to redirect users to malicious websites?",
        "options": [
            "DNS Spoofing",
            "Man-in-the-Middle",
            "ARP Spoofing",
            "Phishing"
        ],
        "answer": "DNS Spoofing"
    },
    {
        "question": "What is a common method to prevent SQL injection attacks?",
        "options": [
            "Using stored procedures",
            "Validating user input",
            "Escaping special characters",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "During a penetration test, the tester uses a tool that captures network traffic. What is this process called?",
        "options": [
            "Sniffing",
            "Scanning",
            "Exploitation",
            "Enumeration"
        ],
        "answer": "Sniffing"
    },
    {
        "question": "What is the primary role of an Information Security Officer?",
        "options": [
            "Conduct penetration tests",
            "Develop security policies and oversee implementation",
            "Monitor network traffic",
            "Manage user accounts"
        ],
        "answer": "Develop security policies and oversee implementation"
    },
    {
        "question": "In a wireless network, which encryption protocol is considered the weakest?",
        "options": [
            "WPA2",
            "WEP",
            "WPA3",
            "AES"
        ],
        "answer": "WEP"
    },
    {
        "question": "What does the term 'social engineering' primarily refer to?",
        "options": [
            "Manipulating systems to breach security",
            "Tricking individuals into revealing confidential information",
            "Analyzing user behavior for patterns",
            "Using malware to exploit software vulnerabilities"
        ],
        "answer": "Tricking individuals into revealing confidential information"
    },
    {
        "question": "Which of the following describes a botnet?",
        "options": [
            "A group of users sharing files",
            "A network of compromised computers controlled by an attacker",
            "A type of encryption algorithm",
            "A software vulnerability"
        ],
        "answer": "A network of compromised computers controlled by an attacker"
    },
    {
        "question": "What is a key difference between symmetric and asymmetric encryption?",
        "options": [
            "Symmetric uses one key; asymmetric uses two keys",
            "Symmetric is faster than asymmetric",
            "Asymmetric is more secure than symmetric",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is the primary purpose of data loss prevention (DLP) solutions?",
        "options": [
            "To encrypt sensitive data",
            "To prevent unauthorized access to sensitive information",
            "To monitor network traffic",
            "To back up data"
        ],
        "answer": "To prevent unauthorized access to sensitive information"
    },
    {
        "question": "In the context of incident response, what is the significance of the containment phase?",
        "options": [
            "To identify the incident",
            "To eliminate the threat",
            "To prevent the incident from spreading",
            "To recover lost data"
        ],
        "answer": "To prevent the incident from spreading"
    },
    {
        "question": "Which of the following is a sign of a potential DDoS attack?",
        "options": [
            "Sudden increase in legitimate traffic",
            "Inability to access services intermittently",
            "Increased error rates in network logs",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is the best method to protect against Cross-Site Scripting (XSS) vulnerabilities?",
        "options": [
            "Use of input validation",
            "Sanitizing user inputs",
            "Implementing Content Security Policy (CSP)",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "Which technique is used to compromise an account by using a combination of stolen usernames and passwords from various breaches?",
        "options": [
            "Credential stuffing",
            "Phishing",
            "Brute force attack",
            "Password spraying"
        ],
        "answer": "Credential stuffing"
    },
    {
        "question": "What is the primary function of an Intrusion Prevention System (IPS)?",
        "options": [
            "To detect unauthorized access attempts",
            "To actively block potential threats",
            "To log security incidents",
            "To provide user authentication"
        ],
        "answer": "To actively block potential threats"
    },
    {
        "question": "What is the purpose of security awareness training for employees?",
        "options": [
            "To teach technical skills",
            "To help employees recognize and respond to security threats",
            "To train employees on how to code securely",
            "To establish user permissions"
        ],
        "answer": "To help employees recognize and respond to security threats"
    },
    {
        "question": "In a penetration test, what does 'pivoting' refer to?",
        "options": [
            "Gaining access to additional systems after initial access",
            "Moving data from one location to another",
            "Changing user permissions",
            "Escaping a compromised system"
        ],
        "answer": "Gaining access to additional systems after initial access"
    },
    {
        "question": "What does the term 'vulnerability scanning' refer to?",
        "options": [
            "The process of identifying security weaknesses in systems",
            "The process of exploiting known vulnerabilities",
            "The process of monitoring network traffic",
            "The process of encrypting data"
        ],
        "answer": "The process of identifying security weaknesses in systems"
    },
    {
        "question": "What type of malware is designed to lock files and demand a ransom for decryption?",
        "options": [
            "Spyware",
            "Adware",
            "Ransomware",
            "Worm"
        ],
        "answer": "Ransomware"
    },
    {
        "question": "Which of the following is a best practice for securing web applications?",
        "options": [
            "Regularly updating software dependencies",
            "Implementing strong input validation",
            "Using HTTPS for all communication",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "An organization finds that an employee's account was compromised due to a phishing attack. What is the best immediate action to take?",
        "options": [
            "Reset the employee's password",
            "Ignore it if no sensitive data was accessed",
            "Notify all employees about the phishing attempt",
            "Close the account permanently"
        ],
        "answer": "Reset the employee's password"
    },
    {
        "question": "Which of the following describes the term 'exfiltration' in cybersecurity?",
        "options": [
            "Unauthorized access to a system",
            "Stealing data from a network",
            "Inserting malicious code into a program",
            "Spreading malware across networks"
        ],
        "answer": "Stealing data from a network"
    },
    {
        "question": "What type of malware is designed to hide its presence from detection?",
        "options": [
            "Trojan",
            "Rootkit",
            "Worm",
            "Adware"
        ],
        "answer": "Rootkit"
    },
    {
        "question": "Which of the following attacks involves an attacker intercepting and altering communications between two parties without their knowledge?",
        "options": [
            "Man-in-the-Middle attack",
            "DDoS attack",
            "SQL Injection",
            "Phishing"
        ],
        "answer": "Man-in-the-Middle attack"
    },
    {
        "question": "What is the purpose of a honeypot in cybersecurity?",
        "options": [
            "To detect and analyze attacks",
            "To prevent unauthorized access",
            "To store sensitive data",
            "To backup systems"
        ],
        "answer": "To detect and analyze attacks"
    },
    {
        "question": "In the context of wireless security, which encryption standard is considered the most secure?",
        "options": [
            "WEP",
            "WPA",
            "WPA2",
            "WPA3"
        ],
        "answer": "WPA3"
    },
    {
        "question": "What does the term 'social engineering' typically involve?",
        "options": [
            "Using technical methods to breach security",
            "Manipulating individuals into divulging confidential information",
            "Analyzing network traffic for vulnerabilities",
            "Writing malicious code"
        ],
        "answer": "Manipulating individuals into divulging confidential information"
    },
    {
        "question": "Which security measure can help mitigate the risk of SQL injection attacks?",
        "options": [
            "Input validation and parameterized queries",
            "Using a web application firewall",
            "Regular security audits",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "During a pen test, an attacker exploits a known vulnerability to gain access to a system. What is this phase called?",
        "options": [
            "Scanning",
            "Exploitation",
            "Reconnaissance",
            "Reporting"
        ],
        "answer": "Exploitation"
    },
    {
        "question": "What is the primary purpose of implementing two-factor authentication?",
        "options": [
            "To increase user convenience",
            "To enhance account security",
            "To speed up login processes",
            "To reduce password complexity"
        ],
        "answer": "To enhance account security"
    },
    {
        "question": "Which of the following is an example of a physical security measure?",
        "options": [
            "Firewalls",
            "Encryption",
            "Access control systems",
            "Antivirus software"
        ],
        "answer": "Access control systems"
    },
    {
        "question": "What is the primary focus of the incident response phase known as 'eradication'?",
        "options": [
            "To identify the source of the incident",
            "To remove the threat from the environment",
            "To recover affected systems",
            "To notify stakeholders"
        ],
        "answer": "To remove the threat from the environment"
    }

    

]
;
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
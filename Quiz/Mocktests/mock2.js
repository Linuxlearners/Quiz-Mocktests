
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "A penetration tester discovers that a web application does not sanitize user input before displaying it back to users. What type of vulnerability is present?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Remote Code Execution",
            "Command Injection"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "During a security assessment, an analyst notices that a network uses default credentials for several devices. What is the most significant risk associated with this practice?",
        "options": [
            "Increased performance",
            "Data encryption vulnerabilities",
            "Unauthorized access",
            "Enhanced security"
        ],
        "answer": "Unauthorized access"
    },
    {
        "question": "An organization implements a security policy that restricts users from installing unauthorized software. What type of control does this represent?",
        "options": [
            "Technical control",
            "Administrative control",
            "Physical control",
            "Operational control"
        ],
        "answer": "Administrative control"
    },
    {
        "question": "A hacker uses social engineering to manipulate an employee into revealing their password. What type of attack is this?",
        "options": [
            "Phishing",
            "Pretexting",
            "Spear phishing",
            "Baiting"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "Which of the following best describes a denial-of-service (DoS) attack?",
        "options": [
            "Exploiting a vulnerability to gain unauthorized access",
            "Flooding a service with requests to make it unavailable",
            "Using malware to steal data",
            "Manipulating data in transit"
        ],
        "answer": "Flooding a service with requests to make it unavailable"
    },
    {
        "question": "A company uses a firewall to block incoming traffic on all ports except 80 and 443. What type of firewall configuration is this?",
        "options": [
            "Stateful filtering",
            "Packet filtering",
            "Application layer filtering",
            "Proxy filtering"
        ],
        "answer": "Packet filtering"
    },
    {
        "question": "What is the purpose of a digital signature?",
        "options": [
            "To encrypt data",
            "To verify the authenticity of a message",
            "To compress files",
            "To store data securely"
        ],
        "answer": "To verify the authenticity of a message"
    },
    {
        "question": "An attacker uses a program to automate login attempts against a web application. What type of attack is being executed?",
        "options": [
            "SQL Injection",
            "Brute Force Attack",
            "Cross-Site Scripting",
            "Session Hijacking"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "Which of the following tools is commonly used for network scanning?",
        "options": [
            "Nmap",
            "Wireshark",
            "Metasploit",
            "Burp Suite"
        ],
        "answer": "Nmap"
    },
    {
        "question": "A security analyst observes unusual outbound traffic from a server. What could this indicate?",
        "options": [
            "Normal operation",
            "Potential data exfiltration",
            "Increased server performance",
            "Malware removal"
        ],
        "answer": "Potential data exfiltration"
    },
    {
        "question": "What does the principle of least privilege imply?",
        "options": [
            "Users should have the highest level of access possible",
            "Users should have only the access necessary for their role",
            "All users should have admin privileges",
            "No user should have access to sensitive data"
        ],
        "answer": "Users should have only the access necessary for their role"
    },
    {
        "question": "Which type of malware is designed to replicate itself and spread to other computers?",
        "options": [
            "Virus",
            "Trojan",
            "Ransomware",
            "Adware"
        ],
        "answer": "Virus"
    },
    {
        "question": "An organization wants to protect its sensitive data stored in the cloud. What is the best approach?",
        "options": [
            "Use strong passwords only",
            "Implement data encryption",
            "Regularly change service providers",
            "Disable user access"
        ],
        "answer": "Implement data encryption"
    },
    {
        "question": "What is a honeypot in cybersecurity?",
        "options": [
            "A tool for encrypting data",
            "A decoy system designed to attract attackers",
            "A method for monitoring user behavior",
            "A type of malware"
        ],
        "answer": "A decoy system designed to attract attackers"
    },
    {
        "question": "During a penetration test, an attacker discovers a vulnerability in a web application that allows for code execution. What is this vulnerability called?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "Remote File Inclusion (RFI)",
            "Local File Inclusion (LFI)",
            "Command Injection"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "What type of attack manipulates a user into providing sensitive information by posing as a trusted entity?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Spoofing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "What is the main purpose of an Intrusion Detection System (IDS)?",
        "options": [
            "To prevent unauthorized access",
            "To detect and alert on potential security breaches",
            "To encrypt data",
            "To block malware"
        ],
        "answer": "To detect and alert on potential security breaches"
    },
    {
        "question": "Which of the following is a characteristic of symmetric encryption?",
        "options": [
            "Uses two different keys for encryption and decryption",
            "Is slower than asymmetric encryption",
            "Uses the same key for both encryption and decryption",
            "Is less secure than asymmetric encryption"
        ],
        "answer": "Uses the same key for both encryption and decryption"
    },
    {
        "question": "An organization uses VLANs to segment its network. What is the primary benefit of this practice?",
        "options": [
            "Enhanced performance",
            "Improved user experience",
            "Increased security through isolation",
            "Reduced costs"
        ],
        "answer": "Increased security through isolation"
    },
    {
        "question": "What type of attack involves sending a large volume of traffic to overwhelm a target system?",
        "options": [
            "Man-in-the-Middle",
            "DoS",
            "Phishing",
            "Spoofing"
        ],
        "answer": "DoS"
    },
    {
        "question": "Which of the following best describes a vulnerability assessment?",
        "options": [
            "The process of identifying, quantifying, and prioritizing vulnerabilities",
            "The execution of exploits against known vulnerabilities",
            "The process of monitoring for security incidents",
            "The development of security policies"
        ],
        "answer": "The process of identifying, quantifying, and prioritizing vulnerabilities"
    },
    {
        "question": "What is the primary goal of a risk assessment?",
        "options": [
            "To identify vulnerabilities in systems",
            "To quantify the impact of risks",
            "To determine the likelihood of threat events",
            "To develop a security strategy"
        ],
        "answer": "To develop a security strategy"
    },
    {
        "question": "A company is monitoring user access logs for unusual behavior. What type of analysis is this?",
        "options": [
            "Behavioral analysis",
            "Statistical analysis",
            "Traffic analysis",
            "Forensic analysis"
        ],
        "answer": "Behavioral analysis"
    },
    {
        "question": "An attacker sends a fake email that appears to be from a legitimate source. What type of attack is this?",
        "options": [
            "Spoofing",
            "Phishing",
            "Baiting",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "What is the purpose of security information and event management (SIEM) systems?",
        "options": [
            "To block malicious traffic",
            "To analyze security alerts and logs",
            "To manage user accounts",
            "To encrypt sensitive data"
        ],
        "answer": "To analyze security alerts and logs"
    },
    {
        "question": "Which technique is used to discover the operating system of a remote host?",
        "options": [
            "Port scanning",
            "OS fingerprinting",
            "Network mapping",
            "Vulnerability scanning"
        ],
        "answer": "OS fingerprinting"
    },
    {
        "question": "What is the main function of a firewall?",
        "options": [
            "To encrypt data",
            "To block unauthorized access to or from a private network",
            "To monitor user behavior",
            "To scan for malware"
        ],
        "answer": "To block unauthorized access to or from a private network"
    },
    {
        "question": "What is a common method to detect SQL Injection vulnerabilities in a web application?",
        "options": [
            "Using parameterized queries",
            "Input validation",
            "Error-based techniques",
            "Data encryption"
        ],
        "answer": "Error-based techniques"
    },
    {
        "question": "Which of the following is a common indicator of compromise (IoC)?",
        "options": [
            "Frequent application crashes",
            "Unusual outbound traffic",
            "Increased login attempts",
            "High CPU usage"
        ],
        "answer": "Unusual outbound traffic"
    },
    {
        "question": "What does the term 'threat vector' refer to?",
        "options": [
            "The method by which an attacker gains access to a target",
            "A type of malware",
            "The source of a vulnerability",
            "An analysis of potential threats"
        ],
        "answer": "The method by which an attacker gains access to a target"
    },
    {
        "question": "What does a digital certificate verify?",
        "options": [
            "The integrity of a message",
            "The identity of the sender",
            "The security of a network",
            "The effectiveness of encryption"
        ],
        "answer": "The identity of the sender"
    },
    {
        "question": "Which of the following describes an APT (Advanced Persistent Threat)?",
        "options": [
            "A single attack with a known vector",
            "A prolonged and targeted cyberattack where the attacker gains access and remains undetected",
            "An attack that uses a large amount of bandwidth",
            "A type of malware that spreads rapidly"
        ],
        "answer": "A prolonged and targeted cyberattack where the attacker gains access and remains undetected"
    },
    {
        "question": "What is a common tool used for wireless network penetration testing?",
        "options": [
            "Wireshark",
            "Aircrack-ng",
            "Nmap",
            "Burp Suite"
        ],
        "answer": "Aircrack-ng"
    },
    {
        "question": "What is the primary objective of data encryption?",
        "options": [
            "To ensure data availability",
            "To protect data confidentiality",
            "To improve data integrity",
            "To simplify data access"
        ],
        "answer": "To protect data confidentiality"
    },
    {
        "question": "What does the term 'data exfiltration' refer to?",
        "options": [
            "The process of encrypting data",
            "The unauthorized transfer of data from a computer or network",
            "The backup of data to a secure location",
            "The restoration of data from backup"
        ],
        "answer": "The unauthorized transfer of data from a computer or network"
    },
    {
        "question": "Which of the following is an example of a reconnaissance technique?",
        "options": [
            "Port scanning",
            "SQL Injection",
            "Packet sniffing",
            "Password cracking"
        ],
        "answer": "Port scanning"
    },
    {
        "question": "What is the role of a patch management process?",
        "options": [
            "To ensure that all software is regularly updated",
            "To prevent all types of malware",
            "To encrypt sensitive data",
            "To monitor network traffic"
        ],
        "answer": "To ensure that all software is regularly updated"
    },
    {
        "question": "An organization implements a web application firewall (WAF). What is its primary function?",
        "options": [
            "To scan for malware",
            "To monitor traffic for malicious activity targeting web applications",
            "To encrypt web traffic",
            "To perform vulnerability assessments"
        ],
        "answer": "To monitor traffic for malicious activity targeting web applications"
    },
    {
        "question": "Which of the following can be used to identify open ports on a target machine?",
        "options": [
            "Network mapping",
            "Vulnerability scanning",
            "Port scanning",
            "Traffic analysis"
        ],
        "answer": "Port scanning"
    },
    {
        "question": "What type of analysis is performed on a piece of malware to understand its behavior?",
        "options": [
            "Static analysis",
            "Dynamic analysis",
            "Behavioral analysis",
            "Contextual analysis"
        ],
        "answer": "Dynamic analysis"
    },
    {
        "question": "Which type of attack involves intercepting and altering communications between two parties?",
        "options": [
            "Spoofing",
            "Man-in-the-Middle",
            "Phishing",
            "Brute Force"
        ],
        "answer": "Man-in-the-Middle"
    },
    {
        "question": "What does the acronym 'VPN' stand for?",
        "options": [
            "Virtual Private Network",
            "Variable Public Network",
            "Visual Protected Network",
            "Virtual Public Node"
        ],
        "answer": "Virtual Private Network"
    },
    {
        "question": "What is the primary purpose of a security policy?",
        "options": [
            "To define security measures and procedures within an organization",
            "To monitor network traffic",
            "To encrypt sensitive data",
            "To conduct vulnerability assessments"
        ],
        "answer": "To define security measures and procedures within an organization"
    },
    {
        "question": "In the context of cybersecurity, what does 'vulnerability' refer to?",
        "options": [
            "A potential threat to data integrity",
            "A weakness that can be exploited by attackers",
            "An outdated software version",
            "A type of malware"
        ],
        "answer": "A weakness that can be exploited by attackers"
    },
    {
        "question": "Which of the following is a method of protecting data in transit?",
        "options": [
            "Data encryption",
            "File compression",
            "Access controls",
            "Data backup"
        ],
        "answer": "Data encryption"
    },
    {
        "question": "What is a common characteristic of ransomware?",
        "options": [
            "It is designed to steal data",
            "It locks users out of their systems and demands payment for access",
            "It spreads via email attachments",
            "It replicates itself without user intervention"
        ],
        "answer": "It locks users out of their systems and demands payment for access"
    },
    {
        "question": "Which technique is commonly used to bypass network security measures?",
        "options": [
            "Social engineering",
            "Encryption",
            "Multi-factor authentication",
            "Data backup"
        ],
        "answer": "Social engineering"
    },
    {
        "question": "What does 'whaling' refer to in the context of phishing attacks?",
        "options": [
            "Attacking high-profile targets within an organization",
            "Phishing attempts aimed at individuals in the organization",
            "General phishing attacks against any user",
            "Spoofing email addresses"
        ],
        "answer": "Attacking high-profile targets within an organization"
    },
    {
        "question": "What is the primary purpose of a cybersecurity framework?",
        "options": [
            "To provide a set of guidelines for managing cybersecurity risks",
            "To enforce legal regulations",
            "To ensure compliance with software licensing",
            "To create network configurations"
        ],
        "answer": "To provide a set of guidelines for managing cybersecurity risks"
    },
    {
        "question": "What does the acronym 'DDoS' stand for?",
        "options": [
            "Distributed Denial of Service",
            "Digital Denial of Service",
            "Decentralized Data Service",
            "Dynamic Data Overload System"
        ],
        "answer": "Distributed Denial of Service"
    },
    {
        "question": "Which of the following is an example of an insider threat?",
        "options": [
            "A hacker breaking into a network from outside",
            "An employee intentionally leaking sensitive information",
            "A phishing email received by a user",
            "Malware installed by a third-party vendor"
        ],
        "answer": "An employee intentionally leaking sensitive information"
    },
    {
        "question": "What is the primary goal of ethical hacking?",
        "options": [
            "To exploit vulnerabilities for profit",
            "To assess and improve an organization's security posture",
            "To disrupt services for malicious purposes",
            "To collect sensitive user data"
        ],
        "answer": "To assess and improve an organization's security posture"
    },
    {
        "question": "What type of malware disguises itself as a legitimate application?",
        "options": [
            "Trojan",
            "Virus",
            "Worm",
            "Ransomware"
        ],
        "answer": "Trojan"
    },
    {
        "question": "What is the purpose of a certificate authority (CA)?",
        "options": [
            "To generate encryption keys",
            "To verify and issue digital certificates",
            "To monitor network traffic",
            "To provide antivirus solutions"
        ],
        "answer": "To verify and issue digital certificates"
    },
    {
        "question": "Which of the following describes an attack where an attacker intercepts communication between two parties and can alter the communication?",
        "options": [
            "Session hijacking",
            "Man-in-the-Middle",
            "DDoS",
            "Spoofing"
        ],
        "answer": "Man-in-the-Middle"
    },
    {
        "question": "What is a key feature of penetration testing?",
        "options": [
            "Automating security measures",
            "Simulating an attack to identify vulnerabilities",
            "Monitoring for real-time threats",
            "Creating security policies"
        ],
        "answer": "Simulating an attack to identify vulnerabilities"
    },
    {
        "question": "Which of the following best describes 'social engineering'?",
        "options": [
            "Exploiting human psychology to gain confidential information",
            "Using software vulnerabilities to gain access",
            "Attacking networks using brute force",
            "Manipulating computer systems to crash"
        ],
        "answer": "Exploiting human psychology to gain confidential information"
    },
    {
        "question": "What is the primary objective of a risk management plan?",
        "options": [
            "To eliminate all risks",
            "To identify and mitigate risks to an acceptable level",
            "To increase system performance",
            "To develop new software"
        ],
        "answer": "To identify and mitigate risks to an acceptable level"
    },
    {
        "question": "What is a common countermeasure against SQL Injection attacks?",
        "options": [
            "Input validation and parameterized queries",
            "Encrypting all database fields",
            "Using a firewall",
            "Regularly changing passwords"
        ],
        "answer": "Input validation and parameterized queries"
    },
    {
        "question": "In network security, what is 'least privilege' principle?",
        "options": [
            "All users have the same level of access",
            "Users have only the minimum permissions necessary to perform their jobs",
            "Every user is granted administrative access",
            "Users are prohibited from accessing any data"
        ],
        "answer": "Users have only the minimum permissions necessary to perform their jobs"
    },
    {
        "question": "Which type of attack uses multiple compromised systems to target a single system with overwhelming traffic?",
        "options": [
            "Phishing",
            "DDoS",
            "Spoofing",
            "Man-in-the-Middle"
        ],
        "answer": "DDoS"
    },
    {
        "question": "What does 'DNS spoofing' involve?",
        "options": [
            "Redirecting a user to a fraudulent website by altering DNS records",
            "Flooding the DNS server with requests",
            "Monitoring DNS queries for sensitive information",
            "Encrypting DNS traffic"
        ],
        "answer": "Redirecting a user to a fraudulent website by altering DNS records"
    },
    {
        "question": "An organization has a high volume of traffic to its website. What security measure can it implement to prevent DDoS attacks?",
        "options": [
            "Increase bandwidth",
            "Implement load balancing and rate limiting",
            "Change DNS servers",
            "Disable user access"
        ],
        "answer": "Implement load balancing and rate limiting"
    },
    {
        "question": "What does the acronym 'RAT' stand for in cybersecurity?",
        "options": [
            "Remote Access Tool",
            "Rapid Access Trojan",
            "Redundant Access Technology",
            "Remote Application Transfer"
        ],
        "answer": "Remote Access Tool"
    },
    {
        "question": "What is the primary goal of a vulnerability assessment?",
        "options": [
            "To identify and prioritize vulnerabilities",
            "To execute exploits",
            "To monitor network traffic",
            "To encrypt sensitive data"
        ],
        "answer": "To identify and prioritize vulnerabilities"
    },
    {
        "question": "Which tool is typically used to perform a packet capture?",
        "options": [
            "Nessus",
            "Metasploit",
            "Wireshark",
            "Burp Suite"
        ],
        "answer": "Wireshark"
    },
    {
        "question": "What does 'credential stuffing' refer to?",
        "options": [
            "Using stolen credentials to gain unauthorized access",
            "Injecting malicious code into credentials",
            "Changing user passwords frequently",
            "Creating fake credentials for social engineering"
        ],
        "answer": "Using stolen credentials to gain unauthorized access"
    },
    {
        "question": "Which of the following describes a 'zero-day' vulnerability?",
        "options": [
            "A vulnerability that has been publicly disclosed but not yet patched",
            "A known vulnerability that has a patch available",
            "A newly discovered vulnerability that is unknown to the vendor",
            "A vulnerability that is difficult to exploit"
        ],
        "answer": "A newly discovered vulnerability that is unknown to the vendor"
    },
    {
        "question": "What does the principle of 'defense in depth' refer to?",
        "options": [
            "Using multiple layers of security controls",
            "Relying solely on firewall protection",
            "Implementing user education programs",
            "Installing antivirus software"
        ],
        "answer": "Using multiple layers of security controls"
    },
    {
        "question": "What type of attack involves sending unsolicited emails with malicious links or attachments?",
        "options": [
            "Spear phishing",
            "Phishing",
            "Whaling",
            "Baiting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "What is a primary function of an access control list (ACL)?",
        "options": [
            "To log network activity",
            "To define permissions for users and groups",
            "To encrypt data",
            "To monitor traffic"
        ],
        "answer": "To define permissions for users and groups"
    },
    {
        "question": "What is a significant risk of using public Wi-Fi without a VPN?",
        "options": [
            "Improved internet speed",
            "Higher data encryption",
            "Increased risk of man-in-the-middle attacks",
            "Reduced network latency"
        ],
        "answer": "Increased risk of man-in-the-middle attacks"
    },
    {
        "question": "What is the purpose of multi-factor authentication (MFA)?",
        "options": [
            "To simplify user access",
            "To add additional layers of security beyond just a password",
            "To encrypt sensitive data",
            "To reduce the number of passwords needed"
        ],
        "answer": "To add additional layers of security beyond just a password"
    },
    {
        "question": "In a penetration test, what is the 'reconnaissance' phase primarily focused on?",
        "options": [
            "Exploiting vulnerabilities",
            "Gathering information about the target",
            "Implementing security controls",
            "Monitoring for attacks"
        ],
        "answer": "Gathering information about the target"
    },
    {
        "question": "What is the primary function of a web application firewall (WAF)?",
        "options": [
            "To filter and monitor HTTP traffic to and from a web application",
            "To encrypt web traffic",
            "To perform vulnerability assessments",
            "To manage user access"
        ],
        "answer": "To filter and monitor HTTP traffic to and from a web application"
    },
    {
        "question": "Which of the following best describes the term 'social engineering'?",
        "options": [
            "Using psychological manipulation to trick users into revealing confidential information",
            "Exploiting software vulnerabilities to gain access",
            "Intercepting communications between users",
            "Creating malicious software"
        ],
        "answer": "Using psychological manipulation to trick users into revealing confidential information"
    },
    {
        "question": "What is a common consequence of a successful phishing attack?",
        "options": [
            "Data loss",
            "Increased system performance",
            "Improved user awareness",
            "Reduced security measures"
        ],
        "answer": "Data loss"
    },
    {
        "question": "What does the term 'cyber threat intelligence' refer to?",
        "options": [
            "The process of analyzing threats to an organization",
            "Information about potential or current threats to an organization's assets",
            "The use of encryption to protect data",
            "Monitoring network traffic for suspicious activity"
        ],
        "answer": "Information about potential or current threats to an organization's assets"
    },
    {
        "question": "What is a significant risk associated with outdated software?",
        "options": [
            "Improved functionality",
            "Enhanced security",
            "Known vulnerabilities that can be exploited",
            "Increased performance"
        ],
        "answer": "Known vulnerabilities that can be exploited"
    },
    {
        "question": "What type of testing focuses on identifying security weaknesses in applications before deployment?",
        "options": [
            "Static testing",
            "Dynamic testing",
            "Penetration testing",
            "Regression testing"
        ],
        "answer": "Penetration testing"
    },
    {
        "question": "In cybersecurity, what is the term 'sandbox' used to describe?",
        "options": [
            "A secure environment for testing software",
            "A type of malware",
            "A method for data encryption",
            "A security policy"
        ],
        "answer": "A secure environment for testing software"
    },
    {
        "question": "What is the function of a network intrusion prevention system (NIPS)?",
        "options": [
            "To monitor network traffic for malicious activity",
            "To encrypt sensitive data",
            "To block unauthorized access to the network",
            "To conduct vulnerability assessments"
        ],
        "answer": "To monitor network traffic for malicious activity"
    },
    {
        "question": "Which of the following describes an exploit?",
        "options": [
            "A tool for scanning networks",
            "A piece of code that takes advantage of a vulnerability",
            "A method for securing systems",
            "An analysis of security policies"
        ],
        "answer": "A piece of code that takes advantage of a vulnerability"
    },
    {
        "question": "What is the primary goal of data loss prevention (DLP) solutions?",
        "options": [
            "To ensure data availability",
            "To monitor user behavior",
            "To protect sensitive data from unauthorized access or leaks",
            "To improve system performance"
        ],
        "answer": "To protect sensitive data from unauthorized access or leaks"
    },
    {
        "question": "In a network environment, what does the term 'pivoting' refer to?",
        "options": [
            "Moving from one network to another",
            "Using a compromised system to attack other systems",
            "Changing user access levels",
            "Redirecting traffic through a proxy"
        ],
        "answer": "Using a compromised system to attack other systems"
    },
    {
        "question": "What is the primary purpose of a security information and event management (SIEM) system?",
        "options": [
            "To prevent unauthorized access",
            "To aggregate and analyze security data from various sources",
            "To provide encryption for data in transit",
            "To manage user permissions"
        ],
        "answer": "To aggregate and analyze security data from various sources"
    },
    {
        "question": "What does the term 'cryptojacking' refer to?",
        "options": [
            "Stealing cryptographic keys",
            "Using someone else's computer to mine cryptocurrency without their consent",
            "Encrypting files for ransom",
            "Creating fake cryptocurrency wallets"
        ],
        "answer": "Using someone else's computer to mine cryptocurrency without their consent"
    },
    {
        "question": "What is a 'rootkit'?",
        "options": [
            "A tool for network intrusion prevention",
            "A type of malware that enables unauthorized access to a computer",
            "A security software used to detect vulnerabilities",
            "A program for data backup"
        ],
        "answer": "A type of malware that enables unauthorized access to a computer"
    },
    {
        "question": "What is the function of a honeypot in cybersecurity?",
        "options": [
            "To store sensitive data securely",
            "To attract and analyze potential attackers",
            "To encrypt data in transit",
            "To manage access control lists"
        ],
        "answer": "To attract and analyze potential attackers"
    },
    {
        "question": "Which attack involves manipulating the timing of packets to evade detection?",
        "options": [
            "Timing attack",
            "Packet sniffing",
            "Replay attack",
            "Session fixation"
        ],
        "answer": "Timing attack"
    },
    {
        "question": "In the context of penetration testing, what is 'post-exploitation'?",
        "options": [
            "The phase where vulnerabilities are identified",
            "The actions taken after gaining access to a system",
            "The analysis of network traffic",
            "The initial reconnaissance phase"
        ],
        "answer": "The actions taken after gaining access to a system"
    },
    {
        "question": "What is the main purpose of using a Web Application Firewall (WAF)?",
        "options": [
            "To protect against SQL injection and cross-site scripting",
            "To encrypt data between the client and server",
            "To monitor network bandwidth",
            "To perform vulnerability assessments"
        ],
        "answer": "To protect against SQL injection and cross-site scripting"
    },
    {
        "question": "Which of the following best defines 'phishing as a service'?",
        "options": [
            "A subscription service for targeted phishing campaigns",
            "Phishing attempts made by automated bots",
            "Legal services for phishing victims",
            "Training programs for cybersecurity professionals"
        ],
        "answer": "A subscription service for targeted phishing campaigns"
    },
    {
        "question": "What is the significance of a 'canary token'?",
        "options": [
            "A type of encryption key",
            "A decoy used to detect unauthorized access",
            "A backup solution for sensitive data",
            "A method for credential management"
        ],
        "answer": "A decoy used to detect unauthorized access"
    },
    {
        "question": "What does 'salting' refer to in password security?",
        "options": [
            "Adding random data to passwords before hashing",
            "Encrypting passwords with multiple keys",
            "Using only uppercase letters in passwords",
            "Storing passwords in plain text"
        ],
        "answer": "Adding random data to passwords before hashing"
    },
    {
        "question": "What is 'Domain Generation Algorithm' (DGA) used for?",
        "options": [
            "To generate domain names for malware communication",
            "To improve domain name resolution",
            "To secure domain name registration",
            "To perform load balancing"
        ],
        "answer": "To generate domain names for malware communication"
    },
    {
        "question": "What type of attack leverages social media to gather personal information for later exploitation?",
        "options": [
            "Phishing",
            "Spear phishing",
            "Social engineering",
            "Credential stuffing"
        ],
        "answer": "Social engineering"
    },
    {
        "question": "What is the role of a threat hunting team?",
        "options": [
            "To automatically block malware",
            "To proactively search for indicators of compromise within networks",
            "To analyze user behavior",
            "To manage incident response"
        ],
        "answer": "To proactively search for indicators of compromise within networks"
    },
    {
        "question": "In cybersecurity, what is a 'buffer overflow'?",
        "options": [
            "A method of data encryption",
            "An error that occurs when more data is written to a buffer than it can hold",
            "A technique to compress data",
            "A tool for network monitoring"
        ],
        "answer": "An error that occurs when more data is written to a buffer than it can hold"
    },
    {
        "question": "Which of the following techniques is used in a SQL injection attack?",
        "options": [
            "Modifying database queries to gain unauthorized access",
            "Encrypting database connections",
            "Using strong passwords for database access",
            "Storing database credentials securely"
        ],
        "answer": "Modifying database queries to gain unauthorized access"
    },
    {
        "question": "In penetration testing, what does the term 'Red Team' refer to?",
        "options": [
            "The defensive security team",
            "An offensive team that simulates real-world attacks",
            "A team focused on compliance and regulations",
            "The team that develops security policies"
        ],
        "answer": "An offensive team that simulates real-world attacks"
    },
    {
        "question": "What technique is commonly used to evade antivirus detection by modifying malware?",
        "options": [
            "Polymorphism",
            "Encryption",
            "Steganography",
            "Obfuscation"
        ],
        "answer": "Polymorphism"
    },
    {
        "question": "What is the primary purpose of a 'vulnerability disclosure policy'?",
        "options": [
            "To outline how vulnerabilities are identified",
            "To provide a framework for responsible reporting of vulnerabilities",
            "To set guidelines for patch management",
            "To define roles and responsibilities in a security team"
        ],
        "answer": "To provide a framework for responsible reporting of vulnerabilities"
    },
    {
        "question": "Which of the following is a key characteristic of a 'spear phishing' attack?",
        "options": [
            "It targets a broad audience",
            "It uses generic messages",
            "It involves extensive research on a specific target",
            "It typically does not involve email"
        ],
        "answer": "It involves extensive research on a specific target"
    },
    {
        "question": "What is 'buffer overflow' exploitation typically aimed at?",
        "options": [
            "Modifying application behavior",
            "Bypassing user authentication",
            "Gaining remote access to a system",
            "Causing denial of service"
        ],
        "answer": "Gaining remote access to a system"
    },
    {
        "question": "In a DDoS attack, what is the primary goal of a 'botnet'?",
        "options": [
            "To collect personal data",
            "To generate revenue through ads",
            "To control multiple compromised computers for coordinated attacks",
            "To spread malware via email"
        ],
        "answer": "To control multiple compromised computers for coordinated attacks"
    },
    {
        "question": "What does the term 'SQL injection' refer to?",
        "options": [
            "Inserting SQL queries into a database for retrieval",
            "Manipulating SQL queries to execute arbitrary code on the database",
            "Using SQL for unauthorized data access",
            "Encrypting SQL data for security"
        ],
        "answer": "Manipulating SQL queries to execute arbitrary code on the database"
    },
    {
        "question": "Which of the following is a common method for exfiltrating data from a secure network?",
        "options": [
            "Using secure FTP",
            "Data encryption",
            "Steganography in images",
            "Implementing firewalls"
        ],
        "answer": "Steganography in images"
    },
    {
        "question": "In cybersecurity, what does 'pivoting' allow an attacker to do?",
        "options": [
            "Gain access to another network after compromising a device",
            "Move data between different security zones",
            "Change attack strategies mid-attack",
            "Steal credentials without detection"
        ],
        "answer": "Gain access to another network after compromising a device"
    },
    {
        "question": "What does 'social engineering' primarily exploit?",
        "options": [
            "Technical vulnerabilities in software",
            "User trust and psychological manipulation",
            "Network protocols",
            "Hardware weaknesses"
        ],
        "answer": "User trust and psychological manipulation"
    },
    {
        "question": "What is the objective of 'credential stuffing' attacks?",
        "options": [
            "To brute-force passwords",
            "To use stolen credentials to access multiple accounts",
            "To harvest credentials from social media",
            "To encrypt user credentials"
        ],
        "answer": "To use stolen credentials to access multiple accounts"
    },
    {
        "question": "Which technique is used to detect unauthorized access to a system by monitoring for abnormal behavior?",
        "options": [
            "Signature-based detection",
            "Anomaly-based detection",
            "Heuristic analysis",
            "Statistical analysis"
        ],
        "answer": "Anomaly-based detection"
    },
    {
        "question": "In the context of encryption, what is the function of a 'nonce'?",
        "options": [
            "To store encrypted keys",
            "To ensure uniqueness in cryptographic operations",
            "To encrypt multiple messages at once",
            "To hash passwords"
        ],
        "answer": "To ensure uniqueness in cryptographic operations"
    },
    {
        "question": "What is a significant risk associated with using public Wi-Fi for sensitive transactions?",
        "options": [
            "Increased speed of connections",
            "Data interception by attackers",
            "Access to more bandwidth",
            "Automatic updates of applications"
        ],
        "answer": "Data interception by attackers"
    },
    {
        "question": "What does 'endpoint security' primarily focus on?",
        "options": [
            "Protecting server environments",
            "Securing devices that connect to the network",
            "Implementing network firewalls",
            "Monitoring cloud services"
        ],
        "answer": "Securing devices that connect to the network"
    },
    {
        "question": "In cybersecurity, what does 'red teaming' involve?",
        "options": [
            "Simulating adversarial attacks to test defenses",
            "Training employees on security practices",
            "Developing incident response plans",
            "Monitoring for compliance with regulations"
        ],
        "answer": "Simulating adversarial attacks to test defenses"
    },
    {
        "question": "Which attack method uses software to exploit vulnerabilities in applications automatically?",
        "options": [
            "SQL injection",
            "Exploitation frameworks",
            "Social engineering",
            "Denial of Service"
        ],
        "answer": "Exploitation frameworks"
    },
    {
        "question": "What does the term 'ethical hacking' imply?",
        "options": [
            "Hacking for malicious purposes",
            "Authorized testing of systems to identify vulnerabilities",
            "Hacking without any authorization",
            "Exploiting weaknesses for profit"
        ],
        "answer": "Authorized testing of systems to identify vulnerabilities"
    },
    {
        "question": "What is the main purpose of a 'web application firewall' (WAF)?",
        "options": [
            "To filter and monitor HTTP traffic to and from a web application",
            "To encrypt web traffic",
            "To provide intrusion detection",
            "To manage user authentication"
        ],
        "answer": "To filter and monitor HTTP traffic to and from a web application"
    },
    {
        "question": "What is 'ransomware' primarily designed to do?",
        "options": [
            "Steal personal information",
            "Encrypt files and demand payment for decryption",
            "Create botnets for DDoS attacks",
            "Monitor network traffic"
        ],
        "answer": "Encrypt files and demand payment for decryption"
    },
    {
        "question": "In the context of malware, what does the term 'keylogger' refer to?",
        "options": [
            "A tool used to encrypt files",
            "Software that records keystrokes to capture sensitive data",
            "A method to track user behavior",
            "A device used to bypass security measures"
        ],
        "answer": "Software that records keystrokes to capture sensitive data"
    },
    {
        "question": "What is the primary risk associated with 'zero-day vulnerabilities'?",
        "options": [
            "They are quickly patched by vendors",
            "They are well-documented and understood",
            "They can be exploited before a fix is available",
            "They are rarely targeted by attackers"
        ],
        "answer": "They can be exploited before a fix is available"
    },
    {
        "question": "In the context of information security, what does 'defense in depth' refer to?",
        "options": [
            "Using multiple security controls to protect information",
            "Implementing a single security solution",
            "Focusing only on perimeter defenses",
            "Training employees on security practices"
        ],
        "answer": "Using multiple security controls to protect information"
    },
    {
        "question": "What is a primary characteristic of 'malware as a service' (MaaS)?",
        "options": [
            "Malware is offered free of charge",
            "Attackers can rent malware tools for various attacks",
            "Malware is exclusively developed for state-sponsored attacks",
            "It focuses only on ransomware attacks"
        ],
        "answer": "Attackers can rent malware tools for various attacks"
    },
    {
        "question": "What is the primary goal of 'social engineering' attacks?",
        "options": [
            "To exploit technical vulnerabilities",
            "To manipulate individuals into divulging confidential information",
            "To gain unauthorized access to networks",
            "To conduct denial-of-service attacks"
        ],
        "answer": "To manipulate individuals into divulging confidential information"
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
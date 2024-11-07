
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "Emily, a penetration tester, finds a web application that uses unsanitized user input in its URL redirection. By manipulating the URL parameters, she can redirect users to a malicious site. What type of vulnerability is this?",
        "options": [
            "Open Redirect",
            "Cross-Site Scripting (XSS)",
            "URL Manipulation",
            "Parameter Injection"
        ],
        "answer": "Open Redirect"
    },
    {
        "question": "During a security audit, Ryan discovers that an organization uses default credentials on their IoT devices. An attacker can easily access these devices and compromise them. What type of security risk does this represent?",
        "options": [
            "Weak Authentication",
            "Insecure Configuration",
            "Unauthorized Access",
            "Data Breach"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "A company implements a new web application that allows users to upload images. However, the application does not check the file types or sizes, enabling attackers to upload executable scripts. What type of attack could result from this vulnerability?",
        "options": [
            "Remote File Inclusion (RFI)",
            "Arbitrary File Upload",
            "Cross-Site Scripting (XSS)",
            "Denial of Service (DoS)"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "Sophia, an ethical hacker, finds that a web application displays detailed error messages containing database information when inputs are invalid. What type of vulnerability does this indicate?",
        "options": [
            "Information Disclosure",
            "Weak Authentication",
            "Cross-Site Scripting (XSS)",
            "SQL Injection"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "A mobile app stores sensitive data in plain text within the device's storage. An attacker gains access to the device and retrieves this data. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Weak Encryption",
            "Data Breach",
            "Insufficient Security Controls"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "During a red team exercise, Alex uses a man-in-the-middle (MitM) attack to intercept and modify data between a user and a web application. What technique is Alex employing?",
        "options": [
            "Session Hijacking",
            "Packet Sniffing",
            "Replay Attack",
            "Data Manipulation"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "An attacker leverages an unpatched vulnerability in a web server to execute commands remotely. What type of attack does this represent?",
        "options": [
            "Remote Code Execution",
            "Privilege Escalation",
            "Denial of Service",
            "Cross-Site Scripting"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "A security analyst discovers that employees are falling victim to social engineering attacks by phone, where callers impersonate tech support. What type of attack is this?",
        "options": [
            "Vishing",
            "Phishing",
            "Smishing",
            "Pretexting"
        ],
        "answer": "Vishing"
    },
    {
        "question": "An organization has implemented a strict policy requiring multifactor authentication for access to sensitive systems. What type of security measure is this?",
        "options": [
            "Access Control",
            "User Authentication",
            "Network Segmentation",
            "Incident Response"
        ],
        "answer": "User Authentication"
    },
    {
        "question": "During a vulnerability assessment, David discovers that the organization's web application is susceptible to CSRF attacks. What type of vulnerability does this represent?",
        "options": [
            "Cross-Site Request Forgery (CSRF)",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Session Fixation"
        ],
        "answer": "Cross-Site Request Forgery (CSRF)"
    },
    {
        "question": "In a recent phishing attack, a user clicked on a link that led to a fake login page and entered their credentials. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Impersonation"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An organization is implementing an intrusion detection system (IDS) but discovers it cannot analyze encrypted traffic. What type of risk does this present?",
        "options": [
            "Blind Spot",
            "Data Leakage",
            "Insecure Configuration",
            "Weak Encryption"
        ],
        "answer": "Blind Spot"
    },
    {
        "question": "Alice, a security engineer, discovers a command injection vulnerability in a web application that allows attackers to execute arbitrary commands on the server. What type of attack does this represent?",
        "options": [
            "Command Injection",
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Remote File Inclusion (RFI)"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "A cloud provider experiences a data breach due to inadequate security measures. What type of attack is most likely responsible for this?",
        "options": [
            "Data Breach",
            "Malware Attack",
            "Denial of Service",
            "Insider Threat"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "A hacker uses a tool to scan an organization's network for open ports and services. What type of activity is this?",
        "options": [
            "Reconnaissance",
            "Exploitation",
            "Gaining Access",
            "Covering Tracks"
        ],
        "answer": "Reconnaissance"
    },
    {
        "question": "During an internal audit, a company discovers that employees have been sharing passwords for access to sensitive systems. What type of security risk does this present?",
        "options": [
            "Insufficient Access Control",
            "Weak Authentication",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "An organization fails to implement proper session management, allowing attackers to hijack user sessions. What type of vulnerability does this represent?",
        "options": [
            "Session Management Flaw",
            "Insecure Session Storage",
            "Weak Authentication",
            "Insufficient Security Controls"
        ],
        "answer": "Session Management Flaw"
    },
    {
        "question": "An attacker successfully executes an SQL injection attack on a database, allowing unauthorized access to sensitive information. What type of attack is this?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Data Breach",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "A company implements a security awareness training program to help employees recognize phishing attempts. What type of measure is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "While testing a web application, Noah finds that it does not validate SSL certificates. An attacker could exploit this flaw to perform which type of attack?",
        "options": [
            "Man-in-the-Middle Attack",
            "Session Hijacking",
            "Data Breach",
            "Phishing"
        ],
        "answer": "Man-in-the-Middle Attack"
    },
    {
        "question": "An organization uses a mobile application that allows users to store and share sensitive files. However, the app does not encrypt files at rest. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Weak Encryption",
            "Data Breach",
            "Insufficient Security Controls"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "An attacker successfully compromises a web server and installs malware that allows remote control. What type of attack is this?",
        "options": [
            "Remote Access Trojan (RAT)",
            "Denial of Service",
            "Data Breach",
            "Exploit Kit Attack"
        ],
        "answer": "Remote Access Trojan (RAT)"
    },
    {
        "question": "A user receives a text message claiming to be from their bank, requesting account verification. What type of attack is this?",
        "options": [
            "Smishing",
            "Phishing",
            "Vishing",
            "Impersonation"
        ],
        "answer": "Smishing"
    },
    {
        "question": "A company implements a firewall to protect its network from unauthorized access. What type of security measure is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "During a pentest, Jamie discovers that a web application is vulnerable to cross-site scripting. This vulnerability allows attackers to execute scripts in users' browsers. What type of attack does this represent?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Command Injection",
            "Remote Code Execution"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "An attacker compromises a system by exploiting an unpatched vulnerability. What type of attack does this represent?",
        "options": [
            "Zero-Day Attack",
            "Data Breach",
            "Privilege Escalation",
            "Denial of Service"
        ],
        "answer": "Zero-Day Attack"
    },
    {
        "question": "A security analyst finds that sensitive information is being logged in plain text files. What type of vulnerability does this indicate?",
        "options": [
            "Information Disclosure",
            "Weak Encryption",
            "Insecure Data Storage",
            "Data Breach"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "A company experiences a denial-of-service attack that overwhelms its web server. What type of attack does this represent?",
        "options": [
            "Distributed Denial of Service (DDoS)",
            "Data Breach",
            "Malware Attack",
            "Insider Threat"
        ],
        "answer": "Distributed Denial of Service (DDoS)"
    },
    {
        "question": "An organization uses a third-party service for email communication without reviewing its security practices. What type of risk does this present?",
        "options": [
            "Third-Party Risk",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Third-Party Risk"
    },
    {
        "question": "During a red team engagement, a tester simulates an attack on the organization's network. What type of activity is this?",
        "options": [
            "Penetration Testing",
            "Vulnerability Assessment",
            "Security Audit",
            "Risk Assessment"
        ],
        "answer": "Penetration Testing"
    },
    {
        "question": "An attacker exploits a flaw in an application to gain unauthorized access to a database. What type of attack does this represent?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Cross-Site Scripting (XSS)",
            "Session Hijacking"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "A hacker uses social engineering tactics to gather personal information about an employee. What type of attack is this?",
        "options": [
            "Pretexting",
            "Phishing",
            "Vishing",
            "Baiting"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An organization is storing sensitive customer data in a database without encryption. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Weak Encryption",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "During a security assessment, a tester finds that a web application does not validate user inputs. What type of vulnerability does this represent?",
        "options": [
            "Input Validation Flaw",
            "Injection Flaw",
            "Access Control Flaw",
            "Session Management Flaw"
        ],
        "answer": "Input Validation Flaw"
    },
    {
        "question": "An attacker uses a botnet to launch a DDoS attack against a web application. What type of attack is this?",
        "options": [
            "Distributed Denial of Service (DDoS)",
            "Data Breach",
            "Privilege Escalation",
            "Malware Attack"
        ],
        "answer": "Distributed Denial of Service (DDoS)"
    },
    {
        "question": "A web application is vulnerable to session fixation, allowing an attacker to hijack user sessions. What type of vulnerability does this represent?",
        "options": [
            "Session Management Flaw",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Input Validation Flaw"
        ],
        "answer": "Session Management Flaw"
    },
    {
        "question": "A company uses a cloud service for data storage but does not encrypt sensitive data. What type of risk does this present?",
        "options": [
            "Data Breach",
            "Insecure Data Storage",
            "Compliance Risk",
            "Third-Party Risk"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "An attacker uses an exploit kit to target vulnerabilities in a web application. What type of attack does this represent?",
        "options": [
            "Exploit Kit Attack",
            "Denial of Service",
            "Data Breach",
            "Phishing"
        ],
        "answer": "Exploit Kit Attack"
    },
    {
        "question": "During a security review, a company finds that employees are using easily guessable passwords. What type of vulnerability does this indicate?",
        "options": [
            "Weak Password Policy",
            "Insufficient Security Controls",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Weak Password Policy"
    },
    {
        "question": "An attacker gains access to a system by exploiting an unpatched vulnerability in the operating system. What type of attack does this represent?",
        "options": [
            "Zero-Day Attack",
            "Privilege Escalation",
            "Data Breach",
            "Denial of Service"
        ],
        "answer": "Zero-Day Attack"
    },
    {
        "question": "During an internal audit, a company discovers that sensitive information is being shared over unsecured channels. What type of risk does this represent?",
        "options": [
            "Data Breach",
            "Insecure Communication",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insecure Communication"
    },
    {
        "question": "A company employs an incident response team to handle security breaches. What type of control is this?",
        "options": [
            "Detective Control",
            "Corrective Control",
            "Preventive Control",
            "Compensatory Control"
        ],
        "answer": "Corrective Control"
    },
    {
        "question": "An organization finds that its employees have been falling for phishing attacks, revealing their credentials. What type of training should be implemented?",
        "options": [
            "Security Awareness Training",
            "Technical Training",
            "Incident Response Training",
            "Risk Management Training"
        ],
        "answer": "Security Awareness Training"
    },
    {
        "question": "A web application does not enforce HTTPS, allowing sensitive data to be transmitted in plain text. What type of vulnerability does this represent?",
        "options": [
            "Insecure Transmission",
            "Weak Encryption",
            "Data Breach",
            "Information Disclosure"
        ],
        "answer": "Insecure Transmission"
    },
    {
        "question": "During a security assessment, a tester finds that a web application allows users to perform actions without proper authorization. What type of vulnerability does this represent?",
        "options": [
            "Access Control Flaw",
            "Input Validation Flaw",
            "Session Management Flaw",
            "Injection Flaw"
        ],
        "answer": "Access Control Flaw"
    },
    {
        "question": "An attacker exploits a vulnerability in a third-party plugin used by a web application. What type of attack does this represent?",
        "options": [
            "Plugin Vulnerability Exploit",
            "Third-Party Risk",
            "Denial of Service",
            "Data Breach"
        ],
        "answer": "Plugin Vulnerability Exploit"
    },
    {
        "question": "A security team discovers malware on a company computer that exfiltrates data. What type of attack is this?",
        "options": [
            "Data Exfiltration",
            "Malware Attack",
            "Phishing",
            "Insider Threat"
        ],
        "answer": "Data Exfiltration"
    },
    {
        "question": "An organization experiences a DDoS attack that disrupts its online services. What type of attack does this represent?",
        "options": [
            "Denial of Service",
            "Data Breach",
            "Exploit Kit Attack",
            "Insider Threat"
        ],
        "answer": "Denial of Service"
    },
    {
        "question": "A user receives an email with a link to a fraudulent website that looks identical to their bank's login page. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Vishing",
            "Whaling"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An attacker uses a rogue access point to intercept network traffic. What type of attack does this represent?",
        "options": [
            "Evil Twin Attack",
            "Man-in-the-Middle Attack",
            "Packet Sniffing",
            "Data Breach"
        ],
        "answer": "Evil Twin Attack"
    },
    {
        "question": "An organization uses a password manager to store and generate complex passwords. What type of security measure is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "During a security assessment, a tester discovers that an application does not restrict the size of uploaded files. What type of vulnerability does this represent?",
        "options": [
            "File Upload Vulnerability",
            "Insecure Data Storage",
            "Information Disclosure",
            "Input Validation Flaw"
        ],
        "answer": "File Upload Vulnerability"
    },
    {
        "question": "A company implements data loss prevention (DLP) measures to protect sensitive information. What type of control is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "An attacker finds an open port on a web server and exploits it to gain access. What type of activity is this?",
        "options": [
            "Exploitation",
            "Reconnaissance",
            "Data Breach",
            "Privilege Escalation"
        ],
        "answer": "Exploitation"
    },
    {
        "question": "A company discovers that a former employee accessed sensitive data after leaving the organization. What type of risk does this present?",
        "options": [
            "Insider Threat",
            "Data Breach",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insider Threat"
    },
    {
        "question": "During a security audit, a company discovers that security patches are not being applied regularly. What type of vulnerability does this indicate?",
        "options": [
            "Patch Management Flaw",
            "Insecure Configuration",
            "Weak Authentication",
            "Data Breach"
        ],
        "answer": "Patch Management Flaw"
    },
    {
        "question": "A user receives a phone call from someone claiming to be from the IT department, asking for their password. What type of attack is this?",
        "options": [
            "Vishing",
            "Phishing",
            "Pretexting",
            "Baiting"
        ],
        "answer": "Vishing"
    },
    {
        "question": "An organization implements network segmentation to protect sensitive data. What type of security measure is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "An attacker intercepts communications between a user and a server without detection. What type of attack does this represent?",
        "options": [
            "Man-in-the-Middle Attack",
            "Session Hijacking",
            "Data Breach",
            "Exploit Kit Attack"
        ],
        "answer": "Man-in-the-Middle Attack"
    },
    {
        "question": "A company implements security policies to govern user access to sensitive systems. What type of control is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "During a pentest, a tester identifies a flaw that allows users to gain administrative privileges without authorization. What type of vulnerability does this represent?",
        "options": [
            "Privilege Escalation",
            "Access Control Flaw",
            "Injection Flaw",
            "Session Management Flaw"
        ],
        "answer": "Privilege Escalation"
    },
    {
        "question": "An attacker uses a phishing email to trick users into revealing their credentials. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Vishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A company experiences a data breach due to unencrypted backups. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Weak Encryption",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "An organization conducts regular vulnerability assessments and penetration tests. What type of proactive security measure is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "An attacker leverages a flaw in a web application to exfiltrate sensitive data. What type of attack does this represent?",
        "options": [
            "Data Exfiltration",
            "SQL Injection",
            "Command Injection",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Data Exfiltration"
    },
    {
        "question": "During a security assessment, a tester discovers that an application does not enforce password complexity. What type of vulnerability does this indicate?",
        "options": [
            "Weak Password Policy",
            "Insufficient Security Controls",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Weak Password Policy"
    },
    {
        "question": "An organization uses cloud services but fails to implement proper security measures. What type of risk does this present?",
        "options": [
            "Cloud Security Risk",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Cloud Security Risk"
    },
    {
        "question": "An organization discovers that an employee has been using their personal email to handle sensitive company information. What type of risk does this present?",
        "options": [
            "Data Breach",
            "Insider Threat",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insider Threat"
    },
    {
        "question": "A company allows employees to work from home without implementing a secure VPN. What type of vulnerability does this represent?",
        "options": [
            "Insecure Remote Access",
            "Weak Authentication",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Insecure Remote Access"
    },
    {
        "question": "An attacker uses a vulnerability scanner to identify weaknesses in a network. What type of activity is this?",
        "options": [
            "Reconnaissance",
            "Exploitation",
            "Gaining Access",
            "Covering Tracks"
        ],
        "answer": "Reconnaissance"
    },
    {
        "question": "A company finds that its web application does not limit login attempts, making it vulnerable to brute-force attacks. What type of vulnerability does this represent?",
        "options": [
            "Access Control Flaw",
            "Weak Authentication",
            "Session Management Flaw",
            "Input Validation Flaw"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "During a security review, it is discovered that employee devices are not regularly updated with security patches. What risk does this present?",
        "options": [
            "Patch Management Flaw",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Patch Management Flaw"
    },
    {
        "question": "An attacker uses social media to gather information about a target before launching a phishing attack. What type of activity is this?",
        "options": [
            "Pretexting",
            "Phishing",
            "Spear Phishing",
            "Information Gathering"
        ],
        "answer": "Information Gathering"
    },
    {
        "question": "A web application stores user passwords without any encryption. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Weak Encryption",
            "Data Breach",
            "Weak Password Policy"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "An organization fails to monitor its network for suspicious activity. What type of risk does this represent?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Detective Control Failure",
            "Data Breach"
        ],
        "answer": "Detective Control Failure"
    },
    {
        "question": "An attacker uses a social engineering technique to trick an employee into revealing confidential information. What type of attack is this?",
        "options": [
            "Phishing",
            "Pretexting",
            "Vishing",
            "Spear Phishing"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An organization implements multi-factor authentication but fails to enforce it company-wide. What type of vulnerability does this indicate?",
        "options": [
            "Insufficient Security Controls",
            "Weak Authentication",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insufficient Security Controls"
    },
    {
        "question": "During a security audit, a company finds that many systems still use outdated software. What risk does this pose?",
        "options": [
            "Patch Management Flaw",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Patch Management Flaw"
    },
    {
        "question": "A company’s website is defaced after an attacker exploits a vulnerability. What type of attack is this?",
        "options": [
            "Website Defacement",
            "Data Breach",
            "Malware Attack",
            "Denial of Service"
        ],
        "answer": "Website Defacement"
    },
    {
        "question": "A company discovers that a third-party vendor has mishandled customer data. What type of risk does this present?",
        "options": [
            "Third-Party Risk",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Third-Party Risk"
    },
    {
        "question": "An organization allows employees to use personal devices to access company resources. What type of risk does this represent?",
        "options": [
            "BYOD Risk",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "BYOD Risk"
    },
    {
        "question": "An attacker leverages a known vulnerability in a web application to steal user data. What type of attack does this represent?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Cross-Site Scripting (XSS)",
            "Data Breach"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "A company implements strict password policies, but employees still share passwords. What type of risk does this indicate?",
        "options": [
            "Weak Authentication",
            "Insufficient Security Controls",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insufficient Security Controls"
    },
    {
        "question": "An attacker uses a bot to send thousands of requests to a server, overwhelming it. What type of attack is this?",
        "options": [
            "Denial of Service",
            "Distributed Denial of Service (DDoS)",
            "Data Breach",
            "Exploitation"
        ],
        "answer": "Denial of Service"
    },
    {
        "question": "An organization discovers that sensitive data is being transmitted without encryption. What type of vulnerability does this represent?",
        "options": [
            "Insecure Transmission",
            "Weak Encryption",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Insecure Transmission"
    },
    {
        "question": "A security analyst identifies that a web application is vulnerable to CSRF attacks. What type of vulnerability does this represent?",
        "options": [
            "Cross-Site Request Forgery (CSRF)",
            "Session Management Flaw",
            "Access Control Flaw",
            "Injection Flaw"
        ],
        "answer": "Cross-Site Request Forgery (CSRF)"
    },
    {
        "question": "A company implements endpoint protection but neglects mobile devices. What risk does this present?",
        "options": [
            "Mobile Security Risk",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Mobile Security Risk"
    },
    {
        "question": "An organization fails to segregate duties, allowing one employee to control critical systems without oversight. What type of risk does this present?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Insider Threat",
            "Data Breach"
        ],
        "answer": "Insider Threat"
    },
    {
        "question": "During a security assessment, it is found that user sessions do not expire after a period of inactivity. What vulnerability does this represent?",
        "options": [
            "Session Management Flaw",
            "Insecure Session Storage",
            "Weak Authentication",
            "Access Control Flaw"
        ],
        "answer": "Session Management Flaw"
    },
    {
        "question": "An attacker exploits a misconfigured cloud storage service to access sensitive files. What type of attack does this represent?",
        "options": [
            "Data Breach",
            "Cloud Misconfiguration",
            "Malware Attack",
            "Privilege Escalation"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "A company conducts a risk assessment and identifies potential threats to its data. What type of activity is this?",
        "options": [
            "Risk Management",
            "Compliance Audit",
            "Vulnerability Assessment",
            "Penetration Testing"
        ],
        "answer": "Risk Management"
    },
    {
        "question": "An organization uses outdated software that is no longer supported. What type of risk does this represent?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Data Breach",
            "Patch Management Flaw"
        ],
        "answer": "Patch Management Flaw"
    },
    {
        "question": "An attacker sends an email that appears to be from a trusted source, asking for sensitive information. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Vishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A web application fails to validate the content of uploaded files, allowing an attacker to upload malicious scripts. What type of vulnerability does this represent?",
        "options": [
            "File Upload Vulnerability",
            "Input Validation Flaw",
            "Access Control Flaw",
            "Session Management Flaw"
        ],
        "answer": "File Upload Vulnerability"
    },
    {
        "question": "A company fails to log and monitor user activities on its systems. What risk does this present?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Detective Control Failure",
            "Data Breach"
        ],
        "answer": "Detective Control Failure"
    },
    {
        "question": "An organization stores sensitive data in plaintext. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Weak Encryption",
            "Data Breach",
            "Compliance Risk"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "An attacker uses a phishing email to install malware on a victim's computer. What type of attack is this?",
        "options": [
            "Malware Attack",
            "Spear Phishing",
            "Social Engineering",
            "Ransomware"
        ],
        "answer": "Malware Attack"
    },
    {
        "question": "A company implements a firewall but fails to configure it properly. What type of risk does this present?",
        "options": [
            "Configuration Risk",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Configuration Risk"
    },
    {
        "question": "A company conducts regular employee training on security awareness. What type of control is this?",
        "options": [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensating Control"
        ],
        "answer": "Preventive Control"
    },
    {
        "question": "An attacker uses a vulnerability in a web application to execute arbitrary code. What type of attack does this represent?",
        "options": [
            "Remote Code Execution",
            "Data Breach",
            "Denial of Service",
            "Privilege Escalation"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "A company discovers that a user account has been compromised and used for unauthorized access. What type of risk does this represent?",
        "options": [
            "Credential Theft",
            "Insider Threat",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Credential Theft"
    },
    {
        "question": "An attacker attempts to guess a user's password by trying multiple combinations. What type of attack is this?",
        "options": [
            "Brute Force Attack",
            "Dictionary Attack",
            "Phishing",
            "Social Engineering"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "A security team discovers a malware infection on a company server. What type of response should be initiated?",
        "options": [
            "Incident Response",
            "Risk Assessment",
            "Vulnerability Assessment",
            "Penetration Testing"
        ],
        "answer": "Incident Response"
    },
    {
        "question": "An organization implements access controls but fails to regularly review them. What type of risk does this present?",
        "options": [
            "Access Control Flaw",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Access Control Flaw"
    },
    {
        "question": "An attacker uses an open Wi-Fi network to intercept sensitive communications. What type of vulnerability does this represent?",
        "options": [
            "Insecure Network",
            "Data Breach",
            "Man-in-the-Middle Attack",
            "Weak Encryption"
        ],
        "answer": "Insecure Network"
    },
    {
        "question": "A company discovers that its database has been compromised due to weak access controls. What type of incident has occurred?",
        "options": [
            "Data Breach",
            "Insider Threat",
            "Malware Attack",
            "Social Engineering"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "An organization conducts a penetration test to identify security weaknesses. What type of assessment is this?",
        "options": [
            "Active Assessment",
            "Passive Assessment",
            "Compliance Audit",
            "Risk Assessment"
        ],
        "answer": "Active Assessment"
    },
    {
        "question": "A company discovers that an employee is accessing unauthorized files on the network. What type of risk does this represent?",
        "options": [
            "Insider Threat",
            "Data Breach",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insider Threat"
    },
    {
        "question": "An organization allows employees to connect to the corporate network using personal devices without any security checks. What type of risk does this represent?",
        "options": [
            "BYOD Risk",
            "Data Breach",
            "Operational Risk",
            "Compliance Risk"
        ],
        "answer": "BYOD Risk"
    },
    {
        "question": "An attacker uses a SQL injection attack to gain unauthorized access to a database. What type of attack is this?",
        "options": [
            "Injection Attack",
            "Cross-Site Scripting (XSS)",
            "Phishing",
            "Malware Attack"
        ],
        "answer": "Injection Attack"
    },
    {
        "question": "A company does not have an incident response plan in place. What type of risk does this pose?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Data Breach",
            "Response Failure"
        ],
        "answer": "Response Failure"
    },
    {
        "question": "An organization uses a third-party service that does not comply with security standards. What risk does this present?",
        "options": [
            "Third-Party Risk",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Third-Party Risk"
    },
    {
        "question": "A security analyst finds that multiple user accounts share the same password. What vulnerability does this indicate?",
        "options": [
            "Weak Password Policy",
            "Access Control Flaw",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Weak Password Policy"
    },
    {
        "question": "A company implements a strong firewall but fails to update its rules regularly. What type of risk does this represent?",
        "options": [
            "Configuration Risk",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Configuration Risk"
    },
    {
        "question": "An attacker uses malware to capture keystrokes and steal user credentials. What type of attack is this?",
        "options": [
            "Keylogging",
            "Phishing",
            "Social Engineering",
            "Ransomware"
        ],
        "answer": "Keylogging"
    },
    {
        "question": "A company allows employees to use weak passwords for their accounts. What type of risk does this pose?",
        "options": [
            "Weak Authentication",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "An organization discovers that sensitive data is stored in an unsecured cloud service. What type of vulnerability does this represent?",
        "options": [
            "Data Breach",
            "Cloud Misconfiguration",
            "Insecure Data Storage",
            "Compliance Risk"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "An attacker performs a DNS spoofing attack to redirect users to a malicious website. What type of attack is this?",
        "options": [
            "Man-in-the-Middle Attack",
            "Phishing",
            "Denial of Service",
            "Spoofing"
        ],
        "answer": "Spoofing"
    },
    {
        "question": "A company requires users to change passwords every 90 days but does not enforce complexity requirements. What vulnerability does this indicate?",
        "options": [
            "Weak Password Policy",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Weak Password Policy"
    },
    {
        "question": "An organization performs regular vulnerability scans but does not act on the findings. What type of risk does this represent?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Detective Control Failure",
            "Data Breach"
        ],
        "answer": "Detective Control Failure"
    },
    {
        "question": "A company implements a policy requiring encryption for all sensitive data but fails to monitor compliance. What risk does this present?",
        "options": [
            "Compliance Risk",
            "Operational Risk",
            "Data Breach",
            "Control Failure"
        ],
        "answer": "Compliance Risk"
    },
    {
        "question": "An attacker uses phishing to trick an employee into revealing their login credentials. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Vishing",
            "Social Engineering"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An organization implements strong access controls but fails to revoke access for terminated employees. What type of risk does this present?",
        "options": [
            "Insider Threat",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Insider Threat"
    },
    {
        "question": "A web application fails to properly validate user input, allowing for a command injection attack. What type of vulnerability does this represent?",
        "options": [
            "Input Validation Flaw",
            "Access Control Flaw",
            "Session Management Flaw",
            "Data Breach"
        ],
        "answer": "Input Validation Flaw"
    },
    {
        "question": "An organization fails to conduct regular security awareness training for employees. What type of risk does this present?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Human Factor Risk",
            "Data Breach"
        ],
        "answer": "Human Factor Risk"
    },
    {
        "question": "An attacker uses a botnet to conduct a distributed denial of service attack against a target. What type of attack is this?",
        "options": [
            "Distributed Denial of Service (DDoS)",
            "Malware Attack",
            "Data Breach",
            "Exploitation"
        ],
        "answer": "Distributed Denial of Service (DDoS)"
    },
    {
        "question": "A company discovers that sensitive customer information has been leaked online. What type of incident has occurred?",
        "options": [
            "Data Breach",
            "Insider Threat",
            "Malware Attack",
            "Social Engineering"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "An organization uses an outdated version of a software application known to have vulnerabilities. What risk does this represent?",
        "options": [
            "Patch Management Flaw",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Patch Management Flaw"
    },
    {
        "question": "An attacker sends a voicemail that appears to be from a trusted source, requesting sensitive information. What type of attack is this?",
        "options": [
            "Vishing",
            "Phishing",
            "Pretexting",
            "Social Engineering"
        ],
        "answer": "Vishing"
    },
    {
        "question": "A company implements logging but fails to regularly review the logs. What type of risk does this present?",
        "options": [
            "Detective Control Failure",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Detective Control Failure"
    },
    {
        "question": "An organization uses two-factor authentication but does not enforce it for all users. What vulnerability does this indicate?",
        "options": [
            "Insufficient Security Controls",
            "Weak Authentication",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insufficient Security Controls"
    },
    {
        "question": "A company fails to securely configure its web servers, making them vulnerable to attacks. What type of risk does this present?",
        "options": [
            "Configuration Risk",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Configuration Risk"
    },
    {
        "question": "An attacker gains physical access to a server room and steals data. What type of attack is this?",
        "options": [
            "Physical Security Breach",
            "Data Breach",
            "Insider Threat",
            "Malware Attack"
        ],
        "answer": "Physical Security Breach"
    },
    {
        "question": "A company finds that its website has been redirected to a competitor’s site due to DNS manipulation. What type of attack is this?",
        "options": [
            "DNS Spoofing",
            "Phishing",
            "Man-in-the-Middle Attack",
            "Denial of Service"
        ],
        "answer": "DNS Spoofing"
    },
    {
        "question": "An organization discovers that its data backup system has not been tested for recovery. What type of risk does this present?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Data Breach",
            "Disaster Recovery Risk"
        ],
        "answer": "Disaster Recovery Risk"
    },
    {
        "question": "An organization fails to regularly update its software, leaving it vulnerable to known exploits. What type of risk does this present?",
        "options": [
            "Patch Management Risk",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Patch Management Risk"
    },
    {
        "question": "A company implements multi-factor authentication but allows users to disable it. What type of vulnerability does this represent?",
        "options": [
            "Weak Authentication",
            "Insufficient Security Controls",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "An attacker gains access to a company's network by exploiting a vulnerability in a third-party application. What type of attack is this?",
        "options": [
            "Third-Party Risk Exploit",
            "Data Breach",
            "Phishing",
            "Insider Threat"
        ],
        "answer": "Third-Party Risk Exploit"
    },
    {
        "question": "A user receives an email with a link to a fake website designed to steal their credentials. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Vishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A company notices that employees are frequently sharing sensitive information via unsecured messaging apps. What type of risk does this indicate?",
        "options": [
            "Insecure Communication",
            "Data Breach",
            "Compliance Risk",
            "Operational Risk"
        ],
        "answer": "Insecure Communication"
    },
    {
        "question": "During a security audit, an organization discovers that it does not have a clear data classification policy. What type of risk does this represent?",
        "options": [
            "Compliance Risk",
            "Operational Risk",
            "Information Disclosure",
            "Data Breach"
        ],
        "answer": "Compliance Risk"
    },
    {
        "question": "An employee clicks on a link in an email that installs ransomware on their computer. What type of attack is this?",
        "options": [
            "Ransomware Attack",
            "Malware Attack",
            "Phishing",
            "Social Engineering"
        ],
        "answer": "Ransomware Attack"
    },
    {
        "question": "A security analyst finds that an organization's firewall is misconfigured, allowing unnecessary inbound traffic. What type of vulnerability does this indicate?",
        "options": [
            "Configuration Vulnerability",
            "Operational Risk",
            "Compliance Risk",
            "Data Breach"
        ],
        "answer": "Configuration Vulnerability"
    },
    {
        "question": "A company stores sensitive customer data in a cloud service without understanding the provider's security measures. What type of risk does this present?",
        "options": [
            "Cloud Security Risk",
            "Compliance Risk",
            "Operational Risk",
            "Data Breach"
        ],
        "answer": "Cloud Security Risk"
    },
    {
        "question": "An organization discovers that sensitive data is being transmitted over unencrypted channels. What type of vulnerability does this represent?",
        "options": [
            "Insecure Transmission",
            "Weak Encryption",
            "Data Breach",
            "Information Disclosure"
        ],
        "answer": "Insecure Transmission"
    },
    {
        "question": "A user has their account compromised after using the same password across multiple sites. What type of risk does this represent?",
        "options": [
            "Credential Stuffing Risk",
            "Weak Password Policy",
            "Insider Threat",
            "Data Breach"
        ],
        "answer": "Credential Stuffing Risk"
    },
    {
        "question": "An attacker employs social engineering tactics to trick an employee into revealing sensitive information. What type of attack is this?",
        "options": [
            "Social Engineering Attack",
            "Phishing",
            "Vishing",
            "Pretexting"
        ],
        "answer": "Social Engineering Attack"
    },
    {
        "question": "A company implements an intrusion detection system (IDS) to monitor network traffic for suspicious activity. What type of control is this?",
        "options": [
            "Detective Control",
            "Preventive Control",
            "Corrective Control",
            "Compensating Control"
        ],
        "answer": "Detective Control"
    },
    {
        "question": "An organization conducts a tabletop exercise to test its incident response plan. What type of assessment is this?",
        "options": [
            "Tabletop Assessment",
            "Compliance Audit",
            "Risk Assessment",
            "Vulnerability Assessment"
        ],
        "answer": "Tabletop Assessment"
    },
    {
        "question": "All quizzes and Mock Test are created by Kamal Varma.",
        "options": [
            "Thank you for your time.",
            "I trust you have gained valuable insights.",
            "Wishing you all the best in your future endeavors.",
            "All statements are accurate."
        ],
        "answer": "All statements are accurate."
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
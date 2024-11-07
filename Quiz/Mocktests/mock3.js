
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "Thomas, a cloud security professional, is performing a security assessment on cloud services to identify any loopholes. He detects a vulnerability in a bare-metal cloud server that can enable hackers to implant malicious backdoors in its firmware. He also identified that an installed backdoor can persist even if the server is reallocated to new clients or businesses that use it as an IaaS. What is the type of cloud attack that can be performed by exploiting the vulnerability discussed in the above scenario?",
        "options": [
            "Man-in-the-cloud (MITC) attack",
            "Cloudborne attack",
            "Cloud cryptojacking",
            "Metadata spoofing attack"
        ],
        "answer": "Cloudborne attack"
    },
    {
        "question": "Calvin, a software developer, uses a feature that helps him auto-generate the content of a web page without manual involvement and is integrated with SSI directives. This leads to a vulnerability in the developed web application as this feature accepts remote user inputs and uses them on the page. Hackers can exploit this feature and pass malicious SSI directives as input values to perform malicious activities such as modifying and erasing server files. What is the type of injection attack Calvin’s web application is susceptible to?",
        "options": [
            "Server-side includes injection",
            "Server-side template injection",
            "Server-side JS injection",
            "CRLF injection"
        ],
        "answer": "Server-side includes injection"
    },
    {
        "question": "During a penetration test, Alex discovers that the web application is vulnerable to an attack that allows him to execute arbitrary commands on the server by injecting crafted input into a vulnerable API endpoint. Which type of attack is Alex likely exploiting?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Remote File Inclusion",
            "Cross-Site Scripting"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "Jessica notices that a web application does not implement proper session management, allowing an attacker to hijack a user’s session using a stolen session ID. What type of vulnerability is this indicative of?",
        "options": [
            "Cross-Site Request Forgery",
            "Session Fixation",
            "Session Hijacking",
            "Broken Authentication"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "A company uses a third-party API to facilitate payments. During a security audit, it is discovered that the API does not enforce strict input validation, allowing attackers to manipulate the payment parameters. What type of vulnerability is this?",
        "options": [
            "Injection Attack",
            "Broken Access Control",
            "Insecure Direct Object Reference",
            "Sensitive Data Exposure"
        ],
        "answer": "Injection Attack"
    },
    {
        "question": "Mike, an ethical hacker, is testing a mobile application that uses a local database for storing user credentials. He finds that the database is not encrypted and can be accessed by malicious users. What type of vulnerability does this represent?",
        "options": [
            "Data Leakage",
            "Insecure Data Storage",
            "Insufficient Encryption",
            "Weak Authentication"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "During an internal assessment, a security analyst discovers that sensitive user data is being logged in plain text within the application logs. What type of security issue does this present?",
        "options": [
            "Data Exposure",
            "Improper Logging",
            "Weak Cryptography",
            "Unrestricted File Upload"
        ],
        "answer": "Data Exposure"
    },
    {
        "question": "A recent vulnerability report reveals that an organization's web server allows directory traversal, enabling attackers to access files outside the intended directory. What type of vulnerability is this?",
        "options": [
            "Cross-Site Scripting",
            "Path Traversal",
            "File Inclusion",
            "Access Control Vulnerability"
        ],
        "answer": "Path Traversal"
    },
    {
        "question": "Liam, a security consultant, is assessing a corporate network that uses outdated software and has not applied critical security patches. Which type of vulnerability is this likely to lead to?",
        "options": [
            "Zero-Day Vulnerability",
            "Known Vulnerability",
            "Exploitable Vulnerability",
            "Unpatched Software Vulnerability"
        ],
        "answer": "Unpatched Software Vulnerability"
    },
    {
        "question": "In a security assessment, a pentester uses a tool to enumerate user accounts on a web application. This tool successfully extracts usernames and email addresses from the application. What type of attack is being executed?",
        "options": [
            "Credential Stuffing",
            "User Enumeration",
            "Phishing",
            "Brute Force Attack"
        ],
        "answer": "User Enumeration"
    },
    {
        "question": "An organization implements a security measure that requires users to enter a verification code sent to their registered mobile device after inputting their password. What type of security control is this?",
        "options": [
            "Single Factor Authentication",
            "Two-Factor Authentication",
            "Multi-Factor Authentication",
            "Contextual Authentication"
        ],
        "answer": "Two-Factor Authentication"
    },
    {
        "question": "During a security review, it is found that an application does not validate or sanitize user inputs, which can lead to various injection attacks. What type of best practice should be implemented to mitigate this risk?",
        "options": [
            "Input Validation",
            "Error Handling",
            "Access Control",
            "Session Management"
        ],
        "answer": "Input Validation"
    },
    {
        "question": "A web application is designed to display user comments but fails to properly encode output, allowing an attacker to inject malicious scripts that execute in the context of other users’ browsers. What vulnerability is this?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "Cross-Site Request Forgery (CSRF)",
            "SQL Injection",
            "Command Injection"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "An attacker successfully accesses a web application by exploiting a vulnerability that allows them to execute commands through a vulnerable input field. What type of attack did the attacker perform?",
        "options": [
            "SQL Injection",
            "Remote Code Execution",
            "Cross-Site Scripting",
            "Command Injection"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "A corporate policy mandates the encryption of all sensitive data stored on devices. However, a recent audit revealed that some laptops still contain unencrypted sensitive information. What type of risk does this pose?",
        "options": [
            "Data Breach Risk",
            "Compliance Risk",
            "Operational Risk",
            "Reputational Risk"
        ],
        "answer": "Data Breach Risk"
    },
    {
        "question": "During a threat modeling session, a security analyst identifies an external service that provides sensitive user data without adequate security controls. What type of threat does this scenario represent?",
        "options": [
            "Insider Threat",
            "Third-Party Risk",
            "Advanced Persistent Threat",
            "Social Engineering Threat"
        ],
        "answer": "Third-Party Risk"
    },
    {
        "question": "When performing a phishing attack, what is the primary goal of the attacker?",
        "options": [
            "To install malware on a victim’s device",
            "To gain unauthorized access to a network",
            "To trick users into providing sensitive information",
            "To launch a DDoS attack"
        ],
        "answer": "To trick users into providing sensitive information"
    },
    {
        "question": "An organization’s firewall logs show repeated attempts to access a web application from an unknown IP address. This behavior is indicative of what type of attack?",
        "options": [
            "Brute Force Attack",
            "Reconnaissance Attack",
            "Denial-of-Service Attack",
            "Data Exfiltration"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "What kind of attack exploits the trust a user has in a legitimate website by using a fake but similar-looking website to harvest credentials?",
        "options": [
            "Spear Phishing",
            "Pharming",
            "Man-in-the-Middle",
            "Credential Harvesting"
        ],
        "answer": "Pharming"
    },
    {
        "question": "In a network that uses WPA2 encryption, an attacker captures the authentication handshake and then tries to recover the password. What type of attack is this?",
        "options": [
            "WPA Handshake Attack",
            "Evil Twin Attack",
            "Deauthentication Attack",
            "Dictionary Attack"
        ],
        "answer": "WPA Handshake Attack"
    },
    {
        "question": "A company's employees are often targeted by attackers posing as IT support staff requesting their passwords. What type of social engineering technique is being used here?",
        "options": [
            "Phishing",
            "Pretexting",
            "Baiting",
            "Quizzing"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "During a red team exercise, the team gains unauthorized access to a database containing sensitive information by exploiting a vulnerability in the web application’s backend API. What type of vulnerability did they likely exploit?",
        "options": [
            "Insecure Direct Object Reference",
            "Insufficient Authentication",
            "Broken Access Control",
            "SQL Injection"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "An application allows users to upload files without validating the file type, which could lead to executing malicious code on the server. What type of vulnerability does this represent?",
        "options": [
            "File Inclusion Vulnerability",
            "Insecure File Upload",
            "Cross-Site Scripting",
            "Remote Code Execution"
        ],
        "answer": "Insecure File Upload"
    },
    {
        "question": "Sophia, a security analyst, is reviewing the permissions of users within a cloud environment and notices that some users have excessive privileges that are not required for their roles. What type of vulnerability does this represent?",
        "options": [
            "Privilege Escalation",
            "Excessive Permissions",
            "Misconfigured Security Controls",
            "Insufficient Access Control"
        ],
        "answer": "Excessive Permissions"
    },
    {
        "question": "During a code review, an analyst finds that error messages reveal detailed information about the application’s structure and database. What type of vulnerability is this indicative of?",
        "options": [
            "Information Leakage",
            "Data Exposure",
            "Code Injection",
            "Insufficient Logging"
        ],
        "answer": "Information Leakage"
    },
    {
        "question": "An attacker sends a user a link that appears to lead to a legitimate site but redirects them to a malicious site. What is this technique called?",
        "options": [
            "Phishing",
            "URL Spoofing",
            "Social Engineering",
            "Drive-by Download"
        ],
        "answer": "URL Spoofing"
    },
    {
        "question": "In a pen test, a team successfully retrieves sensitive files from a server due to inadequate access controls. What is the primary type of vulnerability exploited?",
        "options": [
            "Access Control Vulnerability",
            "Insecure File Permissions",
            "Data Leakage",
            "Code Injection"
        ],
        "answer": "Access Control Vulnerability"
    },
    {
        "question": "A recent audit reveals that users can access the API without any authentication, exposing sensitive data. What type of vulnerability does this represent?",
        "options": [
            "Broken Access Control",
            "Unvalidated Redirects",
            "Lack of Encryption",
            "Insufficient Authentication"
        ],
        "answer": "Broken Access Control"
    },
    {
        "question": "When conducting a security review, an analyst discovers that a web application has no CAPTCHA on forms that could be exploited for automated submissions. What is this vulnerability commonly associated with?",
        "options": [
            "Spam and Abuse",
            "Denial of Service",
            "Information Leakage",
            "Injection Attacks"
        ],
        "answer": "Spam and Abuse"
    },
    {
        "question": "An attacker compromises a web application and alters the HTML content to display fake login forms. What type of attack is this an example of?",
        "options": [
            "Cross-Site Scripting",
            "Phishing",
            "Cross-Site Request Forgery",
            "Malicious Redirection"
        ],
        "answer": "Cross-Site Scripting"
    },
    {
        "question": "While testing a network, an ethical hacker uses a tool to intercept traffic between a user and a web application. What type of attack is being simulated?",
        "options": [
            "Packet Sniffing",
            "Man-in-the-Middle",
            "Session Hijacking",
            "Eavesdropping"
        ],
        "answer": "Man-in-the-Middle"
    },
    {
        "question": "An organization uses a weak encryption algorithm for sensitive data transmission, making it susceptible to decryption by attackers. What type of vulnerability does this represent?",
        "options": [
            "Weak Encryption",
            "Data Exposure",
            "Insecure Communication",
            "Cryptographic Flaw"
        ],
        "answer": "Weak Encryption"
    },
    {
        "question": "A security team finds that several endpoints are vulnerable due to outdated software packages. What is the best practice to mitigate this risk?",
        "options": [
            "Implement Regular Patching",
            "Conduct User Training",
            "Enhance Firewall Rules",
            "Increase Network Segmentation"
        ],
        "answer": "Implement Regular Patching"
    },
    {
        "question": "An organization fails to limit the amount of data returned by a query, exposing too much information. What type of vulnerability does this represent?",
        "options": [
            "Data Leakage",
            "Information Disclosure",
            "Insecure Direct Object Reference",
            "Excessive Data Exposure"
        ],
        "answer": "Excessive Data Exposure"
    },
    {
        "question": "During a security assessment, an analyst discovers a web application that does not implement secure cookie attributes, making them vulnerable to session hijacking. What cookie attribute should be enforced?",
        "options": [
            "HttpOnly",
            "Secure",
            "SameSite",
            "Path"
        ],
        "answer": "HttpOnly"
    },
    {
        "question": "A user inadvertently downloads malware from a legitimate-looking email attachment. What type of attack does this represent?",
        "options": [
            "Spear Phishing",
            "Whaling",
            "Ransomware",
            "Social Engineering"
        ],
        "answer": "Spear Phishing"
    },
    {
        "question": "An attacker exploits a web application vulnerability that allows for arbitrary file upload, which can lead to code execution on the server. What type of vulnerability is this?",
        "options": [
            "Remote File Inclusion",
            "Local File Inclusion",
            "Insecure File Upload",
            "File Path Traversal"
        ],
        "answer": "Insecure File Upload"
    },
    {
        "question": "A vulnerability assessment tool reports that certain ports are open and vulnerable on a target system. What is the risk associated with this finding?",
        "options": [
            "Potential Unauthorized Access",
            "Network Segmentation Failure",
            "Increased Latency",
            "Data Corruption"
        ],
        "answer": "Potential Unauthorized Access"
    },
    {
        "question": "An organization stores sensitive data in plaintext in a database without encryption. What type of vulnerability does this represent?",
        "options": [
            "Data Exposure",
            "Weak Authentication",
            "Insecure Data Storage",
            "Lack of Data Encryption"
        ],
        "answer": "Lack of Data Encryption"
    },
    {
        "question": "During a red team exercise, the team uses social engineering techniques to gain access to a facility. What type of attack is being simulated?",
        "options": [
            "Physical Security Breach",
            "Insider Threat",
            "Phishing",
            "Credential Theft"
        ],
        "answer": "Physical Security Breach"
    },
    {
        "question": "A web application is found to be vulnerable to SQL injection due to a lack of input sanitization. What could be the consequence of this vulnerability?",
        "options": [
            "Database Manipulation",
            "Data Encryption Breach",
            "Session Fixation",
            "Cross-Site Scripting"
        ],
        "answer": "Database Manipulation"
    },
    {
        "question": "An application allows users to reset their passwords without sufficient verification, exposing it to unauthorized changes. What type of vulnerability is this?",
        "options": [
            "Broken Authentication",
            "Weak Password Policy",
            "Insufficient Security Controls",
            "Lack of Input Validation"
        ],
        "answer": "Broken Authentication"
    },
    {
        "question": "A user receives an email from a colleague asking for their login credentials for a system upgrade. What type of social engineering attack is this?",
        "options": [
            "Phishing",
            "Pretexting",
            "Baiting",
            "Vishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An attacker captures the data being sent between a client and a server without altering it. What type of attack is this?",
        "options": [
            "Man-in-the-Middle",
            "Eavesdropping",
            "Session Hijacking",
            "Spoofing"
        ],
        "answer": "Eavesdropping"
    },
    {
        "question": "A cloud application fails to properly segregate data between different tenants, allowing one tenant to access another's data. What type of vulnerability does this represent?",
        "options": [
            "Data Leakage",
            "Insufficient Access Control",
            "Multi-Tenancy Vulnerability",
            "Insecure Data Storage"
        ],
        "answer": "Multi-Tenancy Vulnerability"
    },
    {
        "question": "A vulnerability scan reveals that an application has not implemented proper SSL/TLS encryption for sensitive data in transit. What is the primary risk associated with this issue?",
        "options": [
            "Data Interception",
            "Data Corruption",
            "Data Theft",
            "Data Manipulation"
        ],
        "answer": "Data Interception"
    },
    {
        "question": "An organization is subject to a data breach due to an unsecured API that exposes sensitive user information. What type of risk does this pose?",
        "options": [
            "Reputational Risk",
            "Operational Risk",
            "Financial Risk",
            "Compliance Risk"
        ],
        "answer": "Reputational Risk"
    },
    {
        "question": "A security team identifies that sensitive information is being transmitted in the URL rather than the body of the request. What type of vulnerability does this represent?",
        "options": [
            "Sensitive Data Exposure",
            "Insecure Communication",
            "Information Disclosure",
            "Improper Input Validation"
        ],
        "answer": "Sensitive Data Exposure"
    },
    {
        "question": "An employee is targeted by an attacker who calls pretending to be from IT, asking for their password to fix a 'critical issue'. What type of attack is this?",
        "options": [
            "Phishing",
            "Pretexting",
            "Vishing",
            "Baiting"
        ],
        "answer": "Vishing"
    },
    {
        "question": "A company's website is susceptible to Cross-Site Request Forgery (CSRF) due to a lack of anti-CSRF tokens. What can be a consequence of this vulnerability?",
        "options": [
            "Unauthorized Transactions",
            "Data Loss",
            "Information Disclosure",
            "Denial of Service"
        ],
        "answer": "Unauthorized Transactions"
    },
    {
        "question": "A vulnerability scan identifies that the organization has services running on default ports, exposing them to potential attacks. What is the main concern with this finding?",
        "options": [
            "Increased Attack Surface",
            "Poor Network Segmentation",
            "Weak Authentication Mechanisms",
            "Data Exposure"
        ],
        "answer": "Increased Attack Surface"
    },
    {
        "question": "A security audit reveals that a web application is vulnerable to Cross-Site Scripting (XSS) because it does not sanitize user inputs properly. What type of attack could an attacker perform?",
        "options": [
            "Data Theft",
            "Session Hijacking",
            "Malware Installation",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "An attacker uses a fake wireless access point to intercept traffic and capture credentials. What is this type of attack known as?",
        "options": [
            "Evil Twin Attack",
            "Man-in-the-Middle Attack",
            "Rogue Access Point Attack",
            "Packet Sniffing"
        ],
        "answer": "Evil Twin Attack"
    },
    {
        "question": "A security incident occurs when an unauthorized user gains access to a system by exploiting a known vulnerability. What type of attack does this represent?",
        "options": [
            "Exploited Vulnerability",
            "Insider Attack",
            "Privilege Escalation",
            "Data Breach"
        ],
        "answer": "Exploited Vulnerability"
    },
    {
        "question": "During a social engineering test, a user is tricked into revealing their password over the phone. What technique was likely used?",
        "options": [
            "Phishing",
            "Pretexting",
            "Impersonation",
            "Baiting"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An organization fails to regularly update its software, leaving it vulnerable to exploits. What is the main type of risk associated with this behavior?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Financial Risk",
            "Reputational Risk"
        ],
        "answer": "Operational Risk"
    },
    {
        "question": "A vulnerability scan reveals that a company’s database is exposed to the internet without any firewall protection. What is the primary risk here?",
        "options": [
            "Data Breach",
            "Denial of Service",
            "Malware Infection",
            "Unpatched Software Vulnerability"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "During a security assessment, an analyst identifies that an application is susceptible to Clickjacking. What type of attack does this vulnerability enable?",
        "options": [
            "Phishing",
            "Data Theft",
            "Session Hijacking",
            "Unauthorized Actions"
        ],
        "answer": "Unauthorized Actions"
    },
    {
        "question": "A network administrator discovers a rogue access point within the organization's network. What type of attack does this represent?",
        "options": [
            "Man-in-the-Middle",
            "Evil Twin",
            "Denial of Service",
            "Rogue Device Attack"
        ],
        "answer": "Evil Twin"
    },
    {
        "question": "An application’s session management is compromised, allowing an attacker to reuse an old session ID. What type of vulnerability is this?",
        "options": [
            "Session Fixation",
            "Session Hijacking",
            "Replay Attack",
            "Cross-Site Request Forgery"
        ],
        "answer": "Session Fixation"
    },
    {
        "question": "An organization's application logs reveal that an attacker attempted to access unauthorized files by manipulating the URL. What type of vulnerability is being exploited?",
        "options": [
            "Path Traversal",
            "SQL Injection",
            "Command Injection",
            "Access Control Vulnerability"
        ],
        "answer": "Path Traversal"
    },
    {
        "question": "During a penetration test, a tester uses brute-force techniques to crack a user's password. What type of attack is this?",
        "options": [
            "Credential Stuffing",
            "Password Cracking",
            "Social Engineering",
            "Insider Attack"
        ],
        "answer": "Password Cracking"
    },
    {
        "question": "An attacker gains unauthorized access to an organization’s network by exploiting a known vulnerability in unpatched software. What type of vulnerability is this?",
        "options": [
            "Known Vulnerability",
            "Zero-Day Vulnerability",
            "Misconfiguration",
            "Access Control Vulnerability"
        ],
        "answer": "Known Vulnerability"
    },
    {
        "question": "A security team discovers that an application does not properly handle user inputs, leading to potential XSS attacks. What type of countermeasure should be implemented?",
        "options": [
            "Input Validation",
            "Content Security Policy",
            "Regular Expressions",
            "Data Encryption"
        ],
        "answer": "Input Validation"
    },
    {
        "question": "During an assessment, a security analyst notices that user passwords are stored in plaintext in a configuration file. What type of vulnerability does this represent?",
        "options": [
            "Data Exposure",
            "Weak Password Storage",
            "Insecure Configuration",
            "Insufficient Security Controls"
        ],
        "answer": "Weak Password Storage"
    },
    {
        "question": "An attacker sends a user to a malicious site after they click on a link in an email. What type of attack is being executed?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "URL Spoofing",
            "Malware Distribution"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A vulnerability scan shows that a web server is running outdated software versions. What is the primary risk associated with this finding?",
        "options": [
            "Increased Attack Surface",
            "Exploitable Vulnerability",
            "Poor Performance",
            "Data Corruption"
        ],
        "answer": "Increased Attack Surface"
    },
    {
        "question": "An employee receives a USB drive labeled 'Confidential' and plugs it into their computer, unknowingly installing malware. What type of attack is this?",
        "options": [
            "Baiting",
            "Phishing",
            "Social Engineering",
            "Insider Threat"
        ],
        "answer": "Baiting"
    },
    {
        "question": "During a security audit, a developer discovers that user inputs are being directly used in SQL queries without sanitization. What type of vulnerability does this represent?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Cross-Site Scripting",
            "Data Exposure"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "A user is tricked into providing their credentials on a fake login page that mimics a legitimate service. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Spoofing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An organization fails to enforce access control policies, allowing unauthorized users to access sensitive information. What type of vulnerability does this represent?",
        "options": [
            "Broken Access Control",
            "Privilege Escalation",
            "Insufficient Security Controls",
            "Access Control Vulnerability"
        ],
        "answer": "Broken Access Control"
    },
    {
        "question": "A user unknowingly clicks on a link in a phishing email and downloads ransomware, encrypting their files. What type of attack is this?",
        "options": [
            "Malware Infection",
            "Phishing",
            "Drive-by Download",
            "Spear Phishing"
        ],
        "answer": "Malware Infection"
    },
    {
        "question": "During a vulnerability assessment, a web application is found to have default credentials still active. What type of vulnerability does this represent?",
        "options": [
            "Weak Authentication",
            "Credential Stuffing",
            "Access Control Vulnerability",
            "Misconfiguration"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "An attacker uses a social engineering tactic to convince an employee to reset their password. What type of technique is being used?",
        "options": [
            "Phishing",
            "Pretexting",
            "Spear Phishing",
            "Baiting"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "A security assessment identifies that user sessions do not expire after a period of inactivity, allowing session hijacking. What type of vulnerability is this?",
        "options": [
            "Session Fixation",
            "Session Hijacking",
            "Session Management Flaw",
            "Insecure Session Storage"
        ],
        "answer": "Session Management Flaw"
    },
    {
        "question": "An organization uses a common default password for all user accounts, exposing them to attacks. What type of vulnerability does this represent?",
        "options": [
            "Weak Authentication",
            "Credential Stuffing",
            "Insufficient Security Controls",
            "Password Reuse"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "An attacker uses an automated tool to exploit vulnerabilities in a system without the owner's knowledge. What type of attack does this represent?",
        "options": [
            "Automated Attack",
            "Exploit Kit Attack",
            "Zero-Day Attack",
            "Rogue Software Attack"
        ],
        "answer": "Exploit Kit Attack"
    },
    {
        "question": "During a security assessment, an organization discovers that sensitive data is being logged without encryption. What type of vulnerability does this represent?",
        "options": [
            "Data Exposure",
            "Weak Encryption",
            "Insecure Logging",
            "Insufficient Security Controls"
        ],
        "answer": "Insecure Logging"
    },
    {
        "question": "An organization experiences a denial of service attack, overwhelming their servers and making services unavailable. What type of attack is this?",
        "options": [
            "Distributed Denial of Service",
            "Malware Attack",
            "Network Attack",
            "Resource Exhaustion Attack"
        ],
        "answer": "Distributed Denial of Service"
    },
    {
        "question": "An attacker exploits a flaw in an application to execute arbitrary code on a server. What type of vulnerability is this?",
        "options": [
            "Remote Code Execution",
            "Local File Inclusion",
            "Command Injection",
            "Buffer Overflow"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "During a security assessment, a tester finds that an application is vulnerable to open redirects, allowing attackers to redirect users to malicious sites. What type of vulnerability is this?",
        "options": [
            "Open Redirect",
            "Cross-Site Scripting",
            "URL Spoofing",
            "Information Disclosure"
        ],
        "answer": "Open Redirect"
    },
    {
        "question": "A user receives a phone call from someone claiming to be from tech support, asking them to install remote access software. What type of attack does this represent?",
        "options": [
            "Vishing",
            "Pretexting",
            "Phishing",
            "Social Engineering"
        ],
        "answer": "Vishing"
    },
    {
        "question": "An attacker uses SQL injection to manipulate a web application's database, resulting in unauthorized data access. What type of attack is this?",
        "options": [
            "Data Breach",
            "Information Disclosure",
            "Data Corruption",
            "Database Manipulation"
        ],
        "answer": "Database Manipulation"
    },
    {
        "question": "A developer discovers that an application allows for cross-origin resource sharing without proper validation. What type of vulnerability does this represent?",
        "options": [
            "Cross-Origin Resource Sharing Vulnerability",
            "Cross-Site Scripting",
            "Cross-Site Request Forgery",
            "Insecure Configuration"
        ],
        "answer": "Cross-Origin Resource Sharing Vulnerability"
    },
    {
        "question": "A vulnerability scan identifies an application using outdated libraries known to have security issues. What is the primary risk associated with this finding?",
        "options": [
            "Exploitable Vulnerability",
            "Data Breach",
            "Operational Risk",
            "Compliance Risk"
        ],
        "answer": "Exploitable Vulnerability"
    },
    {
        "question": "During a security assessment, a tester finds that sensitive user information is being sent over unencrypted channels. What type of vulnerability does this represent?",
        "options": [
            "Insecure Communication",
            "Data Leakage",
            "Weak Encryption",
            "Information Disclosure"
        ],
        "answer": "Insecure Communication"
    },
    {
        "question": "An organization discovers that an employee has access to sensitive financial records that exceed their role's requirements. What type of vulnerability does this represent?",
        "options": [
            "Excessive Permissions",
            "Misconfigured Access Control",
            "Privilege Escalation",
            "Insufficient Access Control"
        ],
        "answer": "Excessive Permissions"
    },
    {
        "question": "An application is vulnerable to Cross-Site Request Forgery (CSRF) attacks because it does not include anti-CSRF tokens. What is a potential consequence of this vulnerability?",
        "options": [
            "Unauthorized Actions",
            "Information Disclosure",
            "Data Loss",
            "Session Hijacking"
        ],
        "answer": "Unauthorized Actions"
    },
    {
        "question": "During a security review, a team finds that the application logs contain sensitive information. What type of vulnerability does this represent?",
        "options": [
            "Information Leakage",
            "Data Exposure",
            "Weak Logging Practices",
            "Insecure Logging"
        ],
        "answer": "Sensitive Data Exposure"
    },
    {
        "question": "An attacker exploits an application vulnerability to execute commands on the server. What type of vulnerability is this?",
        "options": [
            "Command Injection",
            "Remote Code Execution",
            "SQL Injection",
            "Local File Inclusion"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "A user receives an email that appears to be from their bank asking for account verification. What type of attack is this?",
        "options": [
            "Phishing",
            "Vishing",
            "Spear Phishing",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An attacker uses a vulnerability in an application to alter its behavior without authorization. What type of attack is this?",
        "options": [
            "Data Manipulation",
            "Command Injection",
            "Remote Code Execution",
            "SQL Injection"
        ],
        "answer": "Data Manipulation"
    },
    {
        "question": "An organization’s application fails to validate user input properly, allowing an attacker to manipulate queries. What type of vulnerability is this?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting",
            "Command Injection",
            "Data Exposure"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "A user clicks on a link in a phishing email and unknowingly installs malware. What type of attack is this?",
        "options": [
            "Malware Infection",
            "Drive-by Download",
            "Spear Phishing",
            "Social Engineering"
        ],
        "answer": "Malware Infection"
    },
    {
        "question": "An attacker exploits a misconfigured server to gain unauthorized access. What type of vulnerability does this represent?",
        "options": [
            "Misconfiguration",
            "Insecure Access Control",
            "Access Control Vulnerability",
            "Privilege Escalation"
        ],
        "answer": "Misconfiguration"
    },
    {
        "question": "An organization has not implemented two-factor authentication for its accounts, increasing the risk of unauthorized access. What type of vulnerability does this represent?",
        "options": [
            "Weak Authentication",
            "Insufficient Security Controls",
            "Insecure Configuration",
            "Lack of Access Control"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "During a security assessment, an analyst identifies that users are able to access sensitive files without proper permissions. What type of vulnerability does this represent?",
        "options": [
            "Broken Access Control",
            "Misconfigured Access Control",
            "Excessive Permissions",
            "Data Leakage"
        ],
        "answer": "Broken Access Control"
    },
    {
        "question": "An application is found to allow users to execute arbitrary code due to an unchecked input validation. What type of vulnerability does this represent?",
        "options": [
            "Command Injection",
            "SQL Injection",
            "Insecure Direct Object Reference",
            "Cross-Site Scripting"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "A security audit reveals that sensitive data is stored in an insecure manner, leading to potential unauthorized access. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Data Leakage",
            "Weak Authentication",
            "Insufficient Security Controls"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "A company’s website is susceptible to cross-site scripting (XSS) due to improper input validation. What type of vulnerability does this represent?",
        "options": [
            "Cross-Site Scripting",
            "SQL Injection",
            "Command Injection",
            "Data Exposure"
        ],
        "answer": "Cross-Site Scripting"
    },
    {
        "question": "An organization does not regularly review and update its security policies, leading to outdated practices. What is the primary risk associated with this behavior?",
        "options": [
            "Compliance Risk",
            "Operational Risk",
            "Reputational Risk",
            "Financial Risk"
        ],
        "answer": "Compliance Risk"
    },
    {
        "question": "A developer discovers that an application fails to restrict access to certain functionality based on user roles. What type of vulnerability does this represent?",
        "options": [
            "Broken Access Control",
            "Insufficient Security Controls",
            "Privilege Escalation",
            "Data Exposure"
        ],
        "answer": "Broken Access Control"
    },
    {
        "question": "An attacker tricks a user into revealing personal information via a fake website. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Impersonation"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A company does not implement proper error handling, revealing sensitive information in error messages. What type of vulnerability does this represent?",
        "options": [
            "Information Disclosure",
            "Data Leakage",
            "Insecure Configuration",
            "Weak Error Handling"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "An organization’s web application allows users to upload files without proper validation. What type of vulnerability does this represent?",
        "options": [
            "File Upload Vulnerability",
            "Malware Upload",
            "Command Injection",
            "Insecure Direct Object Reference"
        ],
        "answer": "File Upload Vulnerability"
    },
    {
        "question": "An attacker sends an email with a malicious attachment that executes when opened. What type of attack is this?",
        "options": [
            "Malware Infection",
            "Phishing",
            "Spear Phishing",
            "Social Engineering"
        ],
        "answer": "Malware Infection"
    },
    {
        "question": "A user receives an email that appears to be from a trusted source but contains a malicious link. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Spoofing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An organization fails to enforce strong password policies, leading to weak passwords among users. What type of vulnerability does this represent?",
        "options": [
            "Weak Password Policies",
            "Weak Authentication",
            "Insufficient Security Controls",
            "Credential Stuffing"
        ],
        "answer": "Weak Password Policies"
    },
    {
        "question": "A user is tricked into entering their credentials into a fake login page that looks legitimate. What type of attack is this?",
        "options": [
            "Phishing",
            "Vishing",
            "Spear Phishing",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An organization allows employees to share accounts, leading to a lack of accountability. What type of vulnerability does this represent?",
        "options": [
            "Shared Accounts",
            "Weak Authentication",
            "Insufficient Security Controls",
            "Insufficient Access Control"
        ],
        "answer": "Shared Accounts"
    },
    {
        "question": "An attacker uses social engineering to convince a user to download malware disguised as a legitimate application. What type of attack is this?",
        "options": [
            "Baiting",
            "Phishing",
            "Spear Phishing",
            "Malware Distribution"
        ],
        "answer": "Baiting"
    },
    {
        "question": "An attacker gains unauthorized access to a system by exploiting a zero-day vulnerability. What type of vulnerability is this?",
        "options": [
            "Zero-Day Vulnerability",
            "Known Vulnerability",
            "Exploited Vulnerability",
            "Misconfiguration"
        ],
        "answer": "Zero-Day Vulnerability"
    },
    {
        "question": "A security analyst discovers that the organization’s web application allows for directory traversal attacks. What type of vulnerability is this?",
        "options": [
            "Directory Traversal",
            "Path Traversal",
            "Access Control Vulnerability",
            "Insecure Configuration"
        ],
        "answer": "Path Traversal"
    },
    {
        "question": "An attacker compromises an organization's system and uses it to launch attacks against other targets. What type of attack is this?",
        "options": [
            "Botnet Attack",
            "Denial of Service",
            "Remote Code Execution",
            "Exploit Kit Attack"
        ],
        "answer": "Botnet Attack"
    },
    {
        "question": "A web application is vulnerable to Cross-Site Scripting (XSS) attacks due to improper output encoding. What type of attack is this?",
        "options": [
            "Cross-Site Scripting",
            "SQL Injection",
            "Command Injection",
            "Data Exposure"
        ],
        "answer": "Cross-Site Scripting"
    },
    {
        "question": "An organization experiences a significant security breach due to weak access controls. What type of attack does this represent?",
        "options": [
            "Data Breach",
            "Unauthorized Access",
            "Privilege Escalation",
            "Insider Threat"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "A user receives a phone call from someone pretending to be from the bank, asking for personal information. What type of attack is this?",
        "options": [
            "Phishing",
            "Vishing",
            "Spear Phishing",
            "Pretexting"
        ],
        "answer": "Vishing"
    },
    {
        "question": "An attacker successfully exploits a vulnerability in a web application to execute arbitrary commands on the server. What type of attack does this represent?",
        "options": [
            "Command Injection",
            "Remote Code Execution",
            "SQL Injection",
            "Data Manipulation"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "A user receives a text message that appears to be from a trusted source asking them to click a link. What type of attack is this?",
        "options": [
            "Phishing",
            "Vishing",
            "Smishing",
            "Pretexting"
        ],
        "answer": "Smishing"
    },
    {
        "question": "An organization discovers that an attacker has successfully installed a backdoor on their system. What type of attack does this represent?",
        "options": [
            "Malware Infection",
            "Privilege Escalation",
            "Data Breach",
            "Backdoor Attack"
        ],
        "answer": "Malware Infection"
    },
    {
        "question": "An attacker exploits a cross-site scripting vulnerability to inject malicious scripts into a web application. What type of attack does this represent?",
        "options": [
            "Cross-Site Scripting",
            "SQL Injection",
            "Command Injection",
            "Data Exposure"
        ],
        "answer": "Cross-Site Scripting"
    },
    {
        "question": "A user receives an email claiming to be from a popular online service, asking them to reset their password. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An attacker compromises a user’s account and uses it to send malicious messages to their contacts. What type of attack does this represent?",
        "options": [
            "Account Compromise",
            "Phishing",
            "Malware Distribution",
            "Credential Stuffing"
        ],
        "answer": "Account Compromise"
    },
    {
        "question": "An organization fails to implement proper input validation, allowing for SQL injection attacks. What type of vulnerability does this represent?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Data Exposure",
            "Insecure Configuration"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "A web application is found to allow for file uploads without validation, potentially leading to code execution. What type of vulnerability does this represent?",
        "options": [
            "File Upload Vulnerability",
            "Command Injection",
            "SQL Injection",
            "Insecure Direct Object Reference"
        ],
        "answer": "File Upload Vulnerability"
    },
    {
        "question": "An attacker uses a phishing scheme to trick users into revealing their credentials. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Vishing",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An attacker gains unauthorized access to a system by exploiting a known vulnerability. What type of attack does this represent?",
        "options": [
            "Exploited Vulnerability",
            "Zero-Day Vulnerability",
            "Misconfiguration",
            "Privilege Escalation"
        ],
        "answer": "Exploited Vulnerability"
    },
    {
        "question": "A security analyst discovers that an organization's system does not log failed login attempts. What type of vulnerability does this represent?",
        "options": [
            "Inadequate Logging",
            "Weak Authentication",
            "Access Control Vulnerability",
            "Insufficient Security Controls"
        ],
        "answer": "Inadequate Logging"
    },
    {
        "question": "A company fails to implement proper access controls, allowing unauthorized users to view sensitive information. What type of vulnerability does this represent?",
        "options": [
            "Broken Access Control",
            "Insecure Configuration",
            "Privilege Escalation",
            "Insufficient Security Controls"
        ],
        "answer": "Broken Access Control"
    },
    {
        "question": "An attacker successfully exploits a vulnerability in a web application to execute unauthorized commands on the server. What type of attack does this represent?",
        "options": [
            "Remote Code Execution",
            "Command Injection",
            "SQL Injection",
            "Data Manipulation"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "A user receives a message from someone posing as a colleague, requesting sensitive information. What type of attack is this?",
        "options": [
            "Social Engineering",
            "Phishing",
            "Vishing",
            "Pretexting"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An attacker uses social engineering tactics to manipulate a user into providing sensitive information. What type of attack does this represent?",
        "options": [
            "Pretexting",
            "Phishing",
            "Baiting",
            "Vishing"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An organization implements a security measure that requires a user to verify their identity via a secondary method. What type of security measure is this?",
        "options": [
            "Two-Factor Authentication",
            "Single Sign-On",
            "Multi-Factor Authentication",
            "Password Manager"
        ],
        "answer": "Two-Factor Authentication"
    },
    {
        "question": "A web application is susceptible to injection attacks due to improper handling of user input. What type of vulnerability does this represent?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Cross-Site Scripting",
            "Input Validation Vulnerability"
        ],
        "answer": "Input Validation Vulnerability"
    },
    {
        "question": "An organization discovers that an employee has downloaded sensitive data without proper authorization. What type of vulnerability does this represent?",
        "options": [
            "Insufficient Access Control",
            "Data Leakage",
            "Unauthorized Access",
            "Excessive Permissions"
        ],
        "answer": "Insufficient Access Control"
    },
    {
        "question": "An attacker exploits a vulnerability in a web application to gain unauthorized access to sensitive data. What type of attack does this represent?",
        "options": [
            "Data Breach",
            "SQL Injection",
            "Command Injection",
            "Information Disclosure"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "A user is tricked into revealing sensitive information by an attacker posing as a trusted source. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Pretexting",
            "Vishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An organization fails to implement logging and monitoring, leading to undetected breaches. What type of vulnerability does this represent?",
        "options": [
            "Inadequate Logging",
            "Weak Security Controls",
            "Insufficient Security Controls",
            "Operational Risk"
        ],
        "answer": "Inadequate Logging"
    },
    {
        "question": "An attacker uses a phishing scheme to trick users into revealing their sensitive data. What type of attack does this represent?",
        "options": [
            "Phishing",
            "Vishing",
            "Spear Phishing",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An organization fails to enforce proper access controls, allowing unauthorized users to manipulate data. What type of vulnerability does this represent?",
        "options": [
            "Broken Access Control",
            "Misconfiguration",
            "Insecure Configuration",
            "Insufficient Security Controls"
        ],
        "answer": "Broken Access Control"
    },
    {
        "question": "An attacker utilizes malware to gain unauthorized access to a network. What type of attack does this represent?",
        "options": [
            "Malware Infection",
            "Data Breach",
            "Exploit Kit Attack",
            "Zero-Day Attack"
        ],
        "answer": "Malware Infection"
    },
    {
        "question": "A user receives a message on social media from someone pretending to be a friend, asking for personal information. What type of attack does this represent?",
        "options": [
            "Social Engineering",
            "Phishing",
            "Spear Phishing",
            "Impersonation"
        ],
        "answer": "Impersonation"
    },
    {
        "question": "An organization’s system allows for improper validation of user input, leading to potential code execution. What type of vulnerability does this represent?",
        "options": [
            "Input Validation Vulnerability",
            "Command Injection",
            "SQL Injection",
            "Insecure Configuration"
        ],
        "answer": "Input Validation Vulnerability"
    },
    {
        "question": "An attacker uses a cross-site scripting vulnerability to inject malicious scripts into a web application. What type of attack does this represent?",
        "options": [
            "Cross-Site Scripting",
            "SQL Injection",
            "Command Injection",
            "Data Exposure"
        ],
        "answer": "Cross-Site Scripting"
    },
    {
        "question": "A user receives an email from a service provider, asking for account verification. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An attacker gains access to a system by exploiting a known vulnerability in the software. What type of attack does this represent?",
        "options": [
            "Exploited Vulnerability",
            "Zero-Day Attack",
            "Privilege Escalation",
            "Denial of Service"
        ],
        "answer": "Exploited Vulnerability"
    },
    {
        "question": "An organization fails to implement proper encryption for sensitive data, leading to potential exposure. What type of vulnerability does this represent?",
        "options": [
            "Insecure Data Storage",
            "Weak Encryption",
            "Data Exposure",
            "Insufficient Security Controls"
        ],
        "answer": "Weak Encryption"
    },
    {
        "question": "An attacker uses a phishing email to trick a user into providing their credentials. What type of attack does this represent?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Vishing",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A security audit reveals that an organization is using outdated software versions with known vulnerabilities. What type of risk does this represent?",
        "options": [
            "Operational Risk",
            "Compliance Risk",
            "Reputational Risk",
            "Financial Risk"
        ],
        "answer": "Operational Risk"
    },
    {
        "question": "An attacker exploits a flaw in a web application to execute arbitrary commands. What type of attack does this represent?",
        "options": [
            "Remote Code Execution",
            "SQL Injection",
            "Command Injection",
            "Data Manipulation"
        ],
        "answer": "Command Injection"
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
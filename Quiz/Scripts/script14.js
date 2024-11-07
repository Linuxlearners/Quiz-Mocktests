
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "Emily is assessing a web application that uses cookies to maintain user sessions. She notices that the session IDs are predictable and can be guessed. What type of attack is this vulnerability associated with?",
        "options": [
            "Session Hijacking",
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Credential Stuffing"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "Mark is analyzing a web application that lacks proper input validation and sanitization. During his tests, he finds that a user can input HTML and JavaScript into the comment section. What vulnerability does this indicate?",
        "options": [
            "Cross-site Request Forgery (CSRF)",
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Remote Code Execution"
        ],
        "answer": "Cross-site Scripting (XSS)"
    },
    {
        "question": "During a penetration test, Linda identifies that the web application is using HTTP instead of HTTPS. Which risk is primarily associated with this configuration?",
        "options": [
            "Data Integrity",
            "Data Confidentiality",
            "Data Availability",
            "Access Control"
        ],
        "answer": "Data Confidentiality"
    },
    {
        "question": "A web application provides a password reset feature that sends a link to the user's email. However, the link does not expire after a certain time. What type of risk does this present?",
        "options": [
            "Replay Attack",
            "Session Fixation",
            "Brute Force Attack",
            "Cross-site Request Forgery (CSRF)"
        ],
        "answer": "Replay Attack"
    },
    {
        "question": "Tom discovers that a web application allows users to input JavaScript into form fields. After submission, the script runs in the context of other users' browsers. What type of attack is this indicative of?",
        "options": [
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Command Injection",
            "Phishing"
        ],
        "answer": "Cross-site Scripting (XSS)"
    },
    {
        "question": "A company’s e-commerce site is facing an increase in orders that seem to come from a single IP address. What type of attack might this indicate?",
        "options": [
            "Distributed Denial of Service (DDoS)",
            "Brute Force Attack",
            "SQL Injection",
            "Session Hijacking"
        ],
        "answer": "Distributed Denial of Service (DDoS)"
    },
    {
        "question": "Samantha finds that sensitive data is being transmitted in the URL rather than in the request body. What kind of threat does this expose the application to?",
        "options": [
            "Data Leakage",
            "Session Fixation",
            "Cross-site Request Forgery (CSRF)",
            "Man-in-the-Middle Attack"
        ],
        "answer": "Data Leakage"
    },
    {
        "question": "An attacker exploits a vulnerability in a web application's file upload feature to upload malicious scripts. What type of threat is this scenario describing?",
        "options": [
            "Command Injection",
            "Remote File Inclusion (RFI)",
            "Local File Inclusion (LFI)",
            "Arbitrary File Upload"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "During a web application penetration test, John starts with reconnaissance and uses automated tools to identify open ports. What is this phase commonly known as?",
        "options": [
            "Scanning",
            "Exploitation",
            "Information Gathering",
            "Post-Exploitation"
        ],
        "answer": "Information Gathering"
    },
    {
        "question": "As part of his testing, Kevin identifies a login page and attempts to brute-force the credentials. What stage of the hacking methodology is he currently in?",
        "options": [
            "Gaining Access",
            "Enumeration",
            "Reconnaissance",
            "Reporting"
        ],
        "answer": "Gaining Access"
    },
    {
        "question": "After gaining access, Sarah explores the web application’s database and discovers user credentials stored in plain text. What should be her next step according to ethical hacking guidelines?",
        "options": [
            "Exploit the credentials for unauthorized access",
            "Document the findings and report them",
            "Alter the database entries",
            "Leave the database untouched"
        ],
        "answer": "Document the findings and report them"
    },
    {
        "question": "In a pentest, Jason finds a vulnerability but decides not to exploit it further due to potential damage. This reflects which principle of ethical hacking?",
        "options": [
            "Confidentiality",
            "Integrity",
            "Non-maleficence",
            "Transparency"
        ],
        "answer": "Non-maleficence"
    },
    {
        "question": "An API allows users to access data without authentication. What type of vulnerability does this represent?",
        "options": [
            "Insecure Direct Object Reference (IDOR)",
            "Broken Authentication",
            "Cross-site Scripting (XSS)",
            "Sensitive Data Exposure"
        ],
        "answer": "Broken Authentication"
    },
    {
        "question": "During a security review, an organization finds that its webhooks can be triggered by anyone. What is the primary risk associated with this issue?",
        "options": [
            "Denial of Service",
            "Data Manipulation",
            "Unauthorized Access",
            "Information Disclosure"
        ],
        "answer": "Data Manipulation"
    },
    {
        "question": "A web application’s backend is accessible via a web shell due to misconfiguration. What is the primary risk posed by this vulnerability?",
        "options": [
            "Command Injection",
            "Unauthorized System Access",
            "SQL Injection",
            "Remote File Inclusion (RFI)"
        ],
        "answer": "Unauthorized System Access"
    },
    {
        "question": "Alex discovers that an API responds to GET requests containing sensitive information, even if POST requests are recommended. What security principle is being violated?",
        "options": [
            "Least Privilege",
            "Data Confidentiality",
            "Input Validation",
            "Segregation of Duties"
        ],
        "answer": "Data Confidentiality"
    },
    {
        "question": "A web application uses session tokens stored in cookies but does not set the HttpOnly flag. What risk does this pose?",
        "options": [
            "Cross-site Scripting (XSS)",
            "Session Hijacking",
            "Man-in-the-Middle Attack",
            "Phishing"
        ],
        "answer": "Cross-site Scripting (XSS)"
    },
    {
        "question": "During a security audit, you notice that user passwords are hashed but without a salt. What is the main vulnerability here?",
        "options": [
            "Password Cracking",
            "Data Breach",
            "SQL Injection",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Password Cracking"
    },
    {
        "question": "A web application is vulnerable to SQL injection, allowing an attacker to manipulate database queries. Which type of input should be properly sanitized to prevent this?",
        "options": [
            "HTML input",
            "JavaScript input",
            "User-controlled input",
            "API input"
        ],
        "answer": "User-controlled input"
    },
    {
        "question": "You are testing a web application that allows file uploads. You find that it accepts files with extensions like .php and .exe. What type of vulnerability does this indicate?",
        "options": [
            "Remote File Inclusion (RFI)",
            "Arbitrary File Upload",
            "Local File Inclusion (LFI)",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "A company implements Multi-Factor Authentication (MFA) but only for internal applications. What is the main risk for external applications?",
        "options": [
            "Unauthorized Access",
            "Data Breach",
            "Session Fixation",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Unauthorized Access"
    },
    {
        "question": "During a security review, you discover a web application that exposes its error messages to users, revealing stack traces. What type of risk does this present?",
        "options": [
            "Information Disclosure",
            "Denial of Service",
            "Session Fixation",
            "SQL Injection"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "A security assessment reveals that a web application is vulnerable to Cross-Site Request Forgery (CSRF). Which of the following methods can mitigate this risk?",
        "options": [
            "Input Validation",
            "SameSite Cookie Attribute",
            "Content Security Policy",
            "Data Encryption"
        ],
        "answer": "SameSite Cookie Attribute"
    },
    {
        "question": "During penetration testing, you find that an application does not limit failed login attempts. What type of attack could this vulnerability allow?",
        "options": [
            "Brute Force Attack",
            "Denial of Service",
            "SQL Injection",
            "Session Fixation"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "A web application allows users to change their email address without verifying ownership. What vulnerability does this create?",
        "options": [
            "Account Takeover",
            "Session Fixation",
            "Data Leakage",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Account Takeover"
    },
    {
        "question": "You are testing a web service API that lacks proper authentication. An attacker can easily access sensitive endpoints. What is this an example of?",
        "options": [
            "Broken Authentication",
            "Insecure Direct Object Reference (IDOR)",
            "Data Exposure",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Broken Authentication"
    },
    {
        "question": "During a security review, you find that an application does not encrypt sensitive data in transit. What type of attack does this expose the data to?",
        "options": [
            "Man-in-the-Middle Attack",
            "Phishing",
            "Denial of Service",
            "Cross-site Request Forgery (CSRF)"
        ],
        "answer": "Man-in-the-Middle Attack"
    },
    {
        "question": "A web application contains an input field that allows users to enter overly long strings. What type of attack could this vulnerability facilitate?",
        "options": [
            "Buffer Overflow",
            "SQL Injection",
            "Cross-site Scripting (XSS)",
            "Session Hijacking"
        ],
        "answer": "Buffer Overflow"
    },
    {
        "question": "You are assessing a web application that utilizes third-party libraries. What is a primary concern regarding these libraries?",
        "options": [
            "License Compliance",
            "Security Vulnerabilities",
            "Performance Issues",
            "Code Quality"
        ],
        "answer": "Security Vulnerabilities"
    },
    {
        "question": "During a code review, you find hardcoded credentials in the source code. What vulnerability does this represent?",
        "options": [
            "Information Disclosure",
            "Insecure Storage",
            "Unauthorized Access",
            "Data Breach"
        ],
        "answer": "Insecure Storage"
    },
    {
        "question": "A security analyst discovers that a web application is susceptible to XML External Entity (XXE) attacks. What should be prioritized in the response?",
        "options": [
            "Input Validation",
            "Output Encoding",
            "Error Handling",
            "Authentication Mechanisms"
        ],
        "answer": "Input Validation"
    },
    {
        "question": "A company requires all sensitive transactions to be encrypted. What type of security measure is this an example of?",
        "options": [
            "Data Integrity",
            "Data Confidentiality",
            "Access Control",
            "Non-repudiation"
        ],
        "answer": "Data Confidentiality"
    },
    {
        "question": "During a security assessment, a developer claims that input validation prevents all types of injections. What is the most appropriate response?",
        "options": [
            "Reassure the developer",
            "Request a review of the validation methods",
            "Ignore the statement",
            "Suggest using prepared statements only"
        ],
        "answer": "Request a review of the validation methods"
    },
    {
        "question": "A web application does not implement proper logging of user activities. What risk does this pose during a security incident?",
        "options": [
            "Lack of Accountability",
            "Data Loss",
            "Increased Downtime",
            "Exposed APIs"
        ],
        "answer": "Lack of Accountability"
    },
    {
        "question": "A security team finds that users are able to bypass security controls by manipulating URL parameters. What is this an example of?",
        "options": [
            "Insecure Direct Object Reference (IDOR)",
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Parameter Injection"
        ],
        "answer": "Insecure Direct Object Reference (IDOR)"
    },
    {
        "question": "You discover that a web application allows users to register accounts without validating email addresses. What risk does this present?",
        "options": [
            "Spam Accounts",
            "Account Takeover",
            "SQL Injection",
            "Data Breach"
        ],
        "answer": "Spam Accounts"
    },
    {
        "question": "An attacker is able to manipulate a web application’s search functionality to execute arbitrary code. What type of attack is this?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Cross-site Scripting (XSS)",
            "Path Traversal"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "A web application uses a Content Management System (CMS) that has not been updated. What is the most significant risk associated with outdated software?",
        "options": [
            "Compatibility Issues",
            "Data Corruption",
            "Exploitation of Known Vulnerabilities",
            "Performance Degradation"
        ],
        "answer": "Exploitation of Known Vulnerabilities"
    },
    {
        "question": "You observe that an application exposes a REST API without rate limiting. What is the main concern with this configuration?",
        "options": [
            "Denial of Service",
            "Data Exposure",
            "Insecure Authentication",
            "Data Integrity"
        ],
        "answer": "Denial of Service"
    },
    {
        "question": "A company implements input sanitization to protect against injections. What additional measure should be taken for optimal security?",
        "options": [
            "User Education",
            "Output Encoding",
            "Database Hardening",
            "Network Security"
        ],
        "answer": "Output Encoding"
    },
    {
        "question": "During a vulnerability assessment, you find that the web application is exposing sensitive information in HTTP headers. What type of risk does this represent?",
        "options": [
            "Information Disclosure",
            "Session Hijacking",
            "Cross-site Scripting (XSS)",
            "Insecure Direct Object Reference (IDOR)"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "A security team notices that the web application uses insecure algorithms for hashing passwords. What is the recommended action?",
        "options": [
            "Change to a secure hashing algorithm",
            "Add salting to the current algorithm",
            "Keep the current algorithm for consistency",
            "Use plain text for ease of use"
        ],
        "answer": "Change to a secure hashing algorithm"
    },
    {
        "question": "An organization finds that its APIs are returning error messages that reveal implementation details. What vulnerability does this represent?",
        "options": [
            "Information Disclosure",
            "Insecure Direct Object Reference (IDOR)",
            "Data Leakage",
            "Cross-site Request Forgery (CSRF)"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "A web application has not implemented Cross-Origin Resource Sharing (CORS) correctly, allowing unauthorized domains to access resources. What risk does this pose?",
        "options": [
            "Data Leakage",
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Credential Theft"
        ],
        "answer": "Data Leakage"
    },
    {
        "question": "You discover a web application that uses unvalidated redirects to external URLs. What type of attack does this vulnerability enable?",
        "options": [
            "Open Redirect",
            "Phishing",
            "Cross-site Scripting (XSS)",
            "SQL Injection"
        ],
        "answer": "Open Redirect"
    },
    {
        "question": "An organization has implemented Web Application Firewalls (WAF) but notices persistent attacks. What could be a reason for this?",
        "options": [
            "Incorrect WAF configuration",
            "Outdated signatures",
            "Insufficient logging",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "A web application allows users to send messages without rate limiting. What is the primary risk associated with this configuration?",
        "options": [
            "Spam and Abuse",
            "Data Loss",
            "Information Disclosure",
            "Unauthorized Access"
        ],
        "answer": "Spam and Abuse"
    },
    {
        "question": "During an audit, you find that a web application does not implement proper session timeouts. What vulnerability does this present?",
        "options": [
            "Session Hijacking",
            "Data Breach",
            "Cross-site Scripting (XSS)",
            "SQL Injection"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "A web application returns overly verbose error messages that could assist an attacker. What type of issue is this?",
        "options": [
            "Information Disclosure",
            "Insecure Configuration",
            "Data Leakage",
            "Input Validation"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "During a security audit, an application is found to have exposed APIs without authentication. What type of vulnerability does this present?",
        "options": [
            "Insecure Direct Object Reference (IDOR)",
            "Broken Authentication",
            "Excessive Data Exposure",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Broken Authentication"
    },
    {
        "question": "A web application is vulnerable to Cross-Site Request Forgery (CSRF) due to the absence of anti-CSRF tokens. What is a potential consequence of this vulnerability?",
        "options": [
            "Unauthorized actions performed on behalf of the user",
            "Data loss due to session hijacking",
            "Exposure of sensitive data in URL",
            "Execution of arbitrary JavaScript code"
        ],
        "answer": "Unauthorized actions performed on behalf of the user"
    },
    {
        "question": "You discover that a web application allows users to submit long inputs without any restriction. What type of attack could be facilitated by this vulnerability?",
        "options": [
            "Buffer Overflow",
            "Denial of Service",
            "SQL Injection",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Buffer Overflow"
    },
    {
        "question": "An attacker is using a tool to enumerate users of a web application. What technique are they likely employing?",
        "options": [
            "Credential Stuffing",
            "Brute Force Attack",
            "User Enumeration Attack",
            "Session Hijacking"
        ],
        "answer": "User Enumeration Attack"
    },
    {
        "question": "A web application uses JWT for authentication, but the secret key is hardcoded in the client-side code. What risk does this present?",
        "options": [
            "Token Forgery",
            "Session Fixation",
            "Cross-site Scripting (XSS)",
            "Replay Attack"
        ],
        "answer": "Token Forgery"
    },
    {
        "question": "You notice a web application is vulnerable to Server-Side Request Forgery (SSRF). What could this allow an attacker to do?",
        "options": [
            "Access internal resources not intended for public access",
            "Inject malicious code into the application",
            "Perform a Denial of Service attack",
            "Bypass authentication mechanisms"
        ],
        "answer": "Access internal resources not intended for public access"
    },
    {
        "question": "An application’s error handling mechanism exposes stack traces to the user. What is the primary risk associated with this?",
        "options": [
            "Information Disclosure",
            "Data Integrity Issues",
            "Authentication Bypass",
            "Denial of Service"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "A web application allows users to upload files without any validation. What type of vulnerability does this create?",
        "options": [
            "Command Injection",
            "Arbitrary File Upload",
            "Cross-site Scripting (XSS)",
            "Local File Inclusion (LFI)"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "You are assessing a web application that uses outdated libraries known for vulnerabilities. What is this an example of?",
        "options": [
            "Insecure Dependencies",
            "Poor Configuration Management",
            "Insufficient Security Controls",
            "Lack of Encryption"
        ],
        "answer": "Insecure Dependencies"
    },
    {
        "question": "A security review reveals that sensitive data is sent as URL parameters instead of in the request body. What type of risk does this pose?",
        "options": [
            "Data Exposure",
            "Session Fixation",
            "Injection Attacks",
            "Cross-site Scripting (XSS)"
        ],
        "answer": "Data Exposure"
    },
    {
        "question": "An attacker successfully performs a Man-in-the-Middle (MitM) attack on a web application using a compromised certificate. What is the primary vulnerability exploited?",
        "options": [
            "Lack of SSL/TLS Implementation",
            "Weak Encryption Algorithms",
            "Improper Certificate Validation",
            "Insecure APIs"
        ],
        "answer": "Improper Certificate Validation"
    },
    {
        "question": "A web application’s API allows CORS requests from any origin. What vulnerability does this configuration expose?",
        "options": [
            "Cross-origin Resource Sharing Attack",
            "Cross-site Scripting (XSS)",
            "Data Manipulation",
            "Session Hijacking"
        ],
        "answer": "Cross-origin Resource Sharing Attack"
    },
    {
        "question": "An organization uses a web application that does not log user activities. What is the main risk during a security incident?",
        "options": [
            "Lack of Accountability",
            "Data Corruption",
            "Increased Downtime",
            "Loss of Reputation"
        ],
        "answer": "Lack of Accountability"
    },
    {
        "question": "During a penetration test, you find that a web application does not implement proper rate limiting on API calls. What attack does this vulnerability facilitate?",
        "options": [
            "Brute Force Attack",
            "Cross-site Request Forgery (CSRF)",
            "SQL Injection",
            "Denial of Service"
        ],
        "answer": "Denial of Service"
    },
    {
        "question": "A web application allows SQL commands to be executed via user input. What type of vulnerability does this represent?",
        "options": [
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Command Injection",
            "Path Traversal"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "You discover that a web application uses unvalidated redirects. What type of attack does this allow?",
        "options": [
            "Phishing",
            "Cross-site Scripting (XSS)",
            "Denial of Service",
            "SQL Injection"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A web application is configured to expose its database structure through error messages. What risk does this present?",
        "options": [
            "Information Disclosure",
            "Data Integrity",
            "Session Fixation",
            "Injection Attacks"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "An attacker is able to upload a malicious script through a web application’s image upload feature. What type of vulnerability is being exploited?",
        "options": [
            "Arbitrary File Upload",
            "Cross-site Scripting (XSS)",
            "Local File Inclusion (LFI)",
            "Remote File Inclusion (RFI)"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "A web application uses weak cryptographic algorithms to encrypt sensitive data. What vulnerability does this create?",
        "options": [
            "Data Breach",
            "Insufficient Encryption",
            "Denial of Service",
            "Session Hijacking"
        ],
        "answer": "Insufficient Encryption"
    },
    {
        "question": "During an assessment, you notice that a web application does not use HTTP Strict Transport Security (HSTS). What risk does this pose?",
        "options": [
            "Man-in-the-Middle Attacks",
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Denial of Service"
        ],
        "answer": "Man-in-the-Middle Attacks"
    },
    {
        "question": "You discover that a web application does not sanitize input fields. What types of attacks could this facilitate?",
        "options": [
            "SQL Injection and XSS",
            "Denial of Service",
            "Session Hijacking",
            "Path Traversal"
        ],
        "answer": "SQL Injection and XSS"
    },
    {
        "question": "A web application uses local storage to store sensitive information without encryption. What is the primary risk of this practice?",
        "options": [
            "Data Exposure",
            "Cross-site Scripting (XSS)",
            "Injection Attacks",
            "Session Fixation"
        ],
        "answer": "Data Exposure"
    },
    {
        "question": "During a security assessment, you find that a web application is vulnerable to XML External Entity (XXE) attacks. What should be your first action?",
        "options": [
            "Disable XML processing",
            "Update to a secure XML parser",
            "Sanitize user inputs",
            "Implement access controls"
        ],
        "answer": "Update to a secure XML parser"
    },
    {
        "question": "A security assessment reveals that an application uses default credentials for administrative access. What risk does this pose?",
        "options": [
            "Unauthorized Access",
            "Information Disclosure",
            "Data Manipulation",
            "Denial of Service"
        ],
        "answer": "Unauthorized Access"
    },
    {
        "question": "You discover that an application fails to verify the integrity of user-uploaded files. What attack could this vulnerability enable?",
        "options": [
            "Code Injection",
            "File Inclusion",
            "Cross-site Scripting (XSS)",
            "Denial of Service"
        ],
        "answer": "File Inclusion"
    },
    {
        "question": "A web application provides verbose error messages that can assist an attacker in identifying vulnerabilities. What is this an example of?",
        "options": [
            "Information Disclosure",
            "Weak Authentication",
            "Insecure Configuration",
            "Session Hijacking"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "During a code review, a developer uses user input directly in a query without parameterization. What logical flaw does this expose?",
        "options": [
            "SQL Injection",
            "Cross-site Scripting (XSS)",
            "Path Traversal",
            "Insecure Direct Object Reference"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "A web application allows users to reset passwords without verifying their identity through multi-factor authentication. What risk does this represent?",
        "options": [
            "Account Takeover",
            "Session Hijacking",
            "Data Exposure",
            "Denial of Service"
        ],
        "answer": "Account Takeover"
    },
    {
        "question": "You discover that an application does not limit failed login attempts. What type of attack does this vulnerability facilitate?",
        "options": [
            "Brute Force Attack",
            "Credential Stuffing",
            "Phishing",
            "Session Fixation"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "An organization’s web application fails to implement a secure content policy. What logical consequence does this have?",
        "options": [
            "Increased risk of XSS attacks",
            "Improper handling of user sessions",
            "Data leakage through insecure channels",
            "Unauthorized API access"
        ],
        "answer": "Increased risk of XSS attacks"
    },
    {
        "question": "A security audit reveals that sensitive API endpoints are accessible without HTTPS. What is the primary risk?",
        "options": [
            "Man-in-the-Middle Attacks",
            "SQL Injection",
            "Cross-site Request Forgery (CSRF)",
            "Information Disclosure"
        ],
        "answer": "Man-in-the-Middle Attacks"
    },
    {
        "question": "During a vulnerability scan, you find that an application is leaking sensitive data through HTTP headers. What should be your immediate focus?",
        "options": [
            "Fix the server configuration",
            "Implement rate limiting",
            "Enhance user authentication",
            "Increase encryption strength"
        ],
        "answer": "Fix the server configuration"
    },
    {
        "question": "A web application allows users to create custom URLs without validation. What type of attack could this enable?",
        "options": [
            "Open Redirect",
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Data Breach"
        ],
        "answer": "Open Redirect"
    },
    {
        "question": "You are assessing a web application that uses HTTP GET requests to submit sensitive data. What logical issue does this present?",
        "options": [
            "Data Exposure in URLs",
            "Insecure API Endpoints",
            "Lack of Input Validation",
            "Weak Authentication Mechanisms"
        ],
        "answer": "Data Exposure in URLs"
    },
    {
        "question": "An application improperly handles user session management, allowing sessions to remain active indefinitely. What risk does this pose?",
        "options": [
            "Session Hijacking",
            "Information Disclosure",
            "SQL Injection",
            "Data Manipulation"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "A developer integrates third-party libraries without reviewing their security status. What risk does this logical oversight introduce?",
        "options": [
            "Exploitation of Known Vulnerabilities",
            "Data Leakage",
            "Unauthorized Access",
            "Denial of Service"
        ],
        "answer": "Exploitation of Known Vulnerabilities"
    },
    {
        "question": "You discover that a web application provides detailed error messages to end users. What logical flaw does this represent?",
        "options": [
            "Information Disclosure",
            "Weak Authentication",
            "Poor Input Validation",
            "Insecure Configuration"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "During a security test, you find that the application exposes its database schema through API responses. What is the primary risk?",
        "options": [
            "Information Disclosure",
            "SQL Injection",
            "Data Integrity",
            "Denial of Service"
        ],
        "answer": "Information Disclosure"
    },
    {
        "question": "A web application does not implement Content Security Policy (CSP). What is a potential impact of this omission?",
        "options": [
            "Increased risk of Cross-Site Scripting (XSS)",
            "Failure to encrypt sensitive data",
            "Weak session management",
            "Improper input validation"
        ],
        "answer": "Increased risk of Cross-Site Scripting (XSS)"
    },
    {
        "question": "You find that a web application allows users to specify URL redirects. What logical attack does this present?",
        "options": [
            "Open Redirect",
            "Cross-site Scripting (XSS)",
            "Data Breach",
            "Phishing"
        ],
        "answer": "Open Redirect"
    },
    {
        "question": "An attacker sends a crafted request to an application that executes unvalidated code. What type of vulnerability is being exploited?",
        "options": [
            "Command Injection",
            "Remote Code Execution",
            "Cross-site Scripting (XSS)",
            "SQL Injection"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "During a review, you notice an application has hardcoded sensitive API keys. What logical flaw does this represent?",
        "options": [
            "Insecure Storage",
            "Weak Authentication",
            "Poor Encryption",
            "Session Fixation"
        ],
        "answer": "Insecure Storage"
    },
    {
        "question": "You observe that a web application does not validate its SSL certificate against known Certificate Authorities. What risk does this pose?",
        "options": [
            "Man-in-the-Middle Attacks",
            "Denial of Service",
            "Data Exposure",
            "Unauthorized Access"
        ],
        "answer": "Man-in-the-Middle Attacks"
    },
    {
        "question": "A web application allows arbitrary script execution through its API due to insufficient input validation. What is the logical flaw?",
        "options": [
            "Code Injection",
            "Cross-site Scripting (XSS)",
            "Data Exposure",
            "Information Disclosure"
        ],
        "answer": "Code Injection"
    },
    {
        "question": "During an assessment, you find an application that fails to log critical actions taken by users. What risk does this present?",
        "options": [
            "Lack of Accountability",
            "Increased Data Loss",
            "Data Corruption",
            "Session Hijacking"
        ],
        "answer": "Lack of Accountability"
    },
    {
        "question": "A web application’s search functionality does not sanitize input properly. What type of attack could this facilitate?",
        "options": [
            "SQL Injection",
            "Cross-site Scripting (XSS)",
            "Denial of Service",
            "Command Injection"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "You discover that a web application is allowing too many requests from a single IP address without throttling. What risk does this create?",
        "options": [
            "Denial of Service",
            "Brute Force Attacks",
            "Session Fixation",
            "Data Leakage"
        ],
        "answer": "Denial of Service"
    },
    {
        "question": "An attacker uses a tool to intercept and manipulate requests between the client and server of a web application. What type of attack is this?",
        "options": [
            "Man-in-the-Middle Attack",
            "Cross-site Scripting (XSS)",
            "SQL Injection",
            "Session Hijacking"
        ],
        "answer": "Man-in-the-Middle Attack"
    },
    {
        "question": "A web application exposes user data through a poorly secured API. What is the primary concern associated with this exposure?",
        "options": [
            "Unauthorized Data Access",
            "Session Fixation",
            "Denial of Service",
            "Code Injection"
        ],
        "answer": "Unauthorized Data Access"
    },
    {
        "question": "During a penetration test, you find that the application allows for directory traversal attacks. What can an attacker potentially access?",
        "options": [
            "Files outside the web root directory",
            "Database connections",
            "Server configuration files",
            "Sensitive environment variables"
        ],
        "answer": "Files outside the web root directory"
    },
    {
        "question": "A web application provides functionality for users to change their profile information without validating the input. What type of attack does this oversight enable?",
        "options": [
            "Cross-site Scripting (XSS)",
            "Insecure Direct Object Reference (IDOR)",
            "SQL Injection",
            "Session Hijacking"
        ],
        "answer": "Insecure Direct Object Reference (IDOR)"
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
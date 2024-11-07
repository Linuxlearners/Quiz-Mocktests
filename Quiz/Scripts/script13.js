
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "Lisa is configuring a web server and needs to decide between using Apache and Nginx. She is looking for better performance under high traffic. Which server should she choose?",
        "options": [
            "Apache",
            "Nginx",
            "IIS",
            "Lighttpd"
        ],
        "answer": "Nginx"
    },
    {
        "question": "Tom is analyzing server logs and notices that multiple requests are made to the same resource from different IP addresses within a short time frame. What could this indicate?",
        "options": [
            "Normal traffic patterns",
            "DDoS attack",
            "Search engine crawling",
            "Botnet activity"
        ],
        "answer": "DDoS attack"
    },
    {
        "question": "During a security audit, Emma finds that the web server is exposing its version in HTTP headers. What is the potential risk of this configuration?",
        "options": [
            "Increased performance",
            "Information disclosure",
            "Improved security",
            "Enhanced compatibility"
        ],
        "answer": "Information disclosure"
    },
    {
        "question": "A web server receives a request that includes a 'Range' header specifying an unusual range of bytes. What type of attack might this be indicative of?",
        "options": [
            "Buffer overflow",
            "HTTP smuggling",
            "Cross-Site Request Forgery (CSRF)",
            "Web Cache Poisoning"
        ],
        "answer": "HTTP smuggling"
    },
    {
        "question": "Mark is investigating a web server that uses SSL/TLS for secure communication. What is the primary function of SSL/TLS in this context?",
        "options": [
            "Data encryption",
            "Data compression",
            "Data integrity",
            "Session management"
        ],
        "answer": "Data encryption"
    },
    {
        "question": "Sara is working with a server that utilizes CGI scripts. Which of the following poses a significant risk when using CGI?",
        "options": [
            "SQL Injection",
            "Command Injection",
            "Path Traversal",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "A new vulnerability in a web server software is discovered, but the vendor has not yet issued a patch. What should a system administrator do in the interim?",
        "options": [
            "Ignore the vulnerability",
            "Disable the affected service",
            "Increase the server's firewall rules",
            "Monitor the server closely"
        ],
        "answer": "Disable the affected service"
    },
    {
        "question": "John is tasked with hardening a web server. Which of the following would be the most effective way to reduce exposure to attacks?",
        "options": [
            "Run the server with default settings",
            "Remove unused services and applications",
            "Increase bandwidth",
            "Use a public-facing database"
        ],
        "answer": "Remove unused services and applications"
    },
    {
        "question": "During a penetration test, a tester discovers that a web server allows the execution of scripts in a directory that is publicly accessible. What type of vulnerability is this likely to be?",
        "options": [
            "Directory traversal",
            "Remote File Inclusion (RFI)",
            "Arbitrary File Execution",
            "Misconfigured permissions"
        ],
        "answer": "Arbitrary File Execution"
    },
    {
        "question": "Which HTTP method is considered the most secure for a web server to accept, minimizing the risk of certain types of attacks?",
        "options": [
            "GET",
            "POST",
            "PUT",
            "DELETE"
        ],
        "answer": "POST"
    },
    {
        "question": "During a vulnerability scan, an attacker discovers that a web application is susceptible to SQL injection. What is the first step the attacker might take?",
        "options": [
            "Inject SQL commands into input fields",
            "Access the database directly",
            "Analyze the web server logs",
            "Change user passwords"
        ],
        "answer": "Inject SQL commands into input fields"
    },
    {
        "question": "A web application is compromised, and the attacker manages to upload a web shell. What capability does this provide the attacker?",
        "options": [
            "Control over the web server",
            "Encrypted data storage",
            "User authentication bypass",
            "Network traffic analysis"
        ],
        "answer": "Control over the web server"
    },
    {
        "question": "An attacker uses an exploit that takes advantage of a known vulnerability in a web server software. This is known as what type of attack?",
        "options": [
            "Zero-day attack",
            "Phishing attack",
            "Social engineering attack",
            "Brute force attack"
        ],
        "answer": "Zero-day attack"
    },
    {
        "question": "When conducting a session fixation attack, what is the attacker primarily trying to achieve?",
        "options": [
            "Steal sensitive data",
            "Control a user's session",
            "Disrupt service availability",
            "Inject malicious scripts"
        ],
        "answer": "Control a user's session"
    },
    {
        "question": "A web server is subjected to a denial-of-service attack, resulting in it being overwhelmed with traffic. Which tool might the attacker use?",
        "options": [
            "Nmap",
            "Wireshark",
            "LOIC",
            "Metasploit"
        ],
        "answer": "LOIC"
    },
    {
        "question": "An attacker is attempting to exploit a Cross-Site Scripting (XSS) vulnerability in a web application. Which of the following is a common target for the injected script?",
        "options": [
            "Database server",
            "Web application log",
            "User's browser",
            "Web server configuration file"
        ],
        "answer": "User's browser"
    },
    {
        "question": "During a red team engagement, the team successfully performs a phishing attack to gain credentials. What is the primary next step?",
        "options": [
            "Use credentials to log in",
            "Report findings immediately",
            "Create a backup of the database",
            "Change the user’s password"
        ],
        "answer": "Use credentials to log in"
    },
    {
        "question": "An attacker wants to gain access to a secure server by exploiting the misconfiguration of an SSL certificate. What type of attack might this involve?",
        "options": [
            "Man-in-the-Middle attack",
            "Eavesdropping",
            "Session hijacking",
            "DNS spoofing"
        ],
        "answer": "Man-in-the-Middle attack"
    },
    {
        "question": "During a penetration test, the tester uses fuzzing techniques on a web application. What is the main goal of fuzzing?",
        "options": [
            "Identify input validation errors",
            "Gain unauthorized access",
            "Disrupt application functionality",
            "Explore all possible paths"
        ],
        "answer": "Identify input validation errors"
    },
    {
        "question": "In a reflected XSS attack, where does the injected script get executed?",
        "options": [
            "On the web server",
            "In the database",
            "In the victim's browser",
            "In the network"
        ],
        "answer": "In the victim's browser"
    },
    {
        "question": "As part of the web application penetration testing methodology, what is the first step in the attack process?",
        "options": [
            "Scanning",
            "Gaining Access",
            "Information Gathering",
            "Reporting"
        ],
        "answer": "Information Gathering"
    },
    {
        "question": "When performing a web application test, an ethical hacker decides to map out the application's structure and inputs. Which technique is he primarily using?",
        "options": [
            "Fuzzing",
            "Directory brute-forcing",
            "Social engineering",
            "Code review"
        ],
        "answer": "Directory brute-forcing"
    },
    {
        "question": "During the testing phase, the ethical hacker uses automated tools to identify vulnerabilities in the web application. What is the main advantage of using automated tools?",
        "options": [
            "Faster identification of vulnerabilities",
            "Less skilled labor required",
            "Better accuracy than manual testing",
            "Reduced risk of detection"
        ],
        "answer": "Faster identification of vulnerabilities"
    },
    {
        "question": "After identifying vulnerabilities, an ethical hacker begins exploiting them to gain unauthorized access. What type of testing is this known as?",
        "options": [
            "Reconnaissance",
            "Exploitation",
            "Post-exploitation",
            "Reporting"
        ],
        "answer": "Exploitation"
    },
    {
        "question": "A penetration tester is examining a web application and discovers a misconfigured API endpoint. What should be the immediate next step?",
        "options": [
            "Report the finding",
            "Attempt to exploit it",
            "Document it for later",
            "Perform a full security audit"
        ],
        "answer": "Attempt to exploit it"
    },
    {
        "question": "During the exploitation phase, the ethical hacker gains access to sensitive data. What should be their next priority?",
        "options": [
            "Exfiltrate the data",
            "Cover their tracks",
            "Report the findings",
            "Gain higher privileges"
        ],
        "answer": "Report the findings"
    },
    {
        "question": "Which of the following is NOT a phase in the standard penetration testing methodology?",
        "options": [
            "Planning",
            "Exploitation",
            "Maintenance",
            "Reporting"
        ],
        "answer": "Maintenance"
    },
    {
        "question": "What is the purpose of a vulnerability assessment in the context of web server testing?",
        "options": [
            "Identify and classify vulnerabilities",
            "Fix identified vulnerabilities",
            "Exploit vulnerabilities",
            "Validate security measures"
        ],
        "answer": "Identify and classify vulnerabilities"
    },
    {
        "question": "When reporting findings after a penetration test, which of the following should be prioritized?",
        "options": [
            "Technical details of exploitation",
            "Business impact of vulnerabilities",
            "Tools used during testing",
            "User feedback"
        ],
        "answer": "Business impact of vulnerabilities"
    },
    {
        "question": "During the post-exploitation phase, what is the ethical hacker's primary concern?",
        "options": [
            "To find more vulnerabilities",
            "To maintain access for future testing",
            "To ensure data integrity",
            "To prepare the final report"
        ],
        "answer": "To maintain access for future testing"
    },
    {
        "question": "To defend against SQL injection attacks, which practice should be implemented at the web application level?",
        "options": [
            "Input validation",
            "Encryption of passwords",
            "Regular backups",
            "Increasing server resources"
        ],
        "answer": "Input validation"
    },
    {
        "question": "A company is implementing a Web Application Firewall (WAF) to protect its web servers. What is the primary purpose of a WAF?",
        "options": [
            "Monitor server performance",
            "Block malicious traffic",
            "Provide SSL termination",
            "Increase website speed"
        ],
        "answer": "Block malicious traffic"
    },
    {
        "question": "In the context of web server security, what is the main purpose of regular patch management?",
        "options": [
            "Enhance server performance",
            "Reduce vulnerabilities",
            "Improve user experience",
            "Increase server capacity"
        ],
        "answer": "Reduce vulnerabilities"
    },
    {
        "question": "To mitigate XSS vulnerabilities, what should developers ensure when processing user inputs?",
        "options": [
            "Escape all user inputs",
            "Use a content delivery network",
            "Increase the server timeout",
            "Limit access to resources"
        ],
        "answer": "Escape all user inputs"
    },
    {
        "question": "A company notices repeated unauthorized access attempts on their web server logs. What countermeasure can they implement?",
        "options": [
            "Enable rate limiting",
            "Disable logging",
            "Increase the server's storage",
            "Expand their bandwidth"
        ],
        "answer": "Enable rate limiting"
    },
    {
        "question": "When securing a web server, why is it important to use secure default configurations?",
        "options": [
            "To make the server easier to use",
            "To prevent attackers from exploiting common vulnerabilities",
            "To improve server performance",
            "To reduce maintenance costs"
        ],
        "answer": "To prevent attackers from exploiting common vulnerabilities"
    },
    {
        "question": "To ensure confidentiality and integrity in web communications, which protocol should be implemented?",
        "options": [
            "HTTP",
            "FTP",
            "TLS/SSL",
            "SMTP"
        ],
        "answer": "TLS/SSL"
    },
    {
        "question": "What is a primary benefit of implementing multi-factor authentication (MFA) on a web server?",
        "options": [
            "Increased speed of access",
            "Reduced administrative costs",
            "Enhanced user experience",
            "Improved security against unauthorized access"
        ],
        "answer": "Improved security against unauthorized access"
    },
    {
        "question": "To prevent directory traversal attacks, what should be configured on the web server?",
        "options": [
            "Restrict file permissions",
            "Enable directory listing",
            "Increase server memory",
            "Use a stronger password"
        ],
        "answer": "Restrict file permissions"
    },
    {
        "question": "Which of the following is a critical practice for securing web applications against common vulnerabilities?",
        "options": [
            "Conducting regular security audits",
            "Increased data redundancy",
            "Upgrading hardware",
            "Using open-source libraries only"
        ],
        "answer": "Conducting regular security audits"
    },
    {
        "question": "Anna is configuring a web server to handle sensitive transactions. What feature should she enable to ensure secure communication?",
        "options": [
            "HTTP/2",
            "SSL/TLS",
            "CDN integration",
            "WebSockets"
        ],
        "answer": "SSL/TLS"
    },
    {
        "question": "What is the primary role of a reverse proxy in web server architecture?",
        "options": [
            "Serve static content",
            "Distribute traffic among servers",
            "Act as a firewall",
            "Encrypt data"
        ],
        "answer": "Distribute traffic among servers"
    },
    {
        "question": "During a security assessment, a tester notices a server is using outdated cryptographic protocols. What is the major risk associated with this?",
        "options": [
            "Faster processing speed",
            "Increased performance",
            "Vulnerability to cryptanalysis",
            "Reduced bandwidth"
        ],
        "answer": "Vulnerability to cryptanalysis"
    },
    {
        "question": "What is the purpose of a Content Security Policy (CSP) in web applications?",
        "options": [
            "Prevent cross-origin requests",
            "Block all scripts by default",
            "Prevent XSS attacks",
            "Improve page load speed"
        ],
        "answer": "Prevent XSS attacks"
    },
    {
        "question": "Which of the following best describes the principle of least privilege in web server security?",
        "options": [
            "Granting all users full access",
            "Providing users only the permissions necessary for their roles",
            "Enabling public access to sensitive resources",
            "Allowing unrestricted access to the server"
        ],
        "answer": "Providing users only the permissions necessary for their roles"
    },
    {
        "question": "In the context of web servers, what does the term 'sandboxing' refer to?",
        "options": [
            "Isolating applications to prevent system-wide changes",
            "Encrypting data in transit",
            "Improving server response time",
            "Blocking unauthorized access"
        ],
        "answer": "Isolating applications to prevent system-wide changes"
    },
    {
        "question": "What is a primary function of web server access control lists (ACLs)?",
        "options": [
            "Manage bandwidth usage",
            "Control who can access certain resources",
            "Monitor server performance",
            "Optimize database queries"
        ],
        "answer": "Control who can access certain resources"
    },
    {
        "question": "What type of web server configuration is most effective for preventing CSRF attacks?",
        "options": [
            "Strictly using GET requests",
            "Implementing anti-CSRF tokens",
            "Allowing cross-origin requests",
            "Increasing session timeouts"
        ],
        "answer": "Implementing anti-CSRF tokens"
    },
    {
        "question": "During a risk assessment, a tester finds that a web server has default credentials enabled. What is the risk associated with this?",
        "options": [
            "Easier system performance tuning",
            "Increased vulnerability to unauthorized access",
            "Reduced maintenance costs",
            "Faster user onboarding"
        ],
        "answer": "Increased vulnerability to unauthorized access"
    },
    {
        "question": "Which of the following headers can be used to mitigate clickjacking attacks?",
        "options": [
            "X-Frame-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ],
        "answer": "X-Frame-Options"
    },
    {
        "question": "A security analyst finds that a web server is suffering from session hijacking. What is the primary technique an attacker might use?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "Brute force password guessing",
            "Phishing",
            "Network sniffing"
        ],
        "answer": "Network sniffing"
    },
    {
        "question": "During a pentest, an ethical hacker discovers an open HTTP method on a server. Which method could be dangerous if not properly controlled?",
        "options": [
            "HEAD",
            "GET",
            "PUT",
            "OPTIONS"
        ],
        "answer": "PUT"
    },
    {
        "question": "An attacker is exploiting a vulnerability that allows them to execute arbitrary commands on a server. What type of vulnerability does this typically indicate?",
        "options": [
            "Command Injection",
            "SQL Injection",
            "XSS",
            "Cross-Site Request Forgery"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "A tester notices that a web application uses a public API key. What risk does this pose?",
        "options": [
            "Exposure to SQL injection",
            "Potential for unauthorized API access",
            "Increased bandwidth usage",
            "Faster application response time"
        ],
        "answer": "Potential for unauthorized API access"
    },
    {
        "question": "Which attack involves an attacker impersonating a legitimate user by intercepting their session token?",
        "options": [
            "Session fixation",
            "Session hijacking",
            "Cross-Site Scripting",
            "Clickjacking"
        ],
        "answer": "Session hijacking"
    },
    {
        "question": "In a web application, an attacker manipulates input fields to execute JavaScript code. This is known as what type of attack?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "Path Traversal"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "A vulnerability assessment reveals that a web application is leaking sensitive data in its error messages. What type of risk does this represent?",
        "options": [
            "Insufficient logging",
            "Information disclosure",
            "Insecure direct object references",
            "Broken authentication"
        ],
        "answer": "Information disclosure"
    },
    {
        "question": "During an assessment, a hacker uses social engineering to trick an employee into revealing sensitive information. What type of attack is this?",
        "options": [
            "Phishing",
            "Pretexting",
            "Baiting",
            "Shoulder surfing"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "Which type of attack can exploit a web application's lack of input validation, allowing an attacker to inject malicious scripts?",
        "options": [
            "Cross-Site Request Forgery (CSRF)",
            "Command Injection",
            "Cross-Site Scripting (XSS)",
            "SQL Injection"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "What type of attack occurs when an attacker manipulates the website's response to a user's request?",
        "options": [
            "HTTP Response Splitting",
            "Denial of Service",
            "Code Injection",
            "SQL Injection"
        ],
        "answer": "HTTP Response Splitting"
    },
    {
        "question": "When conducting a vulnerability scan, what is the primary goal of the reconnaissance phase?",
        "options": [
            "Gathering information about the target",
            "Exploiting vulnerabilities",
            "Reporting findings",
            "Analyzing security policies"
        ],
        "answer": "Gathering information about the target"
    },
    {
        "question": "Which phase of penetration testing involves using the information gathered to identify potential attack vectors?",
        "options": [
            "Exploitation",
            "Scanning",
            "Reporting",
            "Post-exploitation"
        ],
        "answer": "Scanning"
    },
    {
        "question": "An ethical hacker uses tools to simulate attacks on a web server. What is this process called?",
        "options": [
            "Vulnerability assessment",
            "Penetration testing",
            "Network mapping",
            "Risk analysis"
        ],
        "answer": "Penetration testing"
    },
    {
        "question": "In a penetration test, what is the purpose of the exploitation phase?",
        "options": [
            "Identify vulnerabilities",
            "Gain unauthorized access",
            "Analyze security controls",
            "Create a final report"
        ],
        "answer": "Gain unauthorized access"
    },
    {
        "question": "After conducting a penetration test, what is the most critical aspect of the reporting phase?",
        "options": [
            "Detailing every attack vector used",
            "Providing actionable remediation steps",
            "Listing all tools used",
            "Summarizing server performance"
        ],
        "answer": "Providing actionable remediation steps"
    },
    {
        "question": "What is the primary objective of the post-exploitation phase in penetration testing?",
        "options": [
            "To clean up and secure the environment",
            "To extract sensitive data",
            "To gain higher privileges",
            "To finalize the testing tools"
        ],
        "answer": "To extract sensitive data"
    },
    {
        "question": "When reviewing logs after an attack, which type of entry is critical to identify potential breaches?",
        "options": [
            "Successful login attempts",
            "Error messages",
            "Unauthorized access attempts",
            "System reboots"
        ],
        "answer": "Unauthorized access attempts"
    },
    {
        "question": "What is a common tool used for web application scanning during the assessment phase?",
        "options": [
            "Nmap",
            "Burp Suite",
            "Wireshark",
            "Metasploit"
        ],
        "answer": "Burp Suite"
    },
    {
        "question": "In the context of penetration testing, what does the term 'pivoting' refer to?",
        "options": [
            "Gaining access to a target system",
            "Moving laterally within a network after initial access",
            "Exfiltrating data",
            "Generating a final report"
        ],
        "answer": "Moving laterally within a network after initial access"
    },
    {
        "question": "What is a key reason to perform vulnerability scanning regularly?",
        "options": [
            "To identify outdated software",
            "To optimize server performance",
            "To improve user experience",
            "To reduce costs"
        ],
        "answer": "To identify outdated software"
    },
    {
        "question": "What is one of the most effective ways to protect against SQL injection vulnerabilities?",
        "options": [
            "Using prepared statements",
            "Disabling user input",
            "Increasing database privileges",
            "Implementing CAPTCHA"
        ],
        "answer": "Using prepared statements"
    },
    {
        "question": "Which practice helps in mitigating the risk of credential theft in web applications?",
        "options": [
            "Storing passwords as plain text",
            "Using multi-factor authentication",
            "Allowing unlimited login attempts",
            "Using weak hashing algorithms"
        ],
        "answer": "Using multi-factor authentication"
    },
    {
        "question": "What type of logging is essential for detecting malicious activity on a web server?",
        "options": [
            "Only error logging",
            "Comprehensive access and error logging",
            "Performance logging",
            "User activity logging only"
        ],
        "answer": "Comprehensive access and error logging"
    },
    {
        "question": "To minimize exposure to Cross-Site Scripting (XSS), what should developers implement?",
        "options": [
            "Content Security Policy (CSP)",
            "Strict Content-Type headers",
            "URL encoding",
            "User authentication"
        ],
        "answer": "Content Security Policy (CSP)"
    },
    {
        "question": "Which of the following is a best practice for securing API endpoints?",
        "options": [
            "Use public keys only",
            "Implement rate limiting and access controls",
            "Allow all origins",
            "Disable SSL"
        ],
        "answer": "Implement rate limiting and access controls"
    },
    {
        "question": "What is the purpose of using security headers like X-XSS-Protection?",
        "options": [
            "To prevent unauthorized access",
            "To mitigate XSS attacks",
            "To enhance server performance",
            "To log user activities"
        ],
        "answer": "To mitigate XSS attacks"
    },
    {
        "question": "Which countermeasure is effective against Distributed Denial-of-Service (DDoS) attacks?",
        "options": [
            "Increase server bandwidth",
            "Implement network traffic monitoring and filtering",
            "Reduce logging frequency",
            "Disable all external traffic"
        ],
        "answer": "Implement network traffic monitoring and filtering"
    },
    {
        "question": "What practice helps ensure that web server software remains secure?",
        "options": [
            "Ignoring vendor recommendations",
            "Regularly applying security patches",
            "Using outdated versions",
            "Reducing server hardware"
        ],
        "answer": "Regularly applying security patches"
    },
    {
        "question": "To mitigate the risk of an internal threat, what measure should organizations implement?",
        "options": [
            "Open access to all employees",
            "Regular training and awareness programs",
            "Increased password complexity",
            "Reduced monitoring"
        ],
        "answer": "Regular training and awareness programs"
    },
    {
        "question": "What type of testing should be conducted after implementing security measures to ensure their effectiveness?",
        "options": [
            "Retrospective analysis",
            "Regression testing",
            "Penetration testing",
            "User acceptance testing"
        ],
        "answer": "Penetration testing"
    },
    {
        "question": "A web application is vulnerable to a stored XSS attack. An attacker crafts a payload that gets saved in the database. What should the developer implement to mitigate this risk?",
        "options": [
            "Input sanitization",
            "Using HTTP headers",
            "Regular database backups",
            "Password hashing"
        ],
        "answer": "Input sanitization"
    },
    {
        "question": "While testing a web application, a security analyst discovers that error messages reveal stack traces containing sensitive information. What type of vulnerability does this represent?",
        "options": [
            "Information leakage",
            "Cross-Site Request Forgery (CSRF)",
            "SQL Injection",
            "Session fixation"
        ],
        "answer": "Information leakage"
    },
    {
        "question": "A web server has been compromised, and the attacker installs a rootkit to maintain access. What is the most critical first step for the incident response team?",
        "options": [
            "Isolate the affected server",
            "Analyze network traffic",
            "Identify the attack vector",
            "Deploy a backup server"
        ],
        "answer": "Isolate the affected server"
    },
    {
        "question": "During a vulnerability assessment, a web application accepts user-supplied URLs for redirection. This leads to an open redirect vulnerability. What can an organization implement to prevent this?",
        "options": [
            "Whitelist allowed URLs",
            "Sanitize user input",
            "Increase logging detail",
            "Disable URL redirection"
        ],
        "answer": "Whitelist allowed URLs"
    },
    {
        "question": "An organization is using outdated libraries in its web application. What is a significant risk associated with this practice?",
        "options": [
            "Increased server speed",
            "Reduced memory usage",
            "Vulnerability to known exploits",
            "Enhanced user experience"
        ],
        "answer": "Vulnerability to known exploits"
    },
    {
        "question": "After conducting a penetration test, the findings reveal a significant number of outdated plugins in the web application. What immediate action should the development team take?",
        "options": [
            "Ignore them, as updates are not critical",
            "Update all plugins to their latest versions",
            "Create a plan to update plugins gradually",
            "Remove the plugins from the application"
        ],
        "answer": "Update all plugins to their latest versions"
    },
    {
        "question": "During a pentest, an attacker successfully exploits a cross-site scripting vulnerability and executes JavaScript on a user's browser. What type of attack does this represent?",
        "options": [
            "Stored XSS",
            "Reflected XSS",
            "DOM-based XSS",
            "Session hijacking"
        ],
        "answer": "Stored XSS"
    },
    {
        "question": "Which of the following is a primary concern when enabling directory listing on a web server?",
        "options": [
            "Increased server performance",
            "Potential exposure of sensitive files",
            "Improved user navigation",
            "Reduced bandwidth usage"
        ],
        "answer": "Potential exposure of sensitive files"
    },
    {
        "question": "An ethical hacker is assessing a web application and notices it does not validate session tokens. What type of attack is this vulnerability most susceptible to?",
        "options": [
            "Cross-Site Scripting",
            "Session fixation",
            "Cross-Site Request Forgery",
            "Denial of Service"
        ],
        "answer": "Session fixation"
    },
    {
        "question": "To protect against SQL injection, which coding practice is essential?",
        "options": [
            "Using dynamic SQL queries",
            "Implementing input validation and parameterized queries",
            "Allowing user inputs in SQL commands",
            "Hiding error messages from users"
        ],
        "answer": "Implementing input validation and parameterized queries"
    },
    {
        "question": "An attacker conducts a DoS attack on a web application by sending excessive requests. What is a primary countermeasure to mitigate this?",
        "options": [
            "Increasing server bandwidth",
            "Implementing rate limiting",
            "Disabling logging",
            "Using weak passwords"
        ],
        "answer": "Implementing rate limiting"
    },
    {
        "question": "During a security review, it is discovered that a web application does not enforce secure cookies. What risk does this pose?",
        "options": [
            "Increased page load time",
            "Vulnerability to man-in-the-middle attacks",
            "Reduced application performance",
            "Difficulty in maintaining sessions"
        ],
        "answer": "Vulnerability to man-in-the-middle attacks"
    },
    {
        "question": "An attacker successfully gains access to a web server by exploiting a misconfigured security group in the cloud. What type of vulnerability is this an example of?",
        "options": [
            "Misconfiguration vulnerability",
            "Insider threat",
            "Cross-Site Scripting",
            "Weak password policy"
        ],
        "answer": "Misconfiguration vulnerability"
    },
    {
        "question": "Which of the following practices is most effective in protecting against unauthorized data access through an API?",
        "options": [
            "Using public API keys only",
            "Implementing OAuth2 authentication",
            "Allowing unrestricted access",
            "Avoiding encryption"
        ],
        "answer": "Implementing OAuth2 authentication"
    },
    {
        "question": "A penetration tester finds that a web server is running a vulnerable version of a well-known application. What should be the primary course of action?",
        "options": [
            "Ignore it if it works fine",
            "Upgrade to the latest version immediately",
            "Monitor for exploits",
            "Change default configurations"
        ],
        "answer": "Upgrade to the latest version immediately"
    },
    {
        "question": "Which type of attack involves intercepting and altering communications between a user and a web application?",
        "options": [
            "Man-in-the-middle attack",
            "Phishing",
            "Denial of Service",
            "Brute force attack"
        ],
        "answer": "Man-in-the-middle attack"
    },
    {
        "question": "A web application requires users to enter a CAPTCHA to access sensitive features. What is this primarily aimed at preventing?",
        "options": [
            "SQL injection",
            "Automated bot attacks",
            "Cross-Site Scripting",
            "Session hijacking"
        ],
        "answer": "Automated bot attacks"
    },
    {
        "question": "What is the primary risk of not using HTTPS for a web application that handles sensitive user data?",
        "options": [
            "Increased server load",
            "Data exposure during transmission",
            "Reduced search engine ranking",
            "Higher latency"
        ],
        "answer": "Data exposure during transmission"
    },
    {
        "question": "After exploiting a vulnerability, an attacker plants a backdoor on the web server. What is a primary concern for the organization now?",
        "options": [
            "Data loss",
            "Unauthorized persistent access",
            "Increased user activity",
            "Improved application speed"
        ],
        "answer": "Unauthorized persistent access"
    },
    {
        "question": "To enhance web application security, what is a recommended practice regarding third-party libraries?",
        "options": [
            "Use as many as possible for functionality",
            "Regularly review and update them",
            "Trust the vendors completely",
            "Ignore them if they seem stable"
        ],
        "answer": "Regularly review and update them"
    },
    {
        "question": "What type of vulnerability arises when a web application allows users to access resources by manipulating URLs?",
        "options": [
            "Cross-Site Request Forgery (CSRF)",
            "Insecure Direct Object Reference (IDOR)",
            "Session hijacking",
            "SQL Injection"
        ],
        "answer": "Insecure Direct Object Reference (IDOR)"
    },
    {
        "question": "An organization implements multi-factor authentication for its web application. What is the primary benefit of this practice?",
        "options": [
            "Increased usability",
            "Reduced server costs",
            "Improved security against unauthorized access",
            "Faster user registration"
        ],
        "answer": "Improved security against unauthorized access"
    },
    {
        "question": "In a post-exploitation scenario, what should the ethical hacker prioritize?",
        "options": [
            "Maximizing data exfiltration",
            "Covering their tracks",
            "Identifying further vulnerabilities",
            "Preparing the final report"
        ],
        "answer": "Identifying further vulnerabilities"
    },
    {
        "question": "When securing a web application against XSS, which of the following practices is most effective?",
        "options": [
            "Using input validation and output encoding",
            "Limiting user session durations",
            "Implementing CAPTCHA",
            "Enabling error logging"
        ],
        "answer": "Using input validation and output encoding"
    },
    {
        "question": "During a risk assessment, a tester identifies that a web server is exposing version numbers in HTTP headers. What is the primary risk?",
        "options": [
            "Information disclosure",
            "Performance issues",
            "Data corruption",
            "User dissatisfaction"
        ],
        "answer": "Information disclosure"
    },
    {
        "question": "What is the primary purpose of using a Web Application Firewall (WAF) in a web server environment?",
        "options": [
            "To increase server speed",
            "To block or filter HTTP traffic",
            "To manage user sessions",
            "To optimize database queries"
        ],
        "answer": "To block or filter HTTP traffic"
    },
    {
        "question": "When implementing security measures for APIs, which approach is most effective in validating user input?",
        "options": [
            "Trust all incoming data",
            "Use client-side validation only",
            "Implement server-side validation and sanitization",
            "Limit validation to URL paths"
        ],
        "answer": "Implement server-side validation and sanitization"
    },
    {
        "question": "Which of the following is a common indicator of a web application being compromised?",
        "options": [
            "Increased server uptime",
            "Unexpected outbound traffic",
            "Improved response time",
            "Increased user registrations"
        ],
        "answer": "Unexpected outbound traffic"
    },
    {
        "question": "What security measure should be prioritized to protect sensitive information stored in cookies?",
        "options": [
            "Set the SameSite attribute",
            "Disable cookies altogether",
            "Allow access to all domains",
            "Store sensitive data in plain text"
        ],
        "answer": "Set the SameSite attribute"
    },
    {
        "question": "When assessing the security of a web server, what is the significance of employing a 'Defense in Depth' strategy?",
        "options": [
            "To reduce the number of firewalls",
            "To rely on a single security layer",
            "To implement multiple layers of security controls",
            "To streamline security policies"
        ],
        "answer": "To implement multiple layers of security controls"
    },
    {
        "question": "An attacker uses a vulnerability to execute code on a server that allows them to gain a shell. What type of attack is this?",
        "options": [
            "Remote Code Execution (RCE)",
            "Denial of Service (DoS)",
            "SQL Injection",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Remote Code Execution (RCE)"
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
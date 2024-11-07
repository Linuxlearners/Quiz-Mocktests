
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "Alice discovers a vulnerability in a mobile application that allows her to intercept network traffic due to lack of encryption. What type of attack is she likely exploiting?",
        "options": [
            "Man-in-the-Middle (MitM)",
            "Cross-Site Scripting (XSS)",
            "Session Fixation",
            "Phishing"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "While conducting a security assessment, Bob finds that a mobile app stores sensitive data in plain text on the device. What attack vector does this vulnerability primarily represent?",
        "options": [
            "Data Leakage",
            "Insecure Direct Object Reference",
            "Code Injection",
            "SQL Injection"
        ],
        "answer": "Data Leakage"
    },
    {
        "question": "During a penetration test, Carol exploits a weakness in a mobile app's API that lacks proper authentication checks. What type of attack is this an example of?",
        "options": [
            "API Injection",
            "Broken Authentication",
            "Session Hijacking",
            "Insufficient Logging"
        ],
        "answer": "Broken Authentication"
    },
    {
        "question": "A security researcher finds that a mobile banking app does not verify the integrity of the software it communicates with. What risk does this pose?",
        "options": [
            "Code Injection",
            "Man-in-the-Middle attack",
            "Phishing",
            "Data Breach"
        ],
        "answer": "Man-in-the-Middle attack"
    },
    {
        "question": "A company uses a mobile app that lacks proper session management, allowing attackers to hijack active sessions. What vulnerability is this an example of?",
        "options": [
            "Session Fixation",
            "Cross-Site Request Forgery (CSRF)",
            "Insecure Session Management",
            "Insufficient Security Controls"
        ],
        "answer": "Insecure Session Management"
    },
    {
        "question": "Mark is testing an app that allows users to upload files. He notices no validation on file types. What kind of vulnerability is present?",
        "options": [
            "Unrestricted File Upload",
            "Remote Code Execution",
            "Cross-Site Scripting (XSS)",
            "Directory Traversal"
        ],
        "answer": "Unrestricted File Upload"
    },
    {
        "question": "Lisa is analyzing a mobile app that doesn't use HTTPS for data transmission. Which attack could most easily target this app?",
        "options": [
            "Data Breach",
            "Man-in-the-Middle (MitM)",
            "Cross-Site Scripting (XSS)",
            "Denial of Service (DoS)"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "While inspecting an app, John finds that it stores sensitive information in shared preferences. What type of vulnerability is this?",
        "options": [
            "Data Leakage",
            "Insecure Data Storage",
            "Buffer Overflow",
            "Cryptographic Failure"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "During a mobile app audit, Sarah finds that user credentials are sent in the URL instead of the body. What is the main risk here?",
        "options": [
            "Credential Leakage",
            "Insecure Data Transmission",
            "Man-in-the-Middle (MitM)",
            "Session Hijacking"
        ],
        "answer": "Credential Leakage"
    },
    {
        "question": "Tom discovers that a popular mobile app exposes its API endpoints without proper access controls. What attack does this primarily enable?",
        "options": [
            "API Abuse",
            "SQL Injection",
            "Code Injection",
            "Denial of Service (DoS)"
        ],
        "answer": "API Abuse"
    },
    {
        "question": "A mobile application displays sensitive data directly in the user interface without any obfuscation. What type of vulnerability is this indicative of?",
        "options": [
            "Data Leakage",
            "Insecure Data Storage",
            "Lack of Encryption",
            "Inadequate Logging"
        ],
        "answer": "Data Leakage"
    },
    {
        "question": "Emma finds that a mobile app is vulnerable to clickjacking due to improper handling of user interface elements. What is the primary risk?",
        "options": [
            "User Impersonation",
            "Data Breach",
            "Phishing",
            "Session Hijacking"
        ],
        "answer": "User Impersonation"
    },
    {
        "question": "A mobile application uses a third-party library that has known vulnerabilities. What type of attack could this expose the application to?",
        "options": [
            "Dependency Confusion",
            "Supply Chain Attack",
            "Code Injection",
            "Remote File Inclusion"
        ],
        "answer": "Supply Chain Attack"
    },
    {
        "question": "During a security review, David finds that an app does not properly sanitize user inputs. Which attack is this most likely to facilitate?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Directory Traversal",
            "Remote Code Execution"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "A user installs a seemingly harmless app that secretly accesses contacts and messages. What type of attack does this illustrate?",
        "options": [
            "Spyware",
            "Phishing",
            "Data Breach",
            "Ransomware"
        ],
        "answer": "Spyware"
    },
    {
        "question": "A mobile device management (MDM) solution is implemented to secure company-owned devices. What is a primary benefit of this approach?",
        "options": [
            "Remote Wiping of Data",
            "Increased User Autonomy",
            "Reduced Device Performance",
            "Elimination of Malware"
        ],
        "answer": "Remote Wiping of Data"
    },
    {
        "question": "What is the main purpose of a mobile app security assessment?",
        "options": [
            "To improve user experience",
            "To identify vulnerabilities",
            "To enhance app performance",
            "To increase user engagement"
        ],
        "answer": "To identify vulnerabilities"
    },
    {
        "question": "Which mobile platform vulnerability is often associated with improper input validation in web views?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "Insecure Data Storage",
            "Session Fixation",
            "Clickjacking"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "An attacker uses social engineering to trick a user into installing a malicious app. What is this an example of?",
        "options": [
            "Phishing",
            "Spoofing",
            "Ransomware",
            "Trojan Horse"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A company is concerned about the security of its employees' mobile devices. What is the first step in a mobile security strategy?",
        "options": [
            "Implementing strong passwords",
            "Conducting a risk assessment",
            "Deploying an MDM solution",
            "Educating employees about security"
        ],
        "answer": "Conducting a risk assessment"
    },
    {
        "question": "A mobile app allows users to reset passwords via email. What vulnerability could arise if email verification is not implemented properly?",
        "options": [
            "Account Takeover",
            "Session Hijacking",
            "Data Leakage",
            "Insufficient Security Controls"
        ],
        "answer": "Account Takeover"
    },
    {
        "question": "Which of the following is a recommended practice for securing mobile applications?",
        "options": [
            "Use hard-coded credentials",
            "Encrypt sensitive data",
            "Store credentials in plain text",
            "Allow unrestricted file uploads"
        ],
        "answer": "Encrypt sensitive data"
    },
    {
        "question": "A user notices that their mobile app behaves unexpectedly after a recent update. What could this potentially indicate?",
        "options": [
            "Malware Infection",
            "Performance Improvement",
            "User Error",
            "Feature Enhancement"
        ],
        "answer": "Malware Infection"
    },
    {
        "question": "A developer is creating a mobile app that accesses sensitive data. What is an essential security measure to implement during development?",
        "options": [
            "User Feedback Integration",
            "Third-Party Library Usage",
            "Input Validation and Sanitization",
            "Minimal User Interface Design"
        ],
        "answer": "Input Validation and Sanitization"
    },
    {
        "question": "While performing a security audit, a tester finds an outdated library that has known vulnerabilities in a mobile app. What is the best course of action?",
        "options": [
            "Ignore it",
            "Update the library",
            "Report it to the user",
            "Remove the library entirely"
        ],
        "answer": "Update the library"
    },
    {
        "question": "What type of attack allows an attacker to gain access to a mobile device by tricking the user into installing a malicious application?",
        "options": [
            "Trojan Horse",
            "Man-in-the-Middle",
            "Phishing",
            "Keylogging"
        ],
        "answer": "Trojan Horse"
    },
    {
        "question": "During a mobile security assessment, you find that an app is vulnerable to SQL injection. What should be your first recommendation?",
        "options": [
            "Implement parameterized queries",
            "Sanitize all inputs",
            "Use stored procedures",
            "Increase server resources"
        ],
        "answer": "Implement parameterized queries"
    },
    {
        "question": "A mobile application that fails to properly validate SSL certificates is susceptible to which type of attack?",
        "options": [
            "Man-in-the-Middle (MitM)",
            "Session Hijacking",
            "Data Breach",
            "SQL Injection"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "Which of the following is a common vulnerability in mobile applications that use web views?",
        "options": [
            "Insecure Data Storage",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Code Injection"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "A security policy requires that all mobile applications be signed with a trusted certificate. What is the primary goal of this requirement?",
        "options": [
            "To ensure code integrity",
            "To improve performance",
            "To reduce installation time",
            "To enhance user experience"
        ],
        "answer": "To ensure code integrity"
    },
    {
        "question": "An organization implements an MDM solution that allows remote wiping of devices. What is a primary advantage of this feature?",
        "options": [
            "Increased Device Usability",
            "Protection of Sensitive Data",
            "Enhanced User Privacy",
            "Simplified Device Management"
        ],
        "answer": "Protection of Sensitive Data"
    },
    {
        "question": "Which of the following tools is commonly used to analyze mobile application security?",
        "options": [
            "Burp Suite",
            "Nessus",
            "Metasploit",
            "Wireshark"
        ],
        "answer": "Burp Suite"
    },
    {
        "question": "What type of vulnerability occurs when a mobile application exposes sensitive data through log files?",
        "options": [
            "Data Leakage",
            "Insecure Data Storage",
            "Code Injection",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Data Leakage"
    },
    {
        "question": "A developer is tasked with securing a mobile app that uses a public API. What should be the primary focus during the security review?",
        "options": [
            "Rate Limiting",
            "User Interface Design",
            "Database Performance",
            "Server Load Balancing"
        ],
        "answer": "Rate Limiting"
    },
    {
        "question": "An attacker targets a mobile app that does not validate app updates. What type of attack is this called?",
        "options": [
            "Man-in-the-Middle (MitM)",
            "Supply Chain Attack",
            "Replay Attack",
            "Session Hijacking"
        ],
        "answer": "Supply Chain Attack"
    },
    {
        "question": "During a security assessment, a tester discovers that a mobile app hardcodes API keys. What is the primary risk associated with this practice?",
        "options": [
            "API Abuse",
            "Data Breach",
            "Malware Injection",
            "Session Hijacking"
        ],
        "answer": "API Abuse"
    },
    {
        "question": "What type of security feature would help prevent unauthorized app installations on a mobile device?",
        "options": [
            "App Store Restrictions",
            "User Education",
            "VPN Usage",
            "Firewall Settings"
        ],
        "answer": "App Store Restrictions"
    },
    {
        "question": "A penetration tester discovers that a mobile application exposes sensitive endpoints without authentication. What is the primary implication of this vulnerability?",
        "options": [
            "Data Theft",
            "Denial of Service",
            "User Privacy Violation",
            "Performance Degradation"
        ],
        "answer": "Data Theft"
    },
    {
        "question": "Which type of attack involves manipulating the behavior of a mobile application through unexpected input?",
        "options": [
            "Input Validation Attack",
            "Phishing Attack",
            "Denial of Service",
            "Eavesdropping"
        ],
        "answer": "Input Validation Attack"
    },
    {
        "question": "A user installs a mobile app that requests unnecessary permissions. What should the user consider this?",
        "options": [
            "Inconvenient",
            "Suspicious",
            "Normal Practice",
            "Recommended"
        ],
        "answer": "Suspicious"
    },
    {
        "question": "During a security audit, a developer is advised to implement multi-factor authentication in their mobile app. What is the primary benefit of this measure?",
        "options": [
            "Increased User Engagement",
            "Improved Security",
            "Enhanced User Experience",
            "Faster Authentication"
        ],
        "answer": "Improved Security"
    },
    {
        "question": "What is the primary goal of encryption in mobile applications?",
        "options": [
            "To enhance performance",
            "To protect sensitive data",
            "To simplify user authentication",
            "To reduce application size"
        ],
        "answer": "To protect sensitive data"
    },
    {
        "question": "A security team implements a framework for securely developing mobile applications. What is the primary purpose of this framework?",
        "options": [
            "Enhancing User Experience",
            "Improving Security Posture",
            "Reducing Development Time",
            "Increasing Market Reach"
        ],
        "answer": "Improving Security Posture"
    },
    {
        "question": "Which of the following is a common characteristic of a mobile malware?",
        "options": [
            "Self-replicating",
            "Requires user interaction",
            "Installs via email attachment",
            "Targeted towards desktop systems"
        ],
        "answer": "Requires user interaction"
    },
    {
        "question": "A mobile application uses hard-coded secrets for authentication. What is the major security concern with this practice?",
        "options": [
            "Easy to reverse engineer",
            "Increased performance",
            "User convenience",
            "Reduces development time"
        ],
        "answer": "Easy to reverse engineer"
    },
    {
        "question": "During a risk assessment, a company identifies that its mobile app lacks secure coding practices. What should be the first step to mitigate this risk?",
        "options": [
            "Conduct a security training for developers",
            "Implement a new coding language",
            "Remove the mobile app",
            "Increase app advertising"
        ],
        "answer": "Conduct a security training for developers"
    },
    {
        "question": "A security analyst discovers a mobile app that communicates with a server using plain HTTP. What is the most critical issue here?",
        "options": [
            "Insecure Data Transmission",
            "High Latency",
            "Inadequate User Interface",
            "Poor User Experience"
        ],
        "answer": "Insecure Data Transmission"
    },
    {
        "question": "An attacker exploits a mobile app's session management flaw to steal user credentials. What type of vulnerability does this represent?",
        "options": [
            "Cross-Site Request Forgery (CSRF)",
            "Broken Authentication",
            "SQL Injection",
            "Insecure Data Storage"
        ],
        "answer": "Broken Authentication"
    },
    {
        "question": "Which of the following is a common mobile security threat that involves unauthorized access to user data through malicious apps?",
        "options": [
            "Spyware",
            "Denial of Service (DoS)",
            "Ransomware",
            "Phishing"
        ],
        "answer": "Spyware"
    },
    {
        "question": "A security expert advises a company to implement secure app development practices. What is one of the most critical practices?",
        "options": [
            "Frequent updates",
            "User testing",
            "Code reviews",
            "Performance optimization"
        ],
        "answer": "Code reviews"
    },
    {
        "question": "A mobile application is found to have a vulnerability where it allows the injection of unauthorized commands. What is this vulnerability commonly known as?",
        "options": [
            "Command Injection",
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Buffer Overflow"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "An organization decides to use an MDM solution for its mobile devices. What is one of the primary reasons for this decision?",
        "options": [
            "To reduce costs",
            "To enable remote management and security",
            "To limit device functionality",
            "To enhance user customization"
        ],
        "answer": "To enable remote management and security"
    },
    {
        "question": "A developer includes logging functionality in a mobile app. What should they ensure about the logs to maintain security?",
        "options": [
            "Logs contain user passwords",
            "Logs are stored in an encrypted format",
            "Logs are publicly accessible",
            "Logs contain detailed system errors"
        ],
        "answer": "Logs are stored in an encrypted format"
    },
    {
        "question": "During an assessment, a tester finds that a mobile app does not have a mechanism to limit login attempts. What is the primary risk associated with this?",
        "options": [
            "Brute Force Attack",
            "Data Breach",
            "Insecure Data Storage",
            "Phishing"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "An application allows users to authenticate with a fingerprint, but the implementation is weak. What type of vulnerability could this introduce?",
        "options": [
            "Weak Authentication",
            "Insecure Data Storage",
            "Session Hijacking",
            "Code Injection"
        ],
        "answer": "Weak Authentication"
    },
    {
        "question": "A user notices that their mobile app does not ask for permissions before accessing location data. What does this indicate?",
        "options": [
            "Poor Design",
            "Privacy Violation",
            "User Convenience",
            "Security Enhancement"
        ],
        "answer": "Privacy Violation"
    },
    {
        "question": "During a security assessment, you find that an app uses deprecated cryptographic algorithms. What is the main risk of this practice?",
        "options": [
            "Increased Performance",
            "Easier Decryption",
            "Improved Security",
            "Enhanced User Experience"
        ],
        "answer": "Easier Decryption"
    },
    {
        "question": "A company implements a two-factor authentication process for its mobile app. What is the primary purpose of this measure?",
        "options": [
            "To simplify login",
            "To enhance security",
            "To reduce costs",
            "To improve user experience"
        ],
        "answer": "To enhance security"
    },
    {
        "question": "A tester finds that a mobile application does not log security events. What is the main concern with this?",
        "options": [
            "Increased Resource Usage",
            "Inability to Detect Attacks",
            "User Confusion",
            "Performance Issues"
        ],
        "answer": "Inability to Detect Attacks"
    },
    {
        "question": "Which of the following is a critical step in securing mobile applications before deployment?",
        "options": [
            "Final User Testing",
            "Security Review and Testing",
            "Market Research",
            "User Feedback Implementation"
        ],
        "answer": "Security Review and Testing"
    },
    {
        "question": "An organization implements an app sandboxing solution. What is the primary goal of this measure?",
        "options": [
            "Increase Performance",
            "Isolate apps to prevent data leakage",
            "Enhance User Interface",
            "Improve Network Connectivity"
        ],
        "answer": "Isolate apps to prevent data leakage"
    },
    {
        "question": "Which mobile security guideline focuses on keeping libraries and dependencies up to date?",
        "options": [
            "Regular Updates and Patching",
            "User Education",
            "Data Encryption",
            "Access Control Implementation"
        ],
        "answer": "Regular Updates and Patching"
    },
    {
        "question": "A developer learns that their mobile app’s API key was hardcoded in the source code. What is the immediate risk associated with this?",
        "options": [
            "Data Leakage",
            "Insecure Data Transmission",
            "Malware Infiltration",
            "API Abuse"
        ],
        "answer": "API Abuse"
    },
    {
        "question": "During a review of a mobile app, a tester finds that the app lacks session timeout features. What vulnerability does this represent?",
        "options": [
            "Session Hijacking",
            "Cross-Site Request Forgery (CSRF)",
            "Insecure Direct Object Reference",
            "Broken Authentication"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "A mobile application that improperly handles user input can lead to various attacks. What type of attack could result from this vulnerability?",
        "options": [
            "Injection Attack",
            "Data Breach",
            "Phishing",
            "Malware Installation"
        ],
        "answer": "Injection Attack"
    },
    {
        "question": "An attacker successfully installs a malicious app on a user’s mobile device through social engineering. What is this type of attack called?",
        "options": [
            "Trojan Horse",
            "Phishing",
            "Man-in-the-Middle",
            "Spyware"
        ],
        "answer": "Trojan Horse"
    },
    {
        "question": "During a security review, a mobile app developer is advised to implement logging. What is the main reason for this?",
        "options": [
            "User Convenience",
            "Performance Improvement",
            "Incident Response",
            "Feature Enhancement"
        ],
        "answer": "Incident Response"
    },
    {
        "question": "Which security practice is essential when developing mobile applications that handle sensitive data?",
        "options": [
            "Using public APIs",
            "Encrypting sensitive information",
            "Minimizing app features",
            "Allowing unrestricted access"
        ],
        "answer": "Encrypting sensitive information"
    },
    {
        "question": "What is a major risk of allowing users to upload files to a mobile application without strict validation?",
        "options": [
            "Data Breach",
            "Increased Performance",
            "User Convenience",
            "Malware Injection"
        ],
        "answer": "Malware Injection"
    },
    {
        "question": "A company implements biometric authentication in their mobile application. What is a key advantage of this approach?",
        "options": [
            "Increased Security",
            "Reduced User Experience",
            "Lower Costs",
            "Faster App Development"
        ],
        "answer": "Increased Security"
    },
    {
        "question": "A penetration tester discovers that a mobile app allows an attacker to manipulate parameters in API calls. What type of vulnerability is this?",
        "options": [
            "Insecure API",
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Session Hijacking"
        ],
        "answer": "Insecure API"
    },
    {
        "question": "During a review, it is found that a mobile application fails to validate user inputs effectively. What is the primary risk?",
        "options": [
            "Injection Attacks",
            "Denial of Service",
            "Data Leakage",
            "Insecure Data Storage"
        ],
        "answer": "Injection Attacks"
    },
    {
        "question": "A mobile application uses a third-party library with a known vulnerability. What should the organization do immediately?",
        "options": [
            "Ignore the warning",
            "Update the library or remove it",
            "Report to users",
            "Increase advertising budget"
        ],
        "answer": "Update the library or remove it"
    },
    {
        "question": "A tester finds that sensitive data is stored unencrypted on the mobile device. What is this an example of?",
        "options": [
            "Insecure Data Storage",
            "Data Breach",
            "Weak Encryption",
            "Privacy Violation"
        ],
        "answer": "Insecure Data Storage"
    },
    {
        "question": "During an assessment, a mobile app is found to be vulnerable to session fixation. What is a potential impact of this vulnerability?",
        "options": [
            "Session Hijacking",
            "Data Breach",
            "Insecure Data Storage",
            "Performance Degradation"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "A company implements security measures for their mobile applications. What should be a primary focus to mitigate risks?",
        "options": [
            "User Training",
            "Secure Development Practices",
            "Marketing Strategies",
            "Enhanced UI Design"
        ],
        "answer": "Secure Development Practices"
    },
    {
        "question": "A mobile app prompts users to enter their passwords frequently, even during short sessions. What risk does this pose?",
        "options": [
            "User Fatigue",
            "Increased Security",
            "Reduced Usability",
            "Improved Authentication"
        ],
        "answer": "User Fatigue"
    },
    {
        "question": "A mobile application does not implement any kind of input sanitization. What is the main vulnerability this represents?",
        "options": [
            "Injection Vulnerabilities",
            "Cross-Site Scripting (XSS)",
            "Data Breach",
            "Insecure Direct Object Reference"
        ],
        "answer": "Injection Vulnerabilities"
    },
    {
        "question": "What is a common attack vector for mobile applications that allow for unauthorized access to user data?",
        "options": [
            "Weak Authentication Mechanisms",
            "Strong Encryption",
            "Secure Coding Practices",
            "User Education"
        ],
        "answer": "Weak Authentication Mechanisms"
    },
    {
        "question": "During a security review, a tester identifies that a mobile app uses hard-coded API keys. What is the associated risk?",
        "options": [
            "API Abuse",
            "Increased Performance",
            "User Convenience",
            "Malware Installation"
        ],
        "answer": "API Abuse"
    },
    {
        "question": "A company implements role-based access control for its mobile application. What is the primary benefit of this approach?",
        "options": [
            "Enhanced User Experience",
            "Increased Security",
            "Reduced Costs",
            "Simplified Development"
        ],
        "answer": "Increased Security"
    },
    {
        "question": "An organization notices that its mobile app is receiving a lot of invalid login attempts. What should they implement to mitigate this risk?",
        "options": [
            "Rate Limiting",
            "User Training",
            "Enhanced UI Design",
            "Frequent Updates"
        ],
        "answer": "Rate Limiting"
    },
    {
        "question": "David is analyzing a mobile app that permits access to device features without user consent. What type of vulnerability could this represent?",
        "options": [
            "Excessive Permissions",
            "Insecure Data Storage",
            "Improper Error Handling",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Excessive Permissions"
    },
    {
        "question": "Emma finds that a mobile application uses outdated libraries, exposing it to known vulnerabilities. What kind of risk is this?",
        "options": [
            "Third-Party Library Vulnerability",
            "Insecure Code Execution",
            "Data Injection",
            "Denial of Service"
        ],
        "answer": "Third-Party Library Vulnerability"
    },
    {
        "question": "Frank conducts a security audit and discovers that a mobile app fails to implement certificate pinning. What risk does this pose?",
        "options": [
            "Man-in-the-Middle (MitM) attack",
            "Data Corruption",
            "Unauthorized Access",
            "Information Disclosure"
        ],
        "answer": "Man-in-the-Middle (MitM) attack"
    },
    {
        "question": "Grace exploits a flaw in a mobile app that accepts unvalidated input from users, which results in remote code execution. What attack is she using?",
        "options": [
            "Code Injection",
            "Cross-Site Request Forgery (CSRF)",
            "Parameter Pollution",
            "Buffer Overflow"
        ],
        "answer": "Code Injection"
    },
    {
        "question": "Hank finds that a mobile application does not sanitize inputs for its API endpoints, allowing him to execute malicious commands. This is an example of what?",
        "options": [
            "Command Injection",
            "Denial of Service",
            "SQL Injection",
            "Path Traversal"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "Isabella discovers that a mobile app leaks sensitive information through log files. What type of risk does this represent?",
        "options": [
            "Data Exposure",
            "Insecure Communications",
            "Improper Session Handling",
            "Denial of Service"
        ],
        "answer": "Data Exposure"
    },
    {
        "question": "Jake notices that a mobile application does not enforce any rate limiting on login attempts, leading to potential account enumeration. What type of vulnerability is this?",
        "options": [
            "Brute Force Attack",
            "Denial of Service",
            "Cross-Site Scripting (XSS)",
            "Insufficient Authentication"
        ],
        "answer": "Insufficient Authentication"
    },
    {
        "question": "Lily is testing a mobile application and finds that it does not properly verify the user's session after authentication. What risk does this present?",
        "options": [
            "Session Hijacking",
            "SQL Injection",
            "Information Leakage",
            "Code Execution"
        ],
        "answer": "Session Hijacking"
    },
    {
        "question": "Mark analyzes a mobile app that allows users to upload files without restriction. What type of vulnerability could this lead to?",
        "options": [
            "Arbitrary File Upload",
            "SQL Injection",
            "Cross-Site Request Forgery (CSRF)",
            "Denial of Service"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "Nina finds that a mobile application exposes sensitive API endpoints to the public without proper authentication. What type of attack could this facilitate?",
        "options": [
            "Data Breach",
            "Phishing",
            "Social Engineering",
            "Ransomware"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "Oliver discovers that an app relies solely on device ID for authentication. What kind of vulnerability does this introduce?",
        "options": [
            "Insecure Authentication",
            "Insufficient Logging",
            "Broken Access Control",
            "Insecure Data Storage"
        ],
        "answer": "Insecure Authentication"
    },
    {
        "question": "Paula conducts a security test and identifies that the mobile app's web view does not implement content security policies. What is the primary risk?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "Data Leakage",
            "Denial of Service",
            "Insecure Data Transmission"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "Quinn finds that a mobile app does not encrypt data stored locally on the device. What is the main risk associated with this?",
        "options": [
            "Data Breach",
            "Data Loss",
            "Code Execution",
            "Man-in-the-Middle attack"
        ],
        "answer": "Data Breach"
    },
    {
        "question": "Ryan is testing a mobile application and observes that it does not protect sensitive data during transmission. What attack could exploit this weakness?",
        "options": [
            "Man-in-the-Middle (MitM)",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Brute Force"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "Sophie finds that a mobile app lacks proper input validation on form fields, allowing potential SQL injection. What should be prioritized for mitigation?",
        "options": [
            "Input Sanitization",
            "Encryption of Data",
            "User Authentication",
            "Session Management"
        ],
        "answer": "Input Sanitization"
    },
    {
        "question": "Tom is testing an application that allows for deep linking to sensitive areas without proper authorization. What vulnerability does this represent?",
        "options": [
            "Broken Access Control",
            "Insecure Data Storage",
            "Cross-Site Request Forgery (CSRF)",
            "Code Injection"
        ],
        "answer": "Broken Access Control"
    },
    {
        "question": "Uma discovers that a mobile application does not log out users after a period of inactivity. What risk does this behavior pose?",
        "options": [
            "Session Hijacking",
            "Denial of Service",
            "Phishing",
            "Data Breach"
        ],
        "answer": "Session Hijacking"
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
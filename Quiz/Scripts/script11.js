
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        question: "An attacker successfully steals an authentication token from a legitimate user’s session. The attacker then uses the stolen token to impersonate the user and perform unauthorized actions. What type of attack is being described here?",
        options: [
            "Session Fixation",
            "Session Hijacking",
            "Man-in-the-Middle Attack",
            "Cross-Site Scripting (XSS)"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "During a session hijacking attack, an attacker intercepts and takes control of an active session between a client and a server. What is the primary goal of the attacker in this scenario?",
        options: [
            "Access sensitive data stored on the server",
            "Execute code on the server to disrupt services",
            "Steal the user's authentication credentials",
            "Impersonate the legitimate user to perform actions"
        ],
        answer: "Impersonate the legitimate user to perform actions"
    },
    {
        question: "A user logs into a web application and maintains an active session for some time. The session is identified by a session ID that is sent via cookies. An attacker manages to intercept and use this session ID to gain unauthorized access to the user’s account. What type of attack does this represent?",
        options: [
            "Session Replay Attack",
            "Cross-Site Request Forgery (CSRF)",
            "Session Hijacking",
            "Cookie Poisoning"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "What is the key difference between session hijacking and session fixation attacks?",
        options: [
            "Session hijacking involves stealing session data, while session fixation involves setting a predefined session ID for a victim",
            "Session hijacking focuses on brute-forcing session IDs, while session fixation relies on cookies",
            "Session hijacking only targets HTTP sessions, whereas session fixation targets all protocols",
            "There is no difference; both are the same attack"
        ],
        answer: "Session hijacking involves stealing session data, while session fixation involves setting a predefined session ID for a victim"
    },
    {
        question: "Which of the following best describes a scenario in which session hijacking could occur during a TCP session?",
        options: [
            "An attacker intercepts an unencrypted HTTP session and modifies the requests sent between client and server",
            "An attacker steals the session ID from an encrypted HTTPS connection and uses it to access the user’s session",
            "An attacker attempts to change the server’s IP address to trick the client into sending session data",
            "An attacker replaces the session token with a forged token that expires immediately after use"
        ],
        answer: "An attacker steals the session ID from an encrypted HTTPS connection and uses it to access the user’s session"
    },
    {
        question: "You notice that an application does not use secure cookies for session management. This allows an attacker to intercept the session cookie and reuse it to access the application. What type of session hijacking is occurring?",
        options: [
            "Session Hijacking",
            "Session Fixation",
            "Cross-Site Scripting (XSS)",
            "Application-Level Session Hijacking"
        ],
        answer: "Application-Level Session Hijacking"
    },
    {
        question: "A user logs into a web application, but the session is stored without encryption. An attacker gains access to the user's session by exploiting the unencrypted session cookie. What type of vulnerability is this?",
        options: [
            "Cross-Site Request Forgery (CSRF)",
            "Application-Level Session Hijacking",
            "Session Fixation",
            "SQL Injection"
        ],
        answer: "Application-Level Session Hijacking"
    },
    {
        question: "Which of the following attacks is most likely to be used in a scenario where an attacker injects malicious JavaScript into a vulnerable web application to capture session cookies from users?",
        options: [
            "Cross-Site Scripting (XSS)",
            "Session Hijacking via MITM",
            "Session Fixation",
            "Denial of Service (DoS)"
        ],
        answer: "Cross-Site Scripting (XSS)"
    },
    {
        question: "An attacker exploits a web application that does not use HTTPS and intercepts session tokens sent over HTTP. The attacker uses this token to impersonate the user. What type of attack is being described?",
        options: [
            "Man-in-the-Middle Attack",
            "Application-Level Session Hijacking",
            "Session Fixation",
            "DNS Spoofing"
        ],
        answer: "Application-Level Session Hijacking"
    },
    {
        question: "While conducting a penetration test, you notice that an application lacks secure cookie flags, such as HttpOnly and Secure. How could this impact the application’s security regarding session management?",
        options: [
            "An attacker could perform a session fixation attack",
            "An attacker could steal session cookies through JavaScript or packet sniffing",
            "An attacker could bypass IP address validation on the session ID",
            "An attacker could trigger CSRF attacks without validation"
        ],
        answer: "An attacker could steal session cookies through JavaScript or packet sniffing"
    },
    {
        question: "In a network-level session hijacking attack, the attacker intercepts network traffic between a client and a server. Which of the following would be a key indicator that a network-level session hijacking is occurring?",
        options: [
            "An attacker intercepts traffic at the application layer and alters session tokens",
            "The session ID is being reused in subsequent requests, and the client is unaware",
            "The attacker gains access to the victim’s private encryption keys",
            "The attacker performs ARP spoofing to intercept unencrypted traffic"
        ],
        answer: "The attacker performs ARP spoofing to intercept unencrypted traffic"
    },
    {
        question: "A hacker is able to inject malicious packets into a TCP session between a client and a server using a technique called session hijacking. What is one key network vulnerability that this attack exploits?",
        options: [
            "Lack of encryption on the session data",
            "Weak session tokens",
            "TCP sequence number prediction",
            "Poor DNS configuration"
        ],
        answer: "TCP sequence number prediction"
    },
    {
        question: "You are conducting a penetration test on a network where an attacker is intercepting client-server communication using session hijacking techniques. The attacker performs a TCP session hijacking by injecting malicious packets. What method could be used to prevent this attack?",
        options: [
            "Implementing packet encryption with SSL/TLS",
            "Using a VPN to encrypt all client-server communications",
            "Disabling all HTTP requests during the test",
            "Changing the session token on every request"
        ],
        answer: "Implementing packet encryption with SSL/TLS"
    },
    {
        question: "A company’s internal application is vulnerable to network-level session hijacking. The attacker exploits the weak TCP sequence number and takes control of an active session. Which security measure would help protect against this vulnerability?",
        options: [
            "Use of SSL for encrypting all communications", 
            "Session token renewal on each request", 
            "TCP sequence number randomization", 
            "Use of an IDS/IPS system"
        ],
        answer: "TCP sequence number randomization"
    },
    {
        question: "In a man-in-the-middle attack, an attacker intercepts and modifies session data between two parties on an unencrypted connection. Which type of session hijacking is this attacker likely using?",
        options: [
            "Application-Level Hijacking", 
            "Network-Level Hijacking", 
            "Session Fixation", 
            "Cross-Site Scripting (XSS)"
        ],
        answer: "Network-Level Hijacking"
    },
    {
        question: "You are testing the security of a web application and want to perform session hijacking in a controlled environment. Which of the following tools would help you to capture and analyze session cookies from an HTTP response?",
        options: [
            "Burp Suite", 
            "Metasploit", 
            "Wireshark", 
            "Aircrack-ng"
        ],
        answer: "Burp Suite"
    },
    {
        question: "You are using a tool to sniff network traffic in order to capture session tokens during a penetration test. Which of the following tools would be most useful in this scenario?",
        options: [
            "Netcat", 
            "Ettercap", 
            "Wireshark", 
            "Nmap"
        ],
        answer: "Wireshark"
    },
    {
        question: "During a security test, you are using a tool to simulate a session hijacking attack. The tool you are using is capable of sending forged TCP packets to hijack an active session. What tool are you likely using?",
        options: [
            "Cain and Abel", 
            "Metasploit", 
            "Ettercap", 
            "Nessus"
        ],
        answer: "Cain and Abel"
    },
    {
        question: "Which of the following tools can help an attacker perform session hijacking by injecting malicious payloads into a target’s network traffic?",
        options: [
            "Nmap", 
            "Ettercap", 
            "Aircrack-ng", 
            "Burp Suite"
        ],
        answer: "Ettercap"
    },
    {
        question: "You are conducting a penetration test and need a tool to hijack a target’s session using session IDs. Which of the following tools would be the most effective for this purpose?",
        options: [
            "Cain and Abel", 
            "Wireshark", 
            "Burp Suite", 
            "John the Ripper"
        ],
        answer: "Cain and Abel"
    },
    {
        question: "To defend against session hijacking, a web application should ensure that session tokens are unique and difficult to guess. Which of the following countermeasures would best prevent an attacker from predicting valid session tokens?",
        options: [
            "Using strong encryption for session IDs", 
            "Limiting session duration", 
            "Rotating session tokens after each request", 
            "Requiring users to use multi-factor authentication"
        ],
        answer: "Using strong encryption for session IDs"
    },
    {
        question: "Your organization is implementing countermeasures to defend against session hijacking. Which of the following security measures would most effectively secure session tokens from being intercepted during transmission?",
        options: [
            "Enforcing the use of HTTP-only cookies for session management", 
            "Using SSL/TLS encryption for all communication", 
            "Implementing session token expiration policies", 
            "Disabling session timeouts on the application layer"
        ],
        answer: "Using SSL/TLS encryption for all communication"
    },
    {
        question: "Which countermeasure would help prevent session hijacking by ensuring that session tokens are not exposed in URL parameters, where they can be captured by an attacker?",
        options: [
            "Disabling cookies", 
            "Using POST requests instead of GET requests", 
            "Encrypting session tokens in URLs", 
            "Using IP and user-agent validation for session tokens"
        ],
        answer: "Using POST requests instead of GET requests"
    },
    {
        question: "Which of the following countermeasures would help protect against session hijacking by preventing session tokens from being reused by an attacker after they have been intercepted?",
        options: [
            "Implementing session token renewal after each request", 
            "Disabling HTTPS", 
            "Rotating session keys periodically", 
            "Requiring password resets every 30 minutes"
        ],
        answer: "Implementing session token renewal after each request"
    },
    {
        question: "Which of the following security measures would prevent session hijacking by ensuring that session tokens are not accessible to malicious JavaScript running on the client’s browser?",
        options: [
            "Setting the HttpOnly flag on session cookies", 
            "Enforcing IP-based session restrictions", 
            "Using multi-factor authentication for login", 
            "Disabling browser cookies for session management"
        ],
        answer: "Setting the HttpOnly flag on session cookies"
    },
    {
        question: "An attacker uses a technique where they intercept an ongoing session and take control of it by injecting malicious packets into the communication stream. Which type of attack is this?",
        options: [
            "Session Hijacking",
            "Denial of Service (DoS)",
            "Cross-Site Scripting (XSS)",
            "Session Fixation"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "Which of the following is a common method for session hijacking that involves intercepting a session token and using it to gain unauthorized access to the user's session?",
        options: [
            "Session Token Replay",
            "Session Fixation",
            "Session Cookie Theft",
            "Session Prediction"
        ],
        answer: "Session Cookie Theft"
    },
    {
        question: "When an attacker hijacks a user's session by predicting and injecting sequence numbers into an active TCP connection, which attack vector is being used?",
        options: [
            "TCP Session Hijacking",
            "Session Fixation",
            "Application Layer Hijacking",
            "Man-in-the-Middle Attack"
        ],
        answer: "TCP Session Hijacking"
    },
    {
        question: "An attacker steals the session token from a victim’s browser using a tool that performs packet sniffing on an unsecured Wi-Fi network. What is the attacker attempting to perform?",
        options: [
            "Cross-Site Request Forgery (CSRF)",
            "Session Hijacking",
            "SQL Injection",
            "DNS Spoofing"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "In a scenario where an attacker intercepts an HTTP request containing a session token, which type of attack could the attacker potentially use to impersonate the user?",
        options: [
            "Cross-Site Scripting (XSS)",
            "Session Hijacking",
            "Privilege Escalation",
            "DNS Spoofing"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "A web application uses session IDs to maintain user sessions but does not use any encryption for the session IDs transmitted in cookies. What is the main vulnerability here?",
        options: [
            "Session Fixation",
            "Application-Level Session Hijacking",
            "Cross-Site Request Forgery (CSRF)",
            "SQL Injection"
        ],
        answer: "Application-Level Session Hijacking"
    },
    {
        question: "A web developer notices that session IDs are passed in the URL and not encrypted. What type of attack could occur due to this practice?",
        options: [
            "Application-Level Session Hijacking",
            "Cross-Site Scripting (XSS)",
            "Session Fixation",
            "Remote File Inclusion (RFI)"
        ],
        answer: "Application-Level Session Hijacking"
    },
    {
        question: "What is one effective mitigation against application-level session hijacking where session IDs are leaked through URLs?",
        options: [
            "Enforcing the use of HTTPS and session cookies",
            "Increasing session ID length",
            "Disabling all user sessions after 30 minutes",
            "Using CAPTCHA for every request"
        ],
        answer: "Enforcing the use of HTTPS and session cookies"
    },
    {
        question: "An attacker injects malicious JavaScript into a vulnerable web page to capture the session cookie of a user. What attack is being performed?",
        options: [
            "Session Hijacking via XSS",
            "Session Fixation",
            "SQL Injection",
            "Buffer Overflow"
        ],
        answer: "Session Hijacking via XSS"
    },
    {
        question: "You are performing a security assessment and notice that an application’s session management system does not implement any form of session expiration. What is the primary risk in this scenario?",
        options: [
            "Session Hijacking",
            "Session Fixation",
            "SQL Injection",
            "Cross-Site Scripting (XSS)"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "During a penetration test, you observe that an attacker has managed to capture and inject malicious packets into an ongoing TCP session between a client and server. Which method was most likely used?",
        options: [
            "Session Hijacking via Packet Injection",
            "Session Fixation Attack",
            "Cross-Site Request Forgery (CSRF)",
            "Man-in-the-Middle Attack"
        ],
        answer: "Session Hijacking via Packet Injection"
    },
    {
        question: "A hacker intercepts and manipulates the TCP sequence numbers during an active session. Which network-level attack is this?",
        options: [
            "Session Hijacking via Sequence Number Prediction",
            "Session Fixation",
            "Man-in-the-Middle Attack",
            "ARP Spoofing"
        ],
        answer: "Session Hijacking via Sequence Number Prediction"
    },
    {
        question: "During an internal audit, you detect that certain sensitive sessions are being hijacked by an attacker performing ARP spoofing. What is the attacker trying to intercept?",
        options: [
            "Encrypted traffic",
            "Session tokens sent via HTTP",
            "TCP session sequence numbers",
            "Application passwords"
        ],
        answer: "Session tokens sent via HTTP"
    },
    {
        question: "You observe that an attacker has set up a rogue router to intercept and manipulate packets between clients and servers. This is likely an example of what attack?",
        options: [
            "Man-in-the-Middle Attack",
            "Session Hijacking",
            "Cross-Site Scripting (XSS)",
            "Session Fixation"
        ],
        answer: "Man-in-the-Middle Attack"
    },
    {
        question: "An attacker performs a TCP session hijacking attack by sending crafted TCP packets to guess the sequence numbers used in an active connection. What is the goal of this attack?",
        options: [
            "To capture login credentials",
            "To hijack the session and inject malicious data",
            "To redirect traffic to a malicious IP",
            "To cause a denial of service by flooding the target with packets"
        ],
        answer: "To hijack the session and inject malicious data"
    },
    {
        question: "Which of the following tools is designed to capture and analyze network traffic, which can then be used to hijack sessions by stealing session IDs?",
        options: [
            "Cain and Abel",
            "Burp Suite",
            "Wireshark",
            "Metasploit"
        ],
        answer: "Wireshark"
    },
    {
        question: "What tool would you use to capture and manipulate network traffic, including hijacking sessions on an unencrypted HTTP connection?",
        options: [
            "Nmap",
            "Ettercap",
            "John the Ripper",
            "Aircrack-ng"
        ],
        answer: "Ettercap"
    },
    {
        question: "You are conducting a penetration test and need to capture HTTP session cookies from an unencrypted connection. Which tool would be most useful for this task?",
        options: [
            "Netcat",
            "Wireshark",
            "Burp Suite",
            "Aircrack-ng"
        ],
        answer: "Wireshark"
    },
    {
        question: "During a penetration test, you are using a tool to hijack sessions by injecting malicious payloads into network traffic. What tool would be ideal for this purpose?",
        options: [
            "Metasploit",
            "Cain and Abel",
            "Nessus",
            "Ettercap"
        ],
        answer: "Cain and Abel"
    },
    {
        question: "Which of the following tools is commonly used to perform session hijacking via injecting malicious packets into active TCP sessions?",
        options: [
            "Wireshark",
            "Ettercap",
            "Burp Suite",
            "Metasploit"
        ],
        answer: "Ettercap"
    },
    {
        question: "You want to mitigate session hijacking by ensuring session tokens are not exposed to malicious JavaScript. Which countermeasure would help you achieve this?",
        options: [
            "Setting the HttpOnly flag on session cookies",
            "Implementing SSL/TLS for all communications",
            "Changing session IDs on every request",
            "Enabling session expiration after 10 minutes"
        ],
        answer: "Setting the HttpOnly flag on session cookies"
    },
    {
        question: "Which of the following measures would best protect against session hijacking by ensuring that session tokens are never exposed to the user’s browser?",
        options: [
            "Using SSL/TLS for all communications",
            "Disabling cookies for session management",
            "Using strong encryption algorithms for session tokens",
            "Using a secure VPN for all remote users"
        ],
        answer: "Using SSL/TLS for all communications"
    },
    {
        question: "To prevent session hijacking through session ID theft, what practice should be adopted by the application when generating session IDs?",
        options: [
            "Generating session IDs with strong randomness and entropy",
            "Validating session IDs through IP and User-Agent matching",
            "Encrypting session IDs with AES",
            "Storing session IDs in local storage"
        ],
        answer: "Generating session IDs with strong randomness and entropy"
    },
    {
        question: "Which of the following countermeasures would help mitigate session hijacking by ensuring that session tokens are regenerated frequently?",
        options: [
            "Implementing session token expiration",
            "Using multi-factor authentication",
            "Encrypting session tokens with SSL/TLS",
            "Regenerating session IDs after every request"
        ],
        answer: "Regenerating session IDs after every request"
    },
    {
        question: "To defend against session hijacking, which of the following techniques ensures that session tokens are not susceptible to interception over an insecure network?",
        options: [
            "Using SSL/TLS encryption for all communications",
            "Limiting session token length to reduce guessing",
            "Storing session tokens in local storage",
            "Validating session tokens with CAPTCHA"
        ],
        answer: "Using SSL/TLS encryption for all communications"
    },
    {
        question: "During a penetration test, you notice that an attacker is using a packet sniffing tool to intercept session tokens transmitted over HTTP. Which of the following tools would most likely be used for this purpose?",
        options: [
            "Wireshark",
            "Burp Suite",
            "John the Ripper",
            "Netcat"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which tool is designed specifically for intercepting and analyzing sessions and modifying requests on the fly during web application penetration tests?",
        options: [
            "Burp Suite",
            "Cain and Abel",
            "Ettercap",
            "Nessus"
        ],
        answer: "Burp Suite"
    },
    {
        question: "What is the primary purpose of Cain and Abel in relation to session hijacking?",
        options: [
            "To perform password cracking",
            "To capture and decode session tokens",
            "To intercept network traffic",
            "To analyze the source code of applications"
        ],
        answer: "To capture and decode session tokens"
    },
    {
        question: "During a penetration test, you notice that an attacker is using a packet sniffing tool to intercept session tokens transmitted over HTTP. Which of the following tools would most likely be used for this purpose?",
        options: [
            "Wireshark",
            "Burp Suite",
            "John the Ripper",
            "Netcat"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which tool is designed specifically for intercepting and analyzing sessions and modifying requests on the fly during web application penetration tests?",
        options: [
            "Burp Suite",
            "Cain and Abel",
            "Ettercap",
            "Nessus"
        ],
        answer: "Burp Suite"
    },
    {
        question: "What is the primary purpose of Cain and Abel in relation to session hijacking?",
        options: [
            "To perform password cracking",
            "To capture and decode session tokens",
            "To intercept network traffic",
            "To analyze the source code of applications"
        ],
        answer: "To capture and decode session tokens"
    },
    {
        question: "During a penetration test, you need to hijack a session by injecting malicious packets into the communication stream. Which of the following tools would be most effective?",
        options: [
            "Ettercap",
            "Burp Suite",
            "John the Ripper",
            "Wireshark"
        ],
        answer: "Ettercap"
    },
    {
        question: "Which of the following tools would allow an attacker to intercept session data and manipulate it during an active session on a network using MITM techniques?",
        options: [
            "Cain and Abel",
            "Wireshark",
            "Ettercap",
            "Nessus"
        ],
        answer: "Ettercap"
    },
    {
        question: "What tool can be used to monitor and intercept session data for both HTTP and HTTPS traffic in a penetration test scenario?",
        options: [
            "Wireshark",
            "Burp Suite",
            "Ettercap",
            "Nmap"
        ],
        answer: "Burp Suite"
    },
    {
        question: "What functionality does **Ettercap** provide to attackers during a session hijacking attempt?",
        options: [
            "Network sniffing",
            "Man-in-the-Middle (MITM) packet injection",
            "Password brute forcing",
            "Port scanning"
        ],
        answer: "Man-in-the-Middle (MITM) packet injection"
    },
    {
        question: "You are conducting a penetration test and need a tool to sniff the traffic on an unsecured wireless network to capture session tokens. Which tool is best suited for this task?",
        options: [
            "Wireshark",
            "Cain and Abel",
            "Metasploit",
            "John the Ripper"
        ],
        answer: "Wireshark"
    },
    {
        question: "What is the primary feature of Burp Suite when it comes to session hijacking?",
        options: [
            "Packet sniffing",
            "Request interception and manipulation",
            "Password cracking",
            "ARP spoofing"
        ],
        answer: "Request interception and manipulation"
    },
    {
        question: "During a security test, you need to capture session tokens and decrypt the communication between a client and server. Which tool should you use?",
        options: [
            "Cain and Abel",
            "Ettercap",
            "Wireshark",
            "Nessus"
        ],
        answer: "Wireshark"
    },
    {
        question: "In a penetration testing environment, which tool is commonly used to intercept and modify HTTP requests, including session tokens, between a client and server?",
        options: [
            "Wireshark",
            "Burp Suite",
            "Cain and Abel",
            "Nmap"
        ],
        answer: "Burp Suite"
    },
    {
        question: "An attacker intercepts session tokens transmitted over an insecure connection. Which tool would they most likely use to capture this session data?",
        options: [
            "Ettercap",
            "Cain and Abel",
            "Nessus",
            "Metasploit"
        ],
        answer: "Ettercap"
    },
    {
        question: "You are performing a session hijacking test using packet sniffing on an unencrypted HTTP connection. Which tool is capable of capturing the session token in transit?",
        options: [
            "Wireshark",
            "Burp Suite",
            "Cain and Abel",
            "Ettercap"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which tool allows an attacker to inject malicious packets into a TCP session for the purpose of session hijacking?",
        options: [
            "Cain and Abel",
            "Wireshark",
            "Ettercap",
            "Nessus"
        ],
        answer: "Ettercap"
    },
    {
        question: "Which of the following tools can be used to crack session tokens if they are weakly encrypted or hashed?",
        options: [
            "John the Ripper",
            "Cain and Abel",
            "Wireshark",
            "Metasploit"
        ],
        answer: "Cain and Abel"
    },
    {
        question: "When attempting to perform session hijacking on an unencrypted session, which tool would allow the attacker to capture and decode the session token?",
        options: [
            "Wireshark",
            "Burp Suite",
            "Ettercap",
            "Metasploit"
        ],
        answer: "Wireshark"
    },
    {
        question: "In a scenario where an attacker intercepts session tokens on an unencrypted wireless network, what tool would be appropriate for this task?",
        options: [
            "Cain and Abel",
            "Ettercap",
            "Wireshark",
            "Burp Suite"
        ],
        answer: "Wireshark"
    },
    {
        question: "What is the primary use of **Cain and Abel** in the context of session hijacking?",
        options: [
            "Cracking session tokens",
            "Injecting malicious packets into sessions",
            "Monitoring network traffic for session tokens",
            "Performing ARP spoofing"
        ],
        answer: "Cracking session tokens"
    },
    {
        question: "In a penetration test, what tool would you use to analyze network traffic for signs of session hijacking via packet sniffing?",
        options: [
            "Wireshark",
            "Burp Suite",
            "Cain and Abel",
            "Metasploit"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which tool would help you analyze session token encryption in a network session during a penetration test?",
        options: [
            "Burp Suite",
            "Cain and Abel",
            "Wireshark",
            "Nessus"
        ],
        answer: "Burp Suite"
    },
    {
        question: "During a penetration test, you observe that an application doesn’t use secure cookies or encryption for session tokens, and the session IDs are predictable. What kind of vulnerability is present?",
        options: [
            "Session Hijacking via Token Prediction",
            "Session Fixation",
            "Session Replay Attack",
            "Cross-Site Scripting (XSS)"
        ],
        answer: "Session Hijacking via Token Prediction"
    },
    {
        question: "A web application uses session tokens for authentication, but these tokens are exposed in URL parameters instead of in secure cookies. What risk does this expose the application to?",
        options: [
            "Session Hijacking",
            "Session Fixation",
            "Cross-Site Request Forgery (CSRF)",
            "Denial of Service (DoS)"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "You discover that an application performs weak validation of session tokens, allowing an attacker to manipulate the token values. What attack could this lead to?",
        options: [
            "Session Fixation",
            "Session Hijacking",
            "Cross-Site Scripting (XSS)",
            "SQL Injection"
        ],
        answer: "Session Fixation"
    },
    {
        question: "An attacker gains access to a session token by intercepting network traffic on an unsecured Wi-Fi network. What countermeasure could prevent this?",
        options: [
            "Session token encryption using SSL/TLS",
            "Regularly regenerating session tokens",
            "Limiting the number of allowed login attempts",
            "IP address whitelisting"
        ],
        answer: "Session token encryption using SSL/TLS"
    },
    {
        question: "A company implements session token rotation, regenerating the session ID after each request to minimize session hijacking. What security benefit does this provide?",
        options: [
            "Prevents session hijacking by eliminating stale session tokens",
            "Ensures sessions expire after a fixed period",
            "Improves performance by reducing network latency",
            "Blocks brute-force attacks on session tokens"
        ],
        answer: "Prevents session hijacking by eliminating stale session tokens"
    },
    {
        question: "Which of the following tools can be used to simulate a **Man-in-the-Middle (MITM)** attack to intercept and manipulate session tokens in real-time?",
        options: [
            "Wireshark",
            "Ettercap",
            "Cain and Abel",
            "Metasploit"
        ],
        answer: "Ettercap"
    },
    {
        question: "An attacker attempts to hijack a session by forcing a victim to login with a predetermined session ID. What is this attack called?",
        options: [
            "Session Fixation",
            "Session Hijacking",
            "Cross-Site Request Forgery",
            "Session Replay"
        ],
        answer: "Session Fixation"
    },
    {
        question: "You are reviewing an application where session tokens are stored in the browser's local storage instead of cookies. What risk does this introduce?",
        options: [
            "Cross-Site Scripting (XSS) leading to session hijacking",
            "Session Token Prediction",
            "Session Fixation",
            "Buffer Overflow"
        ],
        answer: "Cross-Site Scripting (XSS) leading to session hijacking"
    },
    {
        question: "You have identified that an attacker is using a tool like **Cain and Abel** to intercept session tokens during an active session. What technique is likely being used to perform this attack?",
        options: [
            "Session Hijacking via Packet Sniffing",
            "Session Fixation",
            "Session Token Prediction",
            "Cross-Site Request Forgery (CSRF)"
        ],
        answer: "Session Hijacking via Packet Sniffing"
    },
    {
        question: "Which of the following would prevent session hijacking when using **SSL/TLS** to secure communications between a client and a server?",
        options: [
            "Validating the client’s certificate during the session",
            "Preventing session token exposure through cookies",
            "Encrypting session tokens in transit",
            "Limiting session tokens to single-use"
        ],
        answer: "Encrypting session tokens in transit"
    },
    {
        question: "An attacker is trying to hijack a session by injecting malicious TCP packets that manipulate sequence numbers during an active connection. Which attack type is being used?",
        options: [
            "TCP Session Hijacking",
            "Session Token Prediction",
            "Session Fixation",
            "Cross-Site Request Forgery (CSRF)"
        ],
        answer: "TCP Session Hijacking"
    },
    {
        question: "Which of the following is **not** a recommended countermeasure to prevent session hijacking?",
        options: [
            "Encrypting session tokens using SSL",
            "Validating session tokens with an IP address check",
            "Using predictable session IDs for easier recovery",
            "Regenerating session IDs after every login"
        ],
        answer: "Using predictable session IDs for easier recovery"
    },
    {
        question: "An attacker intercepts session tokens over an unsecured network and uses it to impersonate a legitimate user. What kind of attack is this?",
        options: [
            "Session Hijacking",
            "Session Fixation",
            "Cross-Site Scripting (XSS)",
            "Denial of Service (DoS)"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "During a penetration test, you discover that a web application doesn’t use the `HttpOnly` flag for cookies that store session tokens. What risk does this expose?",
        options: [
            "Cross-Site Scripting (XSS) leading to session hijacking",
            "Session Token Prediction",
            "Man-in-the-Middle Attack",
            "SQL Injection"
        ],
        answer: "Cross-Site Scripting (XSS) leading to session hijacking"
    },
    {
        question: "You are testing an application that does not regenerate session IDs after login. What type of attack is this vulnerable to?",
        options: [
            "Session Fixation",
            "Session Hijacking",
            "Cross-Site Request Forgery (CSRF)",
            "Session Token Prediction"
        ],
        answer: "Session Fixation"
    },
    {
        question: "An attacker is using a packet-sniffing tool to capture session tokens that are transmitted in an HTTP request. Which attack vector are they attempting to exploit?",
        options: [
            "Network-Level Session Hijacking",
            "Application-Level Session Hijacking",
            "Session Token Prediction",
            "Man-in-the-Middle Attack"
        ],
        answer: "Network-Level Session Hijacking"
    },
    {
        question: "You observe that an application generates predictable session IDs based on the current timestamp. What is the risk with this implementation?",
        options: [
            "Session Hijacking via Token Prediction",
            "Session Fixation",
            "Cross-Site Scripting (XSS)",
            "Buffer Overflow"
        ],
        answer: "Session Hijacking via Token Prediction"
    },
    {
        question: "When performing a **Man-in-the-Middle** attack, an attacker intercepts and manipulates session tokens during the transmission between the client and server. Which tool would you use to accomplish this?",
        options: [
            "Ettercap",
            "Wireshark",
            "Cain and Abel",
            "Metasploit"
        ],
        answer: "Ettercap"
    },
    {
        question: "Which of the following best practices helps protect session tokens from being hijacked via JavaScript?",
        options: [
            "Storing session tokens in `localStorage`",
            "Setting the `HttpOnly` flag on session cookies",
            "Sending session tokens in URL parameters",
            "Allowing session tokens to persist indefinitely"
        ],
        answer: "Setting the `HttpOnly` flag on session cookies"
    },
    {
        question: "You are investigating an incident where an attacker hijacked a user’s session by predicting the session ID. Which technique should you suggest as a solution?",
        options: [
            "Regenerate session IDs after each login",
            "Encrypt session tokens with SSL/TLS",
            "Use an unpredictable session token generation algorithm",
            "Set session expiration time to 5 minutes"
        ],
        answer: "Use an unpredictable session token generation algorithm"
    },
    {
        question: "An attacker manages to predict the session token and hijacks a victim’s session. What kind of vulnerability does this suggest about the session token generation?",
        options: [
            "Predictable session token generation",
            "Weak SSL/TLS implementation",
            "Session Fixation",
            "Unvalidated session cookie"
        ],
        answer: "Predictable session token generation"
    },
    {
        question: "While performing a penetration test, you find that an application allows session IDs to be sent in URL parameters. What security risk does this pose?",
        options: [
            "Session Hijacking via URL sniffing",
            "Session Fixation",
            "Cross-Site Request Forgery",
            "Cross-Site Scripting (XSS)"
        ],
        answer: "Session Hijacking via URL sniffing"
    },
    {
        question: "You need to defend against session hijacking. What would you implement to ensure that session tokens are never exposed to malicious scripts on the client side?",
        options: [
            "Set `HttpOnly` and `Secure` flags on cookies",
            "Ensure session tokens are stored in localStorage",
            "Use short session timeouts",
            "Enforce IP address validation"
        ],
        answer: "Set `HttpOnly` and `Secure` flags on cookies"
    },
    {
        question: "Which of the following methods would reduce the risk of session hijacking when users are connected over public Wi-Fi networks?",
        options: [
            "Session token encryption",
            "Multi-Factor Authentication (MFA)",
            "Using HTTP only for session token transmission",
            "VPN for network access"
        ],
        answer: "VPN for network access"
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
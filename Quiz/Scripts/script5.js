
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        question: "What type of scan focuses on identifying open ports and services running on a network device?",
        options: [
            "Vulnerability Scan",
            "Port Scan",
            "Compliance Scan",
            "Configuration Scan"
        ],
        answer: "Port Scan"
    },
    {
        question: "Which of the following vulnerabilities can be mitigated by employing a Content Security Policy (CSP)?",
        options: [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Remote Code Execution",
            "Denial of Service (DoS)"
        ],
        answer: "Cross-Site Scripting (XSS)"
    },
    {
        question: "A vulnerability assessment reveals that a server is exposing sensitive information through error messages. This is an example of:",
        options: [
            "Information Leakage",
            "Configuration Weakness",
            "Access Control Failure",
            "Misconfigured Security Headers"
        ],
        answer: "Information Leakage"
    },
    {
        question: "Which of the following best describes a 'compliance vulnerability'?",
        options: [
            "A flaw that can be exploited for unauthorized access",
            "A failure to meet regulatory or policy standards",
            "An outdated software version",
            "A vulnerability with a known exploit"
        ],
        answer: "A failure to meet regulatory or policy standards"
    },
    {
        question: "What is the purpose of a 'vulnerability management program'?",
        options: [
            "To conduct regular training for employees",
            "To systematically identify, classify, and remediate vulnerabilities",
            "To perform regular penetration tests",
            "To manage user access rights"
        ],
        answer: "To systematically identify, classify, and remediate vulnerabilities"
    },
    {
        question: "A vulnerability assessment identifies a system running outdated software. What is the best initial action to take?",
        options: [
            "Conduct a penetration test",
            "Immediately patch the software",
            "Document the finding for the next audit",
            "Schedule a meeting with IT staff"
        ],
        answer: "Immediately patch the software"
    },
    {
        question: "What kind of vulnerability is created when user input is improperly sanitized, allowing harmful data to be processed?",
        options: [
            "Injection Vulnerability",
            "Access Control Vulnerability",
            "Misconfiguration Vulnerability",
            "Authentication Vulnerability"
        ],
        answer: "Injection Vulnerability"
    },
    {
        question: "Which of the following is a common feature of a vulnerability scanner?",
        options: [
            "Intrusion Detection",
            "Patch Management",
            "Reporting and Documentation",
            "User Training"
        ],
        answer: "Reporting and Documentation"
    },
    {
        question: "Which of the following represents a key benefit of regular vulnerability assessments?",
        options: [
            "Increased system performance",
            "Better employee satisfaction",
            "Early detection of security weaknesses",
            "Improved hardware inventory"
        ],
        answer: "Early detection of security weaknesses"
    },
    {
        question: "When conducting a vulnerability assessment, what does the term 'false positive' refer to?",
        options: [
            "A vulnerability that exists but is not detected",
            "A non-existent vulnerability reported as a finding",
            "A true vulnerability that cannot be exploited",
            "A critical vulnerability that is overlooked"
        ],
        answer: "A non-existent vulnerability reported as a finding"
    },
    {
        question: "In which phase of the vulnerability management lifecycle is risk prioritization conducted?",
        options: [
            "Discovery",
            "Assessment",
            "Remediation",
            "Reporting"
        ],
        answer: "Assessment"
    },
    {
        question: "What type of testing involves simulating real-world attacks on systems to identify vulnerabilities?",
        options: [
            "Vulnerability Scanning",
            "Penetration Testing",
            "Compliance Testing",
            "Static Code Analysis"
        ],
        answer: "Penetration Testing"
    },
    {
        question: "Which of the following vulnerabilities is typically associated with buffer overflow attacks?",
        options: [
            "Input Validation Vulnerability",
            "Memory Corruption Vulnerability",
            "Access Control Vulnerability",
            "Code Injection Vulnerability"
        ],
        answer: "Memory Corruption Vulnerability"
    },
    {
        question: "What does CVSS stand for in the context of vulnerability assessment?",
        options: [
            "Common Vulnerability Scoring System",
            "Critical Vulnerability Security Standard",
            "Comprehensive Vulnerability Scanning System",
            "Common Vulnerability Security System"
        ],
        answer: "Common Vulnerability Scoring System"
    },
    {
        question: "Which of the following describes the purpose of a threat model in vulnerability analysis?",
        options: [
            "To define security policies",
            "To outline vulnerability remediation steps",
            "To identify and prioritize potential threats",
            "To perform compliance audits"
        ],
        answer: "To identify and prioritize potential threats"
    },
    {
        question: "What is the main goal of a penetration test compared to a vulnerability assessment?",
        options: [
            "To identify all vulnerabilities",
            "To exploit vulnerabilities",
            "To document compliance",
            "To train staff"
        ],
        answer: "To exploit vulnerabilities"
    },
    {
        question: "Which type of tool is designed to analyze code for vulnerabilities without executing it?",
        options: [
            "Static Analysis Tool",
            "Dynamic Analysis Tool",
            "Fuzzing Tool",
            "Network Scanner"
        ],
        answer: "Static Analysis Tool"
    },
    {
        question: "In a vulnerability management program, what does 'remediation' involve?",
        options: [
            "Identifying vulnerabilities",
            "Documenting vulnerabilities",
            "Implementing fixes for vulnerabilities",
            "Educating employees about security"
        ],
        answer: "Implementing fixes for vulnerabilities"
    },
    {
        question: "A vulnerability assessment reveals that an organization's software is using outdated libraries. This presents a risk known as:",
        options: [
            "Technical Debt",
            "Legacy Software Risk",
            "Compliance Risk",
            "Operational Risk"
        ],
        answer: "Technical Debt"
    },
    {
        question: "What type of vulnerability is often mitigated through regular security awareness training for employees?",
        options: [
            "Technical Vulnerability",
            "Social Engineering Vulnerability",
            "Configuration Vulnerability",
            "Network Vulnerability"
        ],
        answer: "Social Engineering Vulnerability"
    },
    {
        question: "Which of the following is a primary function of a vulnerability management tool?",
        options: [
            "Encrypt sensitive data",
            "Detect and remediate vulnerabilities",
            "Monitor user activity",
            "Configure firewalls"
        ],
        answer: "Detect and remediate vulnerabilities"
    },
    {
        question: "An organization utilizes a risk matrix to assess the severity of vulnerabilities. What is the primary purpose of this matrix?",
        options: [
            "To determine the cost of remediation",
            "To prioritize vulnerabilities based on risk level",
            "To document compliance requirements",
            "To outline security policies"
        ],
        answer: "To prioritize vulnerabilities based on risk level"
    },
    {
        question: "What is the potential risk of not updating software regularly in relation to vulnerabilities?",
        options: [
            "Increased user productivity",
            "Improved system performance",
            "Exploitation of known vulnerabilities",
            "Compliance with regulations"
        ],
        answer: "Exploitation of known vulnerabilities"
    },
    {
        question: "Which vulnerability can be mitigated by ensuring proper session management practices?",
        options: [
            "Cross-Site Scripting (XSS)",
            "Session Hijacking",
            "SQL Injection",
            "Denial of Service (DoS)"
        ],
        answer: "Session Hijacking"
    },
    {
        question: "A company is evaluating third-party software for vulnerabilities before integration. This process is known as:",
        options: [
            "Supply Chain Risk Assessment",
            "Vendor Assessment",
            "Security Audit",
            "Compliance Check"
        ],
        answer: "Supply Chain Risk Assessment"
    },
    {
        question: "Which regulatory framework emphasizes continuous risk assessment and vulnerability management?",
        options: [
            "PCI DSS",
            "HIPAA",
            "NIST Cybersecurity Framework",
            "ISO 27001"
        ],
        answer: "NIST Cybersecurity Framework"
    },
    {
        question: "What type of vulnerability is associated with improperly configured security controls?",
        options: [
            "Configuration Vulnerability",
            "Operational Vulnerability",
            "Data Leakage Vulnerability",
            "Access Control Vulnerability"
        ],
        answer: "Configuration Vulnerability"
    },
    {
        question: "What is the role of 'penetration testing' in a comprehensive vulnerability management program?",
        options: [
            "To perform routine scans",
            "To exploit identified vulnerabilities",
            "To conduct employee training",
            "To monitor network traffic"
        ],
        answer: "To exploit identified vulnerabilities"
    },
    {
        question: "Which of the following vulnerabilities is particularly concerning for web applications that allow file uploads?",
        options: [
            "Directory Traversal",
            "Cross-Site Request Forgery (CSRF)",
            "Code Injection",
            "Command Injection"
        ],
        answer: "Directory Traversal"
    },
    {
        question: "During a vulnerability assessment, which type of vulnerability is identified by excessive permissions granted to user accounts?",
        options: [
            "Privilege Escalation",
            "Access Control Vulnerability",
            "Configuration Vulnerability",
            "Input Validation Vulnerability"
        ],
        answer: "Access Control Vulnerability"
    },
    {
        question: "A company performs a vulnerability assessment and finds a missing security update on a critical application. What is the most appropriate remediation step?",
        options: [
            "Document the finding",
            "Report it to upper management",
            "Patch the application immediately",
            "Schedule it for the next quarterly review"
        ],
        answer: "Patch the application immediately"
    },
    {
        question: "What is the primary focus of a risk assessment in relation to vulnerability management?",
        options: [
            "Identifying all known vulnerabilities",
            "Analyzing the impact and likelihood of potential threats",
            "Implementing security controls",
            "Conducting penetration tests"
        ],
        answer: "Analyzing the impact and likelihood of potential threats"
    },
    {
        question: "Which of the following vulnerability scanning techniques is most likely to identify zero-day vulnerabilities?",
        options: [
            "Signature-Based Scanning",
            "Anomaly-Based Scanning",
            "Behavior-Based Scanning",
            "Configuration Scanning"
        ],
        answer: "Anomaly-Based Scanning"
    },
    {
        question: "In a vulnerability assessment, what does the term 'remediation' refer to?",
        options: [
            "Identifying vulnerabilities",
            "Documenting security policies",
            "Implementing fixes for vulnerabilities",
            "Conducting user training"
        ],
        answer: "Implementing fixes for vulnerabilities"
    },
    {
        question: "Which component of vulnerability management helps prioritize vulnerabilities based on their potential impact?",
        options: [
            "Risk Assessment",
            "Threat Intelligence",
            "Remediation Plan",
            "Security Policy"
        ],
        answer: "Risk Assessment"
    },
    {
        question: "An organization is conducting a penetration test that simulates insider threats. This test is an example of:",
        options: [
            "Black Box Testing",
            "White Box Testing",
            "Gray Box Testing",
            "Social Engineering Testing"
        ],
        answer: "Gray Box Testing"
    },
    {
        question: "During a vulnerability assessment, Max discovers that certain endpoints have default passwords. What type of risk does this represent?",
        options: [
            "Configuration Risk",
            "Operational Risk",
            "Access Control Risk",
            "Compliance Risk"
        ],
        answer: "Access Control Risk"
    },
    {
        question: "What is the role of a vulnerability management policy in an organization?",
        options: [
            "To define the process for identifying and mitigating vulnerabilities",
            "To dictate user access levels",
            "To outline incident response procedures",
            "To manage compliance requirements"
        ],
        answer: "To define the process for identifying and mitigating vulnerabilities"
    },
    {
        question: "Which type of vulnerability is commonly associated with insufficient input validation in web applications?",
        options: [
            "Cross-Site Request Forgery (CSRF)",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Buffer Overflow"
        ],
        answer: "SQL Injection"
    },
    {
        question: "An automated tool provides alerts about new vulnerabilities as they are published. What type of tool is this?",
        options: [
            "Vulnerability Scanner",
            "Patch Management Tool",
            "Threat Intelligence Platform",
            "Configuration Management Tool"
        ],
        answer: "Threat Intelligence Platform"
    },
    {
        question: "During a vulnerability assessment, a tool scans for software versions known to have vulnerabilities. This technique is known as:",
        options: [
            "Fingerprinting",
            "Version Checking",
            "Fuzzing",
            "Exploit Development"
        ],
        answer: "Version Checking"
    },
    {
        question: "Which framework is widely used for vulnerability management and risk assessment?",
        options: [
            "NIST SP 800-53",
            "CIS Controls",
            "ISO 27001",
            "OWASP Top Ten"
        ],
        answer: "NIST SP 800-53"
    },
    {
        question: "What does the term 'attack vector' refer to in the context of vulnerability analysis?",
        options: [
            "The method used by an attacker to exploit a vulnerability",
            "The number of vulnerabilities in a system",
            "The severity of a vulnerability",
            "The process of scanning for vulnerabilities"
        ],
        answer: "The method used by an attacker to exploit a vulnerability"
    },
    {
        question: "Which of the following is a method for evaluating the effectiveness of security controls in relation to vulnerabilities?",
        options: [
            "Vulnerability Scanning",
            "Penetration Testing",
            "Security Auditing",
            "Network Monitoring"
        ],
        answer: "Penetration Testing"
    },
    {
        question: "An organization has a vulnerability management program that includes regular training for staff on recognizing potential threats. What is this type of measure called?",
        options: [
            "Preventive Control",
            "Detective Control",
            "Corrective Control",
            "Compensatory Control"
        ],
        answer: "Preventive Control"
    },
    {
        question: "In vulnerability assessments, the 'criticality' of a vulnerability typically refers to:",
        options: [
            "The ease of exploitation",
            "The likelihood of being exploited",
            "The potential impact on the organization",
            "The number of affected systems"
        ],
        answer: "The potential impact on the organization"
    },
    {
        question: "During a vulnerability assessment, Max discovers that an application is vulnerable to Cross-Site Scripting (XSS). What type of remediation should be implemented?",
        options: [
            "Implement input validation and output encoding",
            "Remove the application from the server",
            "Change user passwords",
            "Increase the server's security settings"
        ],
        answer: "Implement input validation and output encoding"
    },
    {
        question: "Which of the following tools is commonly used for static application security testing (SAST)?",
        options: [
            "Burp Suite",
            "Nessus",
            "Fortify",
            "Wireshark"
        ],
        answer: "Fortify"
    },
    {
        question: "What is the main purpose of conducting a vulnerability assessment before implementing new technology?",
        options: [
            "To evaluate compliance with regulations",
            "To ensure security is integrated from the start",
            "To determine cost-effectiveness",
            "To assess user training needs"
        ],
        answer: "To ensure security is integrated from the start"
    },
    {
        question: "In vulnerability management, which document outlines the procedures for handling vulnerabilities?",
        options: [
            "Incident Response Plan",
            "Vulnerability Management Policy",
            "Security Awareness Training Manual",
            "Disaster Recovery Plan"
        ],
        answer: "Vulnerability Management Policy"
    },
    {
        question: "Which term describes a security vulnerability that remains unpatched and can be exploited by attackers?",
        options: [
            "Open Vulnerability",
            "Zero-Day Vulnerability",
            "Critical Vulnerability",
            "Exploit Kit"
        ],
        answer: "Open Vulnerability"
    },
    {
        question: "Which of the following techniques is NOT typically used during a vulnerability assessment?",
        options: [
            "Social Engineering",
            "Port Scanning",
            "Network Sniffing",
            "Code Review"
        ],
        answer: "Social Engineering"
    },
    {
        question: "An organization assesses its third-party vendors for potential vulnerabilities. This process is known as:",
        options: [
            "Supply Chain Risk Management",
            "Third-Party Risk Assessment",
            "Vendor Assessment",
            "Compliance Auditing"
        ],
        answer: "Third-Party Risk Assessment"
    },
    {
        question: "A company implements an automated vulnerability scanner to detect missing patches. This is an example of:",
        options: [
            "Active Monitoring",
            "Continuous Assessment",
            "Scheduled Scanning",
            "Static Analysis"
        ],
        answer: "Continuous Assessment"
    },
    {
        question: "Which of the following represents the FIRST step in a vulnerability management lifecycle?",
        options: [
            "Discovery",
            "Remediation",
            "Assessment",
            "Reporting"
        ],
        answer: "Discovery"
    },
    {
        question: "A vulnerability assessment tool identifies multiple systems with weak passwords. This type of finding is classified as a:",
        options: [
            "User Management Vulnerability",
            "Configuration Vulnerability",
            "Access Control Vulnerability",
            "Compliance Vulnerability"
        ],
        answer: "Access Control Vulnerability"
    },
    {
        question: "Which type of analysis is performed to evaluate how changes in the environment can impact existing vulnerabilities?",
        options: [
            "Impact Analysis",
            "Risk Assessment",
            "Change Management",
            "Vulnerability Assessment"
        ],
        answer: "Impact Analysis"
    },
    {
        question: "During a vulnerability assessment, which action is appropriate when a critical vulnerability is identified?",
        options: [
            "Document the finding for future reference",
            "Notify relevant stakeholders for immediate action",
            "Ignore it if it is an isolated case",
            "Conduct a deeper analysis later"
        ],
        answer: "Notify relevant stakeholders for immediate action"
    },
    {
        question: "What type of vulnerability is identified when software is outdated and not receiving security patches?",
        options: [
            "Configuration Vulnerability",
            "Compliance Vulnerability",
            "Software Vulnerability",
            "Operational Vulnerability"
        ],
        answer: "Compliance Vulnerability"
    },
    {
        question: "Which of the following is a potential consequence of failing to address known vulnerabilities in an organization?",
        options: [
            "Increased employee morale",
            "Decreased security incidents",
            "Regulatory penalties and fines",
            "Improved compliance posture"
        ],
        answer: "Regulatory penalties and fines"
    },
    {
        question: "Emma is using a vulnerability scanner that provides detailed reports on identified vulnerabilities, including suggested remediation steps. This type of report is known as:",
        options: [
            "Technical Report",
            "Executive Summary",
            "Remediation Plan",
            "Compliance Report"
        ],
        answer: "Technical Report"
    },
    {
        question: "A network administrator uses a tool that performs 'banner grabbing' to identify the version of services running on their servers. This process is primarily used to:",
        options: [
            "Enumerate user accounts",
            "Identify potential vulnerabilities",
            "Gather network traffic data",
            "Securely configure services"
        ],
        answer: "Identify potential vulnerabilities"
    },
    {
        question: "Which type of vulnerability assessment focuses on the security of mobile applications?",
        options: [
            "Network Assessment",
            "Web Application Assessment",
            "Mobile Application Assessment",
            "Cloud Security Assessment"
        ],
        answer: "Mobile Application Assessment"
    },
    {
        question: "A security analyst notices that the vulnerability scanning tool reports several vulnerabilities as 'remediated' despite not being patched. What is the most likely explanation?",
        options: [
            "The tool is malfunctioning.",
            "There was a successful attack exploiting the vulnerabilities.",
            "The vulnerabilities were falsely reported as fixed.",
            "The analyst missed the patches."
        ],
        answer: "The vulnerabilities were falsely reported as fixed."
    },
    {
        question: "A vulnerability assessment identifies that certain services are running with excessive permissions. What type of risk does this represent?",
        options: [
            "Misconfiguration Risk",
            "Access Control Risk",
            "Operational Risk",
            "Compliance Risk"
        ],
        answer: "Access Control Risk"
    },
    {
        question: "Which of the following is a common technique used by vulnerability scanners to determine the security posture of a system?",
        options: [
            "Fuzzing",
            "Social Engineering",
            "Port Scanning",
            "Phishing"
        ],
        answer: "Port Scanning"
    },
    {
        question: "A company implements a vulnerability management program that includes regular updates and patches. This practice is known as:",
        options: [
            "Security Hardening",
            "Configuration Management",
            "Patch Management",
            "Risk Mitigation"
        ],
        answer: "Patch Management"
    },
    {
        question: "What does the term 'attack surface' refer to in the context of vulnerability analysis?",
        options: [
            "The total number of vulnerabilities",
            "The number of entry points for potential attacks",
            "The methods used to exploit vulnerabilities",
            "The total risk assessment score"
        ],
        answer: "The number of entry points for potential attacks"
    },
    {
        question: "In vulnerability assessment, what does 'exploitation' mean?",
        options: [
            "Finding vulnerabilities",
            "Taking advantage of vulnerabilities to compromise systems",
            "Documenting vulnerabilities",
            "Fixing vulnerabilities"
        ],
        answer: "Taking advantage of vulnerabilities to compromise systems"
    },
    {
        question: "Which vulnerability assessment approach involves both automated and manual testing to ensure thorough coverage?",
        options: [
            "Continuous Testing",
            "Automated Assessment",
            "Hybrid Assessment",
            "Static Analysis"
        ],
        answer: "Hybrid Assessment"
    },
    {
        question: "A report indicates that a system is vulnerable to a particular type of SQL injection. What should the next step be?",
        options: [
            "Document the finding and move on",
            "Immediately exploit the vulnerability",
            "Implement a patch or remediation strategy",
            "Conduct a follow-up vulnerability assessment"
        ],
        answer: "Implement a patch or remediation strategy"
    },
    {
        question: "What is the primary focus of a compliance-driven vulnerability assessment?",
        options: [
            "Identifying all possible vulnerabilities",
            "Meeting specific regulatory or legal requirements",
            "Performing penetration testing",
            "Assessing network performance"
        ],
        answer: "Meeting specific regulatory or legal requirements"
    },
    {
        question: "During a vulnerability assessment, a tool reports multiple instances of 'default credentials' across systems. This is an example of:",
        options: [
            "Configuration Vulnerability",
            "Access Control Vulnerability",
            "User Management Vulnerability",
            "Data Protection Vulnerability"
        ],
        answer: "Configuration Vulnerability"
    },
    {
        question: "Which of the following tools is commonly used for web application vulnerability scanning?",
        options: [
            "Wireshark",
            "Nmap",
            "Burp Suite",
            "Metasploit"
        ],
        answer: "Burp Suite"
    },
    {
        question: "A company wants to evaluate its security posture and decides to engage in a 'red team' exercise. What is the primary goal of this exercise?",
        options: [
            "To train employees on security policies",
            "To simulate real-world attack scenarios",
            "To develop security documentation",
            "To conduct vulnerability scanning"
        ],
        answer: "To simulate real-world attack scenarios"
    },
    {
        question: "What is the primary purpose of vulnerability patch management?",
        options: [
            "To identify all vulnerabilities",
            "To ensure systems are compliant with regulations",
            "To mitigate the risk of vulnerabilities being exploited",
            "To improve system performance"
        ],
        answer: "To mitigate the risk of vulnerabilities being exploited"
    },
    {
        question: "A vulnerability assessment indicates that a firewall is misconfigured, allowing traffic on prohibited ports. This is an example of:",
        options: [
            "Network Vulnerability",
            "Configuration Vulnerability",
            "Access Control Vulnerability",
            "Data Leakage Vulnerability"
        ],
        answer: "Configuration Vulnerability"
    },
    {
        question: "In vulnerability assessments, which of the following is essential for ensuring accurate results?",
        options: [
            "Outdated tools",
            "Regular updates and maintenance of scanning tools",
            "Ignoring false positives",
            "Reducing scan frequency"
        ],
        answer: "Regular updates and maintenance of scanning tools"
    },
    {
        question: "Which of the following describes a 'false negative' in the context of vulnerability scanning?",
        options: [
            "A vulnerability that is not detected when it exists",
            "A non-existent vulnerability reported as an issue",
            "An accurate report of a vulnerability",
            "A vulnerability that cannot be exploited"
        ],
        answer: "A vulnerability that is not detected when it exists"
    },
    {
        question: "What type of vulnerability assessment is performed to identify vulnerabilities in third-party applications and services?",
        options: [
            "Internal Assessment",
            "External Assessment",
            "Third-Party Risk Assessment",
            "Compliance Assessment"
        ],
        answer: "Third-Party Risk Assessment"
    },
    {
        question: "Which framework is commonly used for managing vulnerabilities in an organization?",
        options: [
            "ISO 27001",
            "NIST Cybersecurity Framework",
            "CIS Controls",
            "OWASP Top Ten"
        ],
        answer: "NIST Cybersecurity Framework"
    },
    {
        question: "An organization regularly updates its vulnerability management policies to align with industry best practices. This process is known as:",
        options: [
            "Continuous Improvement",
            "Risk Management",
            "Compliance Auditing",
            "Penetration Testing"
        ],
        answer: "Continuous Improvement"
    },
    {
        question: "What type of report typically summarizes the findings of a vulnerability assessment and provides strategic recommendations for remediation?",
        options: [
            "Technical Report",
            "Executive Summary",
            "Remediation Plan",
            "Compliance Report"
        ],
        answer: "Executive Summary"
    },
    {
        question: "Which of the following describes the role of threat intelligence in vulnerability management?",
        options: [
            "It helps to identify the number of vulnerabilities present.",
            "It provides context on the likelihood of vulnerabilities being exploited.",
            "It eliminates the need for vulnerability assessments.",
            "It automates the patch management process."
        ],
        answer: "It provides context on the likelihood of vulnerabilities being exploited."
    },
    {
        question: "A company’s vulnerability assessment indicates that several web applications are running outdated software. What should be the first priority?",
        options: [
            "Conduct penetration tests on all applications",
            "Update all applications to the latest versions",
            "Document the vulnerabilities for future reference",
            "Inform users about potential risks"
        ],
        answer: "Update all applications to the latest versions"
    },
    {
        question: "In the context of vulnerability assessments, what does the term 'scope creep' refer to?",
        options: [
            "The expansion of project boundaries without proper approval",
            "A gradual increase in vulnerabilities over time",
            "The process of continuous assessment",
            "An increase in security awareness"
        ],
        answer: "The expansion of project boundaries without proper approval"
    },
    {
        question: "What is the primary goal of threat modeling during vulnerability assessments?",
        options: [
            "To identify assets and their vulnerabilities",
            "To develop security policies",
            "To create awareness among employees",
            "To prioritize remediation efforts"
        ],
        answer: "To identify assets and their vulnerabilities"
    },
    {
        question: "Which type of assessment would best identify vulnerabilities in a cloud-based application?",
        options: [
            "Network Assessment",
            "Cloud Security Assessment",
            "Web Application Assessment",
            "Internal Assessment"
        ],
        answer: "Cloud Security Assessment"
    },
    {
        question: "Which of the following vulnerabilities is most likely to be reported by a vulnerability scanner when evaluating outdated software?",
        options: [
            "Cross-Site Scripting (XSS)",
            "Buffer Overflow",
            "SQL Injection",
            "Missing Security Patches"
        ],
        answer: "Missing Security Patches"
    },
    {
        question: "A company is implementing a continuous vulnerability management program. Which of the following activities should be included?",
        options: [
            "Annual penetration testing only",
            "Monthly vulnerability assessments and patching",
            "Only scanning for compliance",
            "Ignoring findings from previous assessments"
        ],
        answer: "Monthly vulnerability assessments and patching"
    },
    {
        question: "During a vulnerability assessment, a tool identifies that certain systems are missing security updates. This type of finding is classified as a:",
        options: [
            "Configuration Vulnerability",
            "Compliance Vulnerability",
            "Operational Vulnerability",
            "Exploit Vulnerability"
        ],
        answer: "Compliance Vulnerability"
    },
    {
        question: "What is the primary purpose of conducting a gap analysis in vulnerability management?",
        options: [
            "To identify vulnerabilities",
            "To assess current security posture against best practices",
            "To automate vulnerability assessments",
            "To reduce overall risk"
        ],
        answer: "To assess current security posture against best practices"
    },
    {
        question: "Max is conducting a vulnerability assessment for a client’s network. He identifies various security flaws and classifies them based on their severity. Which term best describes this process?",
        options: [
            "Vulnerability Classification",
            "Threat Modeling",
            "Penetration Testing",
            "Risk Assessment"
        ],
        answer: "Vulnerability Classification"
    },
    {
        question: "Sarah is reviewing a vulnerability assessment report and notices that certain vulnerabilities are categorized as 'critical.' What does this imply about these vulnerabilities?",
        options: [
            "They are easy to exploit.",
            "They have a high potential impact.",
            "They can be ignored.",
            "They require immediate patching."
        ],
        answer: "They have a high potential impact."
    },
    {
        question: "During a vulnerability assessment, John uses a tool that scans the network for known vulnerabilities. Which type of assessment is he performing?",
        options: [
            "Static Analysis",
            "Dynamic Analysis",
            "Network Scanning",
            "Code Review"
        ],
        answer: "Network Scanning"
    },
    {
        question: "A company utilizes a vulnerability assessment tool that can automatically generate reports after scanning the network. What is the primary benefit of this feature?",
        options: [
            "Manual verification of findings",
            "Automated threat mitigation",
            "Time-saving for security teams",
            "Compliance with regulations"
        ],
        answer: "Time-saving for security teams"
    },
    {
        question: "Max uses a tool that identifies vulnerabilities by checking for missing patches on systems. This type of assessment is known as:",
        options: [
            "Active Scanning",
            "Passive Scanning",
            "Configuration Assessment",
            "Penetration Testing"
        ],
        answer: "Active Scanning"
    },
    {
        question: "A vulnerability assessment tool categorizes vulnerabilities using the CVSS scoring system. What does CVSS stand for?",
        options: [
            "Common Vulnerability Scoring System",
            "Comprehensive Vulnerability Scoring System",
            "Critical Vulnerability Scoring System",
            "Computer Vulnerability Security System"
        ],
        answer: "Common Vulnerability Scoring System"
    },
    {
        question: "While performing a vulnerability assessment, what is the main goal of an authenticated scan compared to an unauthenticated scan?",
        options: [
            "To exploit vulnerabilities",
            "To provide a more in-depth analysis",
            "To test external defenses only",
            "To simulate a real attack"
        ],
        answer: "To provide a more in-depth analysis"
    },
    {
        question: "Which of the following is a key benefit of performing regular vulnerability assessments?",
        options: [
            "Eliminating all risks",
            "Identifying potential threats before they are exploited",
            "Reducing the need for firewalls",
            "Increasing software licensing"
        ],
        answer: "Identifying potential threats before they are exploited"
    },
    {
        question: "When evaluating a vulnerability assessment report, what does the term 'false positive' refer to?",
        options: [
            "A vulnerability that is indeed exploitable",
            "A non-existent vulnerability reported as an issue",
            "An accurate report of a vulnerability",
            "A vulnerability that cannot be exploited"
        ],
        answer: "A non-existent vulnerability reported as an issue"
    },
    {
        question: "An organization decides to conduct a vulnerability assessment using a combination of automated tools and manual testing. This approach is known as:",
        options: [
            "Hybrid Assessment",
            "Dynamic Assessment",
            "Static Assessment",
            "Continuous Assessment"
        ],
        answer: "Hybrid Assessment"
    },
    {
        question: "While using a vulnerability scanning tool, Lisa finds a high-severity vulnerability with a CVSS score of 9.0. What action should she prioritize?",
        options: [
            "Implement a security awareness program",
            "Immediately patch the vulnerability",
            "Document it for future reference",
            "Conduct a penetration test"
        ],
        answer: "Immediately patch the vulnerability"
    },
    {
        question: "A penetration tester uses a tool to simulate a real-world attack on a network. This type of test is primarily aimed at identifying:",
        options: [
            "Vulnerabilities that can be exploited",
            "Employee awareness of security policies",
            "The effectiveness of firewalls",
            "Compliance with industry standards"
        ],
        answer: "Vulnerabilities that can be exploited"
    },
    {
        question: "What is the primary purpose of a vulnerability assessment tool that performs 'passive scanning'?",
        options: [
            "To actively probe for weaknesses",
            "To analyze traffic without disrupting operations",
            "To simulate attacks on the network",
            "To provide compliance reports"
        ],
        answer: "To analyze traffic without disrupting operations"
    },
    {
        question: "A company receives a vulnerability assessment report indicating multiple vulnerabilities with no clear remediation guidance. What should the company do next?",
        options: [
            "Ignore the report",
            "Conduct additional testing",
            "Develop a remediation plan based on risk",
            "Seek external consulting immediately"
        ],
        answer: "Develop a remediation plan based on risk"
    },
    {
        question: "Which type of vulnerability assessment focuses on testing the internal network for weaknesses?",
        options: [
            "External Assessment",
            "Internal Assessment",
            "Web Application Assessment",
            "Network Assessment"
        ],
        answer: "Internal Assessment"
    },
    {
        question: "An organization wants to identify vulnerabilities in its web applications. Which type of assessment should they perform?",
        options: [
            "Network Assessment",
            "Internal Assessment",
            "Web Application Assessment",
            "Physical Security Assessment"
        ],
        answer: "Web Application Assessment"
    },
    {
        question: "Max uses a vulnerability scanner to identify configuration weaknesses in a web server. This type of assessment primarily focuses on:",
        options: [
            "Application vulnerabilities",
            "Network vulnerabilities",
            "Configuration vulnerabilities",
            "User access vulnerabilities"
        ],
        answer: "Configuration vulnerabilities"
    },
    {
        question: "Which of the following would be considered a non-intrusive vulnerability assessment?",
        options: [
            "Port scanning",
            "Vulnerability scanning",
            "Social engineering testing",
            "Network penetration testing"
        ],
        answer: "Vulnerability scanning"
    },
    {
        question: "A company decides to evaluate their security posture by hiring a third party to conduct an assessment without informing the staff. This approach is known as:",
        options: [
            "White Box Testing",
            "Black Box Testing",
            "Gray Box Testing",
            "Open Box Testing"
        ],
        answer: "Black Box Testing"
    },
    {
        question: "When using a vulnerability assessment tool, what is the primary purpose of the 'remediation' step?",
        options: [
            "To report findings",
            "To mitigate identified vulnerabilities",
            "To scan for new vulnerabilities",
            "To develop security policies"
        ],
        answer: "To mitigate identified vulnerabilities"
    },
    {
        question: "What is the significance of the 'impact' metric in the CVSS scoring system?",
        options: [
            "It measures the ease of exploitation.",
            "It assesses the potential consequences of a successful exploit.",
            "It indicates the number of affected systems.",
            "It evaluates the technical complexity of the attack."
        ],
        answer: "It assesses the potential consequences of a successful exploit."
    },
    {
        question: "In vulnerability assessments, the term 'risk' is primarily defined as:",
        options: [
            "The likelihood of a threat exploiting a vulnerability",
            "The potential financial loss from a security breach",
            "The severity of a vulnerability",
            "The cost of implementing security controls"
        ],
        answer: "The likelihood of a threat exploiting a vulnerability"
    },
    {
        question: "Which of the following is an example of a tool commonly used for network vulnerability assessments?",
        options: [
            "Burp Suite",
            "Wireshark",
            "Nessus",
            "Metasploit"
        ],
        answer: "Nessus"
    },
    {
        question: "Which stage in the vulnerability management lifecycle involves identifying, assessing, and prioritizing vulnerabilities?",
        options: [
            "Discovery",
            "Remediation",
            "Reporting",
            "Validation"
        ],
        answer: "Discovery"
    },
    {
        question: "In a vulnerability assessment report, what does a 'risk rating' indicate?",
        options: [
            "The urgency of patching",
            "The exploitability of a vulnerability",
            "The overall security posture of the organization",
            "The potential impact of a vulnerability"
        ],
        answer: "The potential impact of a vulnerability"
    },
    {
        question: "A security team implements a tool that continually monitors the network for vulnerabilities. This approach is known as:",
        options: [
            "Periodic Assessment",
            "Continuous Monitoring",
            "Point-in-Time Assessment",
            "Scheduled Assessment"
        ],
        answer: "Continuous Monitoring"
    },
    {
        question: "Which of the following best describes a 'penetration test' in the context of vulnerability assessment?",
        options: [
            "A simulated attack to exploit vulnerabilities",
            "A tool that scans for known vulnerabilities",
            "A compliance check for security policies",
            "A review of security documentation"
        ],
        answer: "A simulated attack to exploit vulnerabilities"
    },
    {
        question: "What is a key difference between vulnerability assessments and penetration testing?",
        options: [
            "Vulnerability assessments identify vulnerabilities; penetration tests exploit them.",
            "Vulnerability assessments are manual; penetration tests are automated.",
            "Vulnerability assessments focus on external threats; penetration tests focus on internal threats.",
            "There is no difference; they are the same."
        ],
        answer: "Vulnerability assessments identify vulnerabilities; penetration tests exploit them."
    },
    {
        question: "In vulnerability assessments, what does the term 'scope' refer to?",
        options: [
            "The potential impact of a vulnerability",
            "The systems and assets included in the assessment",
            "The tools used for assessment",
            "The duration of the assessment"
        ],
        answer: "The systems and assets included in the assessment"
    },
    {
        question: "An organization is conducting an internal assessment using a tool to scan for vulnerabilities within its infrastructure. Which of the following vulnerabilities might it most likely discover?",
        options: [
            "SQL Injection in a web application",
            "Open ports on internal servers",
            "Weak passwords used by employees",
            "Unpatched software on endpoints"
        ],
        answer: "Unpatched software on endpoints"
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
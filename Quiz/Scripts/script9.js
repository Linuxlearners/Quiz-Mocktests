
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        question: "An attacker creates a fake webpage that looks identical to a legitimate bank site, asking users to input their personal banking credentials. What type of attack is being executed?",
        options: [
            "Phishing",
            "Whaling",
            "Vishing",
            "Spear Phishing"
        ],
        answer: "Phishing"
    },
    {
        question: "Which of the following is NOT typically a social engineering attack?",
        options: [
            "Tailgating",
            "Phishing",
            "SQL Injection",
            "Pretexting"
        ],
        answer: "SQL Injection"
    },
    {
        question: "An attacker tries to gain physical access to a secure building by pretending to be a new contractor on their first day. This is an example of which social engineering technique?",
        options: [
            "Impersonation",
            "Pretexting",
            "Phishing",
            "Baiting"
        ],
        answer: "Impersonation"
    },
    {
        question: "An attacker creates a fake social media profile for a company’s CEO to convince an employee to send them sensitive company information. Which social engineering technique is being used?",
        options: [
            "Whaling",
            "Pretexting",
            "Spear Phishing",
            "Impersonation"
        ],
        answer: "Spear Phishing"
    },
    {
        question: "Which social engineering attack involves tricking someone into downloading malicious software by offering fake services or rewards?",
        options: [
            "Baiting",
            "Phishing",
            "Vishing",
            "Pretexting"
        ],
        answer: "Baiting"
    },
    {
        question: "An attacker impersonates a trusted colleague to convince a user to share login credentials. What technique is being used?",
        options: [
            "Impersonation",
            "Pretexting",
            "Spear Phishing",
            "Phishing"
        ],
        answer: "Impersonation"
    },
    {
        question: "What term refers to the use of social engineering tactics to trick a user into revealing confidential information through text messages or phone calls?",
        options: [
            "Vishing",
            "Phishing",
            "Spear Phishing",
            "Impersonation"
        ],
        answer: "Vishing"
    },
    {
        question: "An attacker sends an email disguised as a security warning from a trusted vendor asking users to click on a link and update their account information. This is an example of which type of attack?",
        options: [
            "Whaling",
            "Phishing",
            "Spear Phishing",
            "Impersonation"
        ],
        answer: "Phishing"
    },
    {
        question: "An attacker posts a link to a fake job offer on a social media platform to collect users’ personal information. Which attack technique is this?",
        options: [
            "Baiting",
            "Phishing",
            "Pretexting",
            "Tailgating"
        ],
        answer: "Baiting"
    },
    {
        question: "An attacker sends a fake email from a bank asking a user to click on a link to reset their password. What type of social engineering attack is this?",
        options: [
            "Vishing",
            "Phishing",
            "Spear Phishing",
            "Pretexting"
        ],
        answer: "Phishing"
    },
    {
        question: "An attacker pretends to be an internal IT administrator and calls an employee, requesting access to the employee’s account to perform 'routine maintenance'. What technique is the attacker using?",
        options: [
            "Pretexting",
            "Phishing",
            "Whaling",
            "Tailgating"
        ],
        answer: "Pretexting"
    },
    {
        question: "An attacker targets a specific executive in an organization, posing as an important client, and sends a crafted email with a malicious attachment. What kind of attack is this?",
        options: [
            "Spear Phishing",
            "Phishing",
            "Whaling",
            "Impersonation"
        ],
        answer: "Whaling"
    },
    {
        question: "What technique involves attackers exploiting a person’s familiarity with a system or device by tricking them into revealing sensitive information or allowing unauthorized access?",
        options: [
            "Phishing",
            "Pretexting",
            "Impersonation",
            "Social Engineering"
        ],
        answer: "Pretexting"
    },
    {
        question: "An attacker uses a fake phone call and pretends to be a helpdesk technician, asking an employee for a one-time password to fix an account issue. What technique is being used?",
        options: [
            "Vishing",
            "Phishing",
            "Pretexting",
            "Whaling"
        ],
        answer: "Vishing"
    },
    {
        question: "In which of the following techniques does the attacker manipulate the victim into providing sensitive information by creating a false sense of urgency?",
        options: [
            "Phishing",
            "Pretexting",
            "Baiting",
            "Scareware"
        ],
        answer: "Scareware"
    },
    {
        question: "An attacker leaves a USB stick in a public place, labeled ‘Confidential Employee Salaries.’ A curious employee finds it and plugs it into a computer. What technique is the attacker using?",
        options: [
            "Baiting",
            "Pretexting",
            "Phishing",
            "Impersonation"
        ],
        answer: "Baiting"
    },
    {
        question: "An attacker convinces a user to click on a link in an email that appears to come from a trusted source, and the user is redirected to a fake website that captures login credentials. Which type of social engineering attack is being executed?",
        options: [
            "Phishing",
            "Spear Phishing",
            "Vishing",
            "Pretexting"
        ],
        answer: "Spear Phishing"
    },
    {
        question: "A malicious actor poses as a consultant and uses a fraudulent identity to request access to sensitive data or systems. What type of social engineering technique is being used?",
        options: [
            "Pretexting",
            "Impersonation",
            "Baiting",
            "Phishing"
        ],
        answer: "Impersonation"
    },
    {
        question: "An attacker sends an SMS to a user pretending to be from their bank, asking for personal details to prevent a security breach. What type of attack is this?",
        options: [
            "Phishing",
            "Vishing",
            "SMS Spoofing",
            "Smishing"
        ],
        answer: "Smishing"
    },
    {
        question: "Which social engineering attack technique involves using a seemingly trustworthy individual to gain unauthorized access to secure areas?",
        options: [
            "Tailgating",
            "Baiting",
            "Vishing",
            "Impersonation"
        ],
        answer: "Tailgating"
    },
    {
        question: "A disgruntled employee with access to sensitive company data leaks the information to the public as a form of retaliation. Which type of insider threat is this?",
        options: [
            "Malicious Insider",
            "Unintentional Insider",
            "Compromised Insider",
            "Impersonation"
        ],
        answer: "Malicious Insider"
    },
    {
        question: "A former employee who still has access to company resources uses their credentials to steal sensitive data. Which type of insider threat does this represent?",
        options: [
            "Compromised Insider",
            "Malicious Insider",
            "Unintentional Insider",
            "Phishing"
        ],
        answer: "Compromised Insider"
    },
    {
        question: "Which of the following describes an insider threat where an employee unknowingly exposes sensitive information to an external party due to poor security practices?",
        options: [
            "Unintentional Insider",
            "Malicious Insider",
            "Compromised Insider",
            "Phishing"
        ],
        answer: "Unintentional Insider"
    },
    {
        question: "An organization’s internal IT administrator accidentally emails a database containing customer information to an external vendor. What kind of insider threat is this?",
        options: [
            "Unintentional Insider",
            "Malicious Insider",
            "Compromised Insider",
            "Impersonation"
        ],
        answer: "Unintentional Insider"
    },
    {
        question: "An employee becomes upset over their workload and intentionally deletes key business records from a company server. Which type of insider threat is being exhibited?",
        options: [
            "Malicious Insider",
            "Compromised Insider",
            "Unintentional Insider",
            "Pretexting"
        ],
        answer: "Malicious Insider"
    },
    {
        question: "Which of the following best describes a scenario where an insider intentionally accesses sensitive data without authorization to harm the organization?",
        options: [
            "Compromised Insider",
            "Malicious Insider",
            "Unintentional Insider",
            "Whaling"
        ],
        answer: "Malicious Insider"
    },
    {
        question: "A user unintentionally shares an internal report with an unauthorized external contact via email. What kind of insider threat is this?",
        options: [
            "Compromised Insider",
            "Unintentional Insider",
            "Malicious Insider",
            "Tailgating"
        ],
        answer: "Unintentional Insider"
    },
    {
        question: "An organization discovers that one of its employees has been accessing financial records without authorization. Which type of insider threat does this describe?",
        options: [
            "Malicious Insider",
            "Compromised Insider",
            "Unintentional Insider",
            "Impersonation"
        ],
        answer: "Malicious Insider"
    },
    {
        question: "An attacker gains access to an organization’s system by compromising a trusted employee’s login credentials. What type of insider threat is this?",
        options: [
            "Compromised Insider",
            "Unintentional Insider",
            "Malicious Insider",
            "Phishing"
        ],
        answer: "Compromised Insider"
    },
    {
        question: "An organization implements a policy that all external requests for sensitive information must be verified through a phone call to the requester’s official number. What type of countermeasure is this?",
        options: [
            "Authentication Policy",
            "Access Control",
            "Physical Security",
            "Social Engineering Awareness"
        ],
        answer: "Authentication Policy"
    },
    {
        question: "To counter social engineering attacks like vishing or phishing, an organization requires employees to use multi-factor authentication for accessing sensitive information. What type of countermeasure is this?",
        options: [
            "Access Control",
            "Network Segmentation",
            "User Awareness Training",
            "Authentication Mechanism"
        ],
        answer: "Authentication Mechanism"
    },
    {
        question: "Which of the following measures would help prevent a tailgating attack?",
        options: [
            "Secure ID card readers",
            "Employee security awareness training",
            "Encryption of sensitive data",
            "Firewalls"
        ],
        answer: "Secure ID card readers"
    },
    {
        question: "An organization is implementing an email filter that identifies and blocks malicious attachments and suspicious links. What kind of countermeasure is this?",
        options: [
            "Network Defense",
            "Social Engineering Awareness",
            "Security Filtering",
            "Access Control"
        ],
        answer: "Security Filtering"
    },
    {
        question: "A company deploys a solution that monitors all outgoing emails for sensitive information such as credit card numbers or social security numbers. What type of countermeasure is this?",
        options: [
            "Data Loss Prevention",
            "Encryption",
            "Access Control",
            "Firewall"
        ],
        answer: "Data Loss Prevention"
    },
    {
        question: "In response to social engineering attacks, an organization starts performing regular security drills and simulated phishing tests for its employees. What countermeasure is being used?",
        options: [
            "Security Awareness Training",
            "Incident Response Plan",
            "Encryption",
            "Access Control"
        ],
        answer: "Security Awareness Training"
    },
    {
        question: "An organization’s security policy states that sensitive information must not be shared through email. This is an example of which type of countermeasure?",
        options: [
            "Access Control",
            "Data Encryption",
            "Information Sharing Policy",
            "Network Segmentation"
        ],
        answer: "Information Sharing Policy"
    },
    {
        question: "A company trains its employees to verify any unsolicited phone calls before disclosing sensitive information. What type of countermeasure is this?",
        options: [
            "Security Awareness Training",
            "Incident Response Plan",
            "Access Control",
            "Firewall"
        ],
        answer: "Security Awareness Training"
    },
    {
        question: "What countermeasure would best prevent unauthorized physical access to secure areas through tailgating?",
        options: [
            "Biometric access controls",
            "Employee security training",
            "Password management policies",
            "Network segmentation"
        ],
        answer: "Biometric access controls"
    },
    {
        "question": "An attacker calls a target company’s helpdesk, pretending to be an executive, and requests access to a sensitive database for an urgent task. The helpdesk operator provides the requested access, believing the caller’s story. Which social engineering technique is being employed?",
        "options": [
            "Pretexting",
            "Impersonation",
            "Spear Phishing",
            "Phishing"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "A hacker sets up a fake social media profile to communicate with employees of a targeted company. The hacker sends personalized messages offering fake job opportunities to gather sensitive company information. Which technique is being used?",
        "options": [
            "Impersonation",
            "Spear Phishing",
            "Pretexting",
            "Social Engineering"
        ],
        "answer": "Spear Phishing"
    },
    {
        "question": "An attacker sends a link in an email that appears to come from a trusted source, urging the recipient to download a document with important information. The document contains a malware payload. What type of social engineering attack is this?",
        "options": [
            "Phishing",
            "Baiting",
            "Spear Phishing",
            "Vishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "Which type of attack manipulates victims into providing personal information by creating a false sense of trust or urgency?",
        "options": [
            "Phishing",
            "Pretexting",
            "Whaling",
            "Scareware"
        ],
        "answer": "Scareware"
    },
    {
        "question": "A hacker tries to obtain a company’s confidential data by contacting an employee, posing as a technician who is conducting a security audit. What type of attack is this?",
        "options": [
            "Pretexting",
            "Impersonation",
            "Baiting",
            "Tailgating"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "Which of the following describes a situation where an attacker gains access to a system by using the identity of a legitimate user who is unaware of the attack?",
        "options": [
            "Compromised Insider",
            "Phishing",
            "Man-in-the-Middle",
            "Impersonation"
        ],
        "answer": "Compromised Insider"
    },
    {
        "question": "An employee receives an email from what appears to be the HR department requesting an immediate update to their account password for ‘security purposes.’ What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Vishing",
            "Pretexting"
        ],
        "answer": "Spear Phishing"
    },
    {
        "question": "Which type of attack exploits the human desire to help others in order to gain unauthorized access to systems or data?",
        "options": [
            "Pretexting",
            "Phishing",
            "Baiting",
            "Impersonation"
        ],
        "answer": "Impersonation"
    },
    {
        "question": "An attacker installs malware on a USB drive and leaves it in a public place in the hope that someone will find it and use it on a company computer. What type of social engineering technique is this?",
        "options": [
            "Baiting",
            "Phishing",
            "Impersonation",
            "Pretexting"
        ],
        "answer": "Baiting"
    },
    {
        "question": "Which of the following is a type of social engineering where attackers use the telephone to trick victims into revealing personal information or credentials?",
        "options": [
            "Vishing",
            "Whaling",
            "Spear Phishing",
            "Phishing"
        ],
        "answer": "Vishing"
    },
    {
        "question": "An attacker calls a company’s helpdesk claiming to be an employee locked out of their account. The attacker requests that the helpdesk provide the password reset information for access. Which social engineering technique is being used?",
        "options": [
            "Impersonation",
            "Phishing",
            "Vishing",
            "Pretexting"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An attacker uses a fake job offer to trick a victim into revealing their personal details. What type of social engineering is being employed?",
        "options": [
            "Baiting",
            "Spear Phishing",
            "Whaling",
            "Phishing"
        ],
        "answer": "Baiting"
    },
    {
        "question": "An attacker sends out fake security alerts to trick users into clicking a link that installs malware on their systems. What type of attack does this represent?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Scareware",
            "Vishing"
        ],
        "answer": "Scareware"
    },
    {
        "question": "What is the primary goal of a vishing attack?",
        "options": [
            "To trick users into downloading malicious files",
            "To steal sensitive information via social engineering over the phone",
            "To gain unauthorized access to a physical location",
            "To manipulate users into clicking malicious links"
        ],
        "answer": "To steal sensitive information via social engineering over the phone"
    },
    {
        "question": "An attacker uses a fake email address that appears to be from an internal system to request sensitive data from an employee. What type of social engineering attack is this?",
        "options": [
            "Impersonation",
            "Phishing",
            "Spear Phishing",
            "Pretexting"
        ],
        "answer": "Spear Phishing"
    },
    {
        "question": "A hacker sends a malicious email disguised as a system update, instructing users to click a link to ‘install updates’ but instead installs malware. What technique is being used?",
        "options": [
            "Spear Phishing",
            "Phishing",
            "Baiting",
            "Impersonation"
        ],
        "answer": "Baiting"
    },
    {
        "question": "An attacker uses a fake website to trick users into inputting their credentials by claiming to be a secure login page for a popular service. What kind of attack is this?",
        "options": [
            "Phishing",
            "Vishing",
            "Spear Phishing",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "Which of the following is a form of social engineering that uses fake social media profiles to manipulate people into revealing sensitive information?",
        "options": [
            "Spear Phishing",
            "Whaling",
            "Impersonation",
            "Pretexting"
        ],
        "answer": "Impersonation"
    },
    {
        "question": "An attacker creates an account on a legitimate social networking site to gain the trust of an employee, then tries to manipulate them into disclosing company secrets. What type of attack is this?",
        "options": [
            "Impersonation",
            "Phishing",
            "Spear Phishing",
            "Pretexting"
        ],
        "answer": "Spear Phishing"
    },
    {
        "question": "What kind of attack involves manipulating an individual to click a link in a message that leads to a phishing site, where they are asked for their login credentials?",
        "options": [
            "Vishing",
            "Phishing",
            "Baiting",
            "Pretexting"
        ],
        "answer": "Phishing"
    },
    {
        "question": "A social engineering attack that targets high-level executives and tricks them into revealing critical business information or authorizing large transactions is called:",
        "options": [
            "Whaling",
            "Spear Phishing",
            "Phishing",
            "Impersonation"
        ],
        "answer": "Whaling"
    },
    {
        "question": "An attacker convinces a company employee to visit a malicious website via email to ‘resolve an issue with their account.’ The website is designed to steal login credentials. What attack is this?",
        "options": [
            "Phishing",
            "Baiting",
            "Impersonation",
            "Vishing"
        ],
        "answer": "Phishing"
    },
    {
        "question": "An attacker who gains access to company data by compromising an employee’s account after their credentials were stolen from an unsecured device would be classified as:",
        "options": [
            "Compromised Insider",
            "Malicious Insider",
            "Unintentional Insider",
            "Impersonator"
        ],
        "answer": "Compromised Insider"
    },
    {
        "question": "Which type of insider threat occurs when an employee intentionally misuses their access to steal or leak sensitive data for personal gain?",
        "options": [
            "Compromised Insider",
            "Unintentional Insider",
            "Malicious Insider",
            "Impersonation"
        ],
        "answer": "Malicious Insider"
    },
    {
        "question": "Which type of countermeasure would help reduce the risks associated with insider threats by preventing access to critical data based on job roles?",
        "options": [
            "Role-Based Access Control",
            "Network Segmentation",
            "Data Loss Prevention",
            "Encryption"
        ],
        "answer": "Role-Based Access Control"
    },
    {
        "question": "An organization detects an employee accessing files they should not have access to, suggesting they may be attempting to leak information. Which countermeasure could help identify and prevent future incidents?",
        "options": [
            "Data Loss Prevention",
            "Intrusion Detection System",
            "Employee Monitoring Software",
            "Firewall"
        ],
        "answer": "Employee Monitoring Software"
    },
    {
        "question": "Which countermeasure would be most effective in preventing data leaks through email by monitoring and controlling outgoing data traffic?",
        "options": [
            "Data Loss Prevention (DLP)",
            "Access Control",
            "Intrusion Detection Systems",
            "Two-Factor Authentication"
        ],
        "answer": "Data Loss Prevention (DLP)"
    },
    {
        "question": "A company implements a strong password policy that requires frequent changes and complex passwords. What type of countermeasure is this?",
        "options": [
            "Access Control",
            "User Authentication",
            "Network Defense",
            "Incident Response"
        ],
        "answer": "User Authentication"
    },
    {
        "question": "An insider threat occurs when a company employee intentionally deletes sensitive data from a system in retaliation for a grievance. Which type of insider threat does this describe?",
        "options": [
            "Unintentional Insider",
            "Malicious Insider",
            "Compromised Insider",
            "Impersonator"
        ],
        "answer": "Malicious Insider"
    },
    {
        "question": "An employee with valid credentials is tricked into downloading a malicious attachment that compromises the company’s data. Which type of insider threat is this?",
        "options": [
            "Malicious Insider",
            "Compromised Insider",
            "Unintentional Insider",
            "Impersonation"
        ],
        "answer": "Compromised Insider"
    },
    {
        "question": "An insider inadvertently leaks sensitive information by sending an email to the wrong recipient. This would be classified as which type of insider threat?",
        "options": [
            "Compromised Insider",
            "Malicious Insider",
            "Unintentional Insider",
            "Impersonator"
        ],
        "answer": "Unintentional Insider"
    },
    {
        "question": "Which type of attack involves a trusted insider who deliberately discloses company information to a competitor?",
        "options": [
            "Malicious Insider",
            "Unintentional Insider",
            "Compromised Insider",
            "Phishing"
        ],
        "answer": "Malicious Insider"
    },
    {
        "question": "A company deploys a system that logs and monitors all user activities to detect suspicious behavior that could indicate insider threats. What type of countermeasure is this?",
        "options": [
            "Access Control",
            "Intrusion Detection System",
            "User Monitoring Software",
            "Security Awareness Training"
        ],
        "answer": "User Monitoring Software"
    },
    {
        "question": "Which countermeasure helps detect abnormal user behavior patterns that could be indicative of a compromised insider threat?",
        "options": [
            "Behavioral Analytics",
            "Encryption",
            "Firewalls",
            "Data Loss Prevention"
        ],
        "answer": "Behavioral Analytics"
    },
    {
        "question": "To prevent insider threats from escalating, an organization should establish which policy to ensure users can report suspicious activities?",
        "options": [
            "Incident Response Plan",
            "Whistleblower Policy",
            "Access Control",
            "Security Awareness Training"
        ],
        "answer": "Whistleblower Policy"
    },
    {
        "question": "An employee’s credentials are compromised by an attacker, who uses them to access sensitive data. Which type of insider threat does this represent?",
        "options": [
            "Compromised Insider",
            "Unintentional Insider",
            "Malicious Insider",
            "Impersonator"
        ],
        "answer": "Compromised Insider"
    },
    {
        "question": "An organization implements encryption to protect data stored on employee laptops. What type of countermeasure is this?",
        "options": [
            "Encryption",
            "Data Loss Prevention",
            "Access Control",
            "Firewall"
        ],
        "answer": "Encryption"
    },
    {
        "question": "What is the primary purpose of implementing multifactor authentication (MFA) in an organization’s security policy?",
        "options": [
            "To ensure only authorized users can access critical systems",
            "To encrypt sensitive data",
            "To monitor user activities",
            "To prevent email phishing attacks"
        ],
        "answer": "To ensure only authorized users can access critical systems"
    },
    {
        "question": "An organization receives an email that appears to be from their service provider, requesting that they update their payment information to avoid disruption in services. Upon clicking the link, the user is directed to a legitimate-looking website that requests credit card information. What type of attack is this, given the details provided?",
        "options": [
            "Phishing",
            "Domain Spoofing",
            "Man-in-the-Middle (MitM)",
            "Spear Phishing"
        ],
        "answer": "Spear Phishing"
    },
    {
        "question": "An attacker sets up a fake Wi-Fi network near a corporate office and convinces employees to connect. Once connected, the attacker monitors all the employees’ communications and captures sensitive information. Which type of attack is being executed?",
        "options": [
            "Evil Twin",
            "Rogue Access Point",
            "WEP Cracking",
            "Session Hijacking"
        ],
        "answer": "Evil Twin"
    },
    {
        "question": "An attacker compromises an employee’s personal email account, then uses the information in the email to gain access to the employee’s corporate account by bypassing security questions. What type of attack is this?",
        "options": [
            "Pretexting",
            "Phishing",
            "Credential Stuffing",
            "Compromised Insider"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An employee receives an urgent email from an executive asking for sensitive financial data for an upcoming audit. The email appears legitimate, and the executive’s email address is spoofed using a very convincing method. What type of social engineering attack is this?",
        "options": [
            "Whaling",
            "Spear Phishing",
            "Impersonation",
            "Vishing"
        ],
        "answer": "Whaling"
    },
    {
        "question": "An attacker sends a fake email appearing to be from a legitimate vendor, including a ‘new’ version of the company’s ‘secure’ software update. Once the user clicks the link and installs the update, malware is deployed. What is the main objective of this attack?",
        "options": [
            "Exfiltration of credentials",
            "Data destruction",
            "Installation of remote access trojans (RATs)",
            "Denial of Service (DoS)"
        ],
        "answer": "Installation of remote access trojans (RATs)"
    },
    {
        "question": "Which of the following is a technique where attackers create fake domains that closely resemble legitimate domains in order to trick users into disclosing sensitive information?",
        "options": [
            "Domain Spoofing",
            "Typosquatting",
            "Social Engineering",
            "Pharming"
        ],
        "answer": "Typosquatting"
    },
    {
        "question": "An insider at a company leaks sensitive information after being manipulated through a fake tech support call, where an attacker posed as a support representative. Which of the following best describes this insider threat?",
        "options": [
            "Compromised Insider",
            "Malicious Insider",
            "Unintentional Insider",
            "Insider Impersonation"
        ],
        "answer": "Compromised Insider"
    },
    {
        "question": "A phishing email contains a hyperlink that redirects a user to a page that looks like the internal login page of their company. This page captures the entered credentials and uses them to compromise the employee’s account. What is the primary attack vector used here?",
        "options": [
            "Credential Stuffing",
            "Session Fixation",
            "Pharming",
            "Man-in-the-Middle"
        ],
        "answer": "Pharming"
    },
    {
        "question": "An attacker uses a social engineering technique to trick an employee into providing them with access to physical building keys by impersonating a fire inspector. This would be classified under which attack?",
        "options": [
            "Tailgating",
            "Pretexting",
            "Physical Security Breach",
            "Social Engineering"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "Which of the following countermeasures would be most effective in preventing an employee from being tricked into disclosing sensitive information via vishing (voice phishing)?",
        "options": [
            "Multi-Factor Authentication",
            "Security Awareness Training",
            "Network Segmentation",
            "User Authentication"
        ],
        "answer": "Security Awareness Training"
    },
    {
        "question": "A company deploys a new authentication system where all employees must scan their fingerprint and facial recognition to access their workstations. This is an example of which type of countermeasure?",
        "options": [
            "Multi-Factor Authentication",
            "Access Control",
            "Behavioral Analytics",
            "Biometric Authentication"
        ],
        "answer": "Biometric Authentication"
    },
    {
        "question": "An employee unknowingly provides sensitive company data to an attacker over the phone, believing they are helping with an IT troubleshooting task. What social engineering technique was most likely used?",
        "options": [
            "Pretexting",
            "Impersonation",
            "Spear Phishing",
            "Vishing"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "A hacker sends a malicious PDF attachment with embedded JavaScript to an employee. Once opened, the PDF exploits a vulnerability in the employee’s reader to execute malicious code. What type of attack is being executed?",
        "options": [
            "Drive-by Download",
            "Exploit Kit",
            "Malicious Macro",
            "Fileless Malware Attack"
        ],
        "answer": "Drive-by Download"
    },
    {
        "question": "An attacker masquerades as a trusted third-party contractor to bypass security protocols and gain unauthorized access to critical systems. Which countermeasure would most effectively prevent this type of attack?",
        "options": [
            "Access Control Lists (ACLs)",
            "Multi-Factor Authentication (MFA)",
            "Physical Security Controls",
            "Role-Based Access Control (RBAC)"
        ],
        "answer": "Role-Based Access Control (RBAC)"
    },
    {
        "question": "A user mistakenly gives an attacker access to a company’s internal network by responding to an email that appears to be from the IT department, asking them to confirm their network credentials for security purposes. What type of attack is this?",
        "options": [
            "Phishing",
            "Spear Phishing",
            "Whaling",
            "Credential Stuffing"
        ],
        "answer": "Spear Phishing"
    },
    {
        "question": "What type of attack involves an adversary gaining access to a trusted system, then using it to launch attacks on other systems or networks by sending out malicious emails from that system?",
        "options": [
            "Botnet Attack",
            "Pivoting",
            "Credential Stuffing",
            "Compromised Insider Attack"
        ],
        "answer": "Pivoting"
    },
    {
        "question": "An attacker uses compromised internal credentials to send out phishing emails that appear to be from the HR department. What would be the best countermeasure to prevent this?",
        "options": [
            "Email Filtering",
            "Multi-Factor Authentication (MFA)",
            "Intrusion Detection System (IDS)",
            "Role-Based Access Control (RBAC)"
        ],
        "answer": "Multi-Factor Authentication (MFA)"
    },
    {
        "question": "An organization has observed a high number of failed login attempts from different locations, often using compromised usernames and passwords. Which advanced attack type is this indicative of?",
        "options": [
            "Credential Stuffing",
            "Phishing",
            "Man-in-the-Middle Attack",
            "Insider Impersonation"
        ],
        "answer": "Credential Stuffing"
    },
    {
        "question": "During a penetration test, a tester discovers an employee’s personal phone number was leaked on social media. The tester uses this information to impersonate the employee and trick the helpdesk into revealing the employee’s network password. What type of attack is this?",
        "options": [
            "Spear Phishing",
            "Pretexting",
            "Phishing",
            "Vishing"
        ],
        "answer": "Vishing"
    },
    {
        "question": "A hacker deploys a malware-laden software update on a company’s internal network by exploiting a vulnerability in the vendor’s update mechanism. What type of attack is this?",
        "options": [
            "Supply Chain Attack",
            "Insider Attack",
            "Advanced Persistent Threat (APT)",
            "Man-in-the-Middle (MitM)"
        ],
        "answer": "Supply Chain Attack"
    },
    {
        "question": "An organization experiences multiple instances of sensitive data being leaked, and after investigation, it is found that employees have been communicating classified information via social media platforms. What kind of countermeasure should be prioritized to prevent future data leaks?",
        "options": [
            "Social Media Monitoring",
            "Data Loss Prevention (DLP)",
            "Access Control Lists",
            "Security Awareness Training"
        ],
        "answer": "Data Loss Prevention (DLP)"
    },
    {
        "question": "A company deploys a solution that tracks every email sent by an employee to detect any potential leaks of sensitive information through outbound messages. What type of security control is being used?",
        "options": [
            "Data Loss Prevention (DLP)",
            "Email Filtering",
            "Intrusion Detection System",
            "Web Filtering"
        ],
        "answer": "Data Loss Prevention (DLP)"
    },
    {
        "question": "An attacker sends an email containing a link to a malicious file that exploits a vulnerability in an unpatched PDF reader. The attacker is able to compromise the system without the user’s knowledge. What type of advanced attack is this?",
        "options": [
            "Zero-Day Exploit",
            "Drive-by Download",
            "Malicious Macro",
            "Fileless Malware Attack"
        ],
        "answer": "Zero-Day Exploit"
    },
    {
        "question": "A penetration tester uses social engineering techniques to trick an employee into leaving their desk unattended. While the employee is away, the tester installs a keylogger on the workstation. Which technique was used in this scenario?",
        "options": [
            "Tailgating",
            "Pretexting",
            "Baiting",
            "Vishing"
        ],
        "answer": "Tailgating"
    },
    {
        "question": "A malicious insider sends an email containing a malicious attachment to an external competitor. The attachment contains exfiltrated company data. What type of insider threat is this?",
        "options": [
            "Compromised Insider",
            "Malicious Insider",
            "Unintentional Insider",
            "Impersonation"
        ],
        "answer": "Malicious Insider"
    },
    {
        "question": "An employee accidentally forwards sensitive company information to an unauthorized recipient due to a typo in the email address. What kind of insider threat does this represent?",
        "options": [
            "Compromised Insider",
            "Malicious Insider",
            "Unintentional Insider",
            "Social Engineering"
        ],
        "answer": "Unintentional Insider"
    },
    {
        "question": "An attacker impersonates a government official and uses fear tactics to trick employees into revealing sensitive data, claiming it is for an audit. What is the most likely social engineering technique used here?",
        "options": [
            "Phishing",
            "Pretexting",
            "Whaling",
            "Scareware"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An attacker successfully gains access to an employee’s account using stolen credentials from an unsecured Wi-Fi network. What type of attack was most likely performed?",
        "options": [
            "Man-in-the-Middle Attack",
            "Phishing",
            "Rogue Access Point",
            "Credential Stuffing"
        ],
        "answer": "Man-in-the-Middle Attack"
    },
    {
        "question": "During a targeted attack, an attacker gains access to a company’s private information by exploiting weak internal security controls, then uses social engineering tactics to further compromise the organization. What is this attack commonly referred to as?",
        "options": [
            "Advanced Persistent Threat (APT)",
            "Ransomware Attack",
            "Supply Chain Attack",
            "Privilege Escalation"
        ],
        "answer": "Advanced Persistent Threat (APT)"
    },
    {
        "question": "A hacker intercepts an employee’s communications between the employee and the company’s external VPN server, gaining access to sensitive information. What type of attack is being carried out?",
        "options": [
            "Man-in-the-Middle Attack",
            "Eavesdropping",
            "Packet Sniffing",
            "Session Fixation"
        ],
        "answer": "Man-in-the-Middle Attack"
    },
    {
        "question": "An attacker using a botnet sends out multiple phishing emails designed to steal login credentials. The attacker then uses the compromised accounts to access sensitive company systems. What kind of attack technique is being executed?",
        "options": [
            "Credential Stuffing",
            "Botnet Attack",
            "Pharming",
            "Spear Phishing"
        ],
        "answer": "Botnet Attack"
    },
    {
        "question": "A company implements strict data access controls based on a 'need-to-know' basis and enforces regular auditing of employee actions. This is an example of which type of countermeasure?",
        "options": [
            "Data Loss Prevention",
            "Role-Based Access Control",
            "Encryption",
            "Multi-Factor Authentication"
        ],
        "answer": "Role-Based Access Control"
    },
    {
        "question": "An employee is approached by a hacker posing as a 'security auditor' who offers to help secure the company's IT systems. The hacker then persuades the employee to share sensitive internal documents. What social engineering technique is being used?",
        "options": [
            "Pretexting",
            "Impersonation",
            "Spear Phishing",
            "Baiting"
        ],
        "answer": "Pretexting"
    },
    {
        "question": "An attacker leverages information gathered from a social media account to craft a convincing email, which then tricks the recipient into clicking a link that installs a Trojan. What social engineering technique is being used?",
        "options": [
            "Spear Phishing",
            "Impersonation",
            "Whaling",
            "Phishing"
        ],
        "answer": "Spear Phishing"
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

let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    // IoT Concepts
    {
        "question": "Lisa is designing an IoT solution for smart homes. She needs to ensure that the devices can communicate securely over the internet. Which protocol should she prioritize for secure data transmission?",
        "options": [
            "HTTP",
            "MQTT",
            "CoAP",
            "HTTPS"
        ],
        "answer": "HTTPS"
    },
    {
        "question": "During a project meeting, a team member mentions that IoT devices should be designed with minimal resources to reduce costs. What principle of IoT device design is being referenced?",
        "options": [
            "Interoperability",
            "Scalability",
            "Resource Constrained Design",
            "High Availability"
        ],
        "answer": "Resource Constrained Design"
    },
    {
        "question": "An organization plans to implement an IoT-based monitoring system. They require the devices to gather data autonomously and communicate with a centralized server. Which of the following is a key characteristic of such IoT devices?",
        "options": [
            "Human intervention",
            "Manual data entry",
            "Autonomous operation",
            "Static configurations"
        ],
        "answer": "Autonomous operation"
    },
    {
        "question": "A security engineer is tasked with assessing an IoT device’s ability to maintain user privacy. Which IoT principle should the engineer focus on?",
        "options": [
            "Data Minimization",
            "Redundancy",
            "Scalability",
            "Firmware Upgradability"
        ],
        "answer": "Data Minimization"
    },
    {
        "question": "While reviewing IoT devices, a technician finds that some devices are designed with hardcoded credentials. What type of security flaw does this represent?",
        "options": [
            "Weak Cryptography",
            "Insecure Storage",
            "Poor Access Control",
            "Lack of Encryption"
        ],
        "answer": "Poor Access Control"
    },
    {
        "question": "An IoT device manufacturer wants to ensure that their products are future-proof. What design characteristic should they prioritize?",
        "options": [
            "Proprietary Protocols",
            "Open Standards",
            "Static Firmware",
            "Limited Functionality"
        ],
        "answer": "Open Standards"
    },
    {
        "question": "When discussing IoT ecosystems, which term refers to the ability of devices from different manufacturers to work together seamlessly?",
        "options": [
            "Interoperability",
            "Scalability",
            "Portability",
            "Configurability"
        ],
        "answer": "Interoperability"
    },
    {
        "question": "A device is designed to only collect and transmit data when a specific condition is met, minimizing unnecessary data usage. What is this approach called?",
        "options": [
            "Data Aggregation",
            "Event-Driven Architecture",
            "Data Redundancy",
            "Continuous Monitoring"
        ],
        "answer": "Event-Driven Architecture"
    },
    {
        "question": "In the context of IoT, what does the term 'edge computing' refer to?",
        "options": [
            "Processing data on cloud servers",
            "Data processing at the source of data generation",
            "Using edge devices for increased security",
            "Centralized data management"
        ],
        "answer": "Data processing at the source of data generation"
    },
    {
        "question": "When developing IoT applications, why is it important to implement firmware updates?",
        "options": [
            "To add new features",
            "To improve aesthetic design",
            "To fix security vulnerabilities",
            "To enhance user experience"
        ],
        "answer": "To fix security vulnerabilities"
    },
    
    // IoT Attacks
    {
        "question": "An attacker exploits a weakness in the default password of a smart thermostat to gain unauthorized access. What type of attack is this?",
        "options": [
            "Man-in-the-Middle Attack",
            "Brute Force Attack",
            "DDoS Attack",
            "Credential Stuffing"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "During an assessment, a security analyst finds that an IoT camera has an unsecured API endpoint allowing remote access. What vulnerability is the camera likely exposed to?",
        "options": [
            "Broken Authentication",
            "Cross-Site Scripting (XSS)",
            "Insecure Direct Object References (IDOR)",
            "Buffer Overflow"
        ],
        "answer": "Insecure Direct Object References (IDOR)"
    },
    {
        "question": "A hacker sends malformed packets to an IoT device, causing it to crash and reboot repeatedly. What type of attack is being executed?",
        "options": [
            "DoS Attack",
            "Ransomware Attack",
            "SQL Injection",
            "Phishing Attack"
        ],
        "answer": "DoS Attack"
    },
    {
        "question": "An organization is using IoT sensors to monitor environmental conditions. An attacker intercepts the communication between the sensors and the server. What type of attack is this?",
        "options": [
            "Eavesdropping",
            "Man-in-the-Middle Attack",
            "Data Injection",
            "Session Hijacking"
        ],
        "answer": "Man-in-the-Middle Attack"
    },
    {
        "question": "A vulnerability assessment reveals that an IoT device does not validate incoming firmware updates. What type of risk does this pose?",
        "options": [
            "Data Loss",
            "Unauthorized Access",
            "Malicious Firmware Installation",
            "Service Disruption"
        ],
        "answer": "Malicious Firmware Installation"
    },
    {
        "question": "An attacker uses a botnet of IoT devices to launch a distributed denial-of-service attack on a website. What is the primary tactic being employed?",
        "options": [
            "Phishing",
            "Exploitation of Vulnerabilities",
            "Network Reconnaissance",
            "Flooding the Target"
        ],
        "answer": "Flooding the Target"
    },
    {
        "question": "A researcher discovers that a smart lock can be opened using a replay attack. What does this indicate about the lock's security measures?",
        "options": [
            "Insufficient encryption",
            "Weak authentication protocols",
            "Vulnerability to session fixation",
            "Inadequate logging mechanisms"
        ],
        "answer": "Weak authentication protocols"
    },
    {
        "question": "While investigating a compromised IoT device, a forensic analyst discovers that it was infected with malware that exfiltrates data. What type of malware is this likely categorized as?",
        "options": [
            "Ransomware",
            "Adware",
            "Spyware",
            "Trojan"
        ],
        "answer": "Spyware"
    },
    {
        "question": "A security team receives alerts about an IoT device being flooded with requests, causing it to malfunction. What is the likely type of attack occurring?",
        "options": [
            "Man-in-the-Middle Attack",
            "DDoS Attack",
            "SQL Injection",
            "Phishing Attack"
        ],
        "answer": "DDoS Attack"
    },
    {
        "question": "An IoT device communicates with a cloud service without using encryption. What kind of attack can an adversary easily perform?",
        "options": [
            "Eavesdropping",
            "SQL Injection",
            "Cross-Site Scripting",
            "Phishing"
        ],
        "answer": "Eavesdropping"
    },

    // IoT Hacking Methodology
    {
        "question": "During a penetration test of an IoT device, a tester needs to gather information about the device's network interfaces. Which phase of the hacking methodology is this?",
        "options": [
            "Reconnaissance",
            "Scanning",
            "Exploitation",
            "Post-Exploitation"
        ],
        "answer": "Reconnaissance"
    },
    {
        "question": "A penetration tester is analyzing the firmware of a smart light bulb. What tool would be most useful for this purpose?",
        "options": [
            "Nmap",
            "Wireshark",
            "Binwalk",
            "Burp Suite"
        ],
        "answer": "Binwalk"
    },
    {
        "question": "In an IoT penetration test, a tester identifies a vulnerable API. What is the next logical step in the hacking methodology?",
        "options": [
            "Performing a denial-of-service attack",
            "Exploiting the vulnerability",
            "Gathering further information",
            "Reporting findings"
        ],
        "answer": "Exploiting the vulnerability"
    },
    {
        "question": "A security professional conducts a thorough assessment of the physical security of an IoT device. What phase of the hacking methodology does this fall under?",
        "options": [
            "Exploitation",
            "Reconnaissance",
            "Post-Exploitation",
            "Reporting"
        ],
        "answer": "Reconnaissance"
    },
    {
        "question": "During the exploitation phase of an IoT assessment, a tester finds a way to remotely control the device. What type of vulnerability might they have exploited?",
        "options": [
            "Insecure Direct Object References",
            "Cross-Site Request Forgery",
            "Remote Code Execution",
            "SQL Injection"
        ],
        "answer": "Remote Code Execution"
    },
    {
        "question": "A tester is analyzing the network traffic generated by an IoT device to identify sensitive data leaks. What type of analysis is being conducted?",
        "options": [
            "Static Analysis",
            "Dynamic Analysis",
            "Binary Analysis",
            "Protocol Analysis"
        ],
        "answer": "Protocol Analysis"
    },
    {
        "question": "After successfully exploiting an IoT device, a tester installs a backdoor for persistent access. What phase of the hacking methodology does this represent?",
        "options": [
            "Post-Exploitation",
            "Reconnaissance",
            "Exploitation",
            "Reporting"
        ],
        "answer": "Post-Exploitation"
    },
    {
        "question": "During a pentest of a smart home system, a tester discovers that commands can be sent in plaintext over the network. What kind of vulnerability is this an example of?",
        "options": [
            "Insecure Communications",
            "Weak Authentication",
            "Cross-Site Scripting",
            "Input Validation Failure"
        ],
        "answer": "Insecure Communications"
    },
    {
        "question": "In an IoT environment, a tester successfully retrieves sensitive data from a device's memory. What type of attack does this represent?",
        "options": [
            "Physical Attack",
            "Network Attack",
            "Social Engineering",
            "Remote Attack"
        ],
        "answer": "Physical Attack"
    },
    {
        "question": "During the reporting phase of a pentest, what is the primary goal of the tester?",
        "options": [
            "To exploit vulnerabilities",
            "To gather more information",
            "To document findings and recommend remediation",
            "To communicate with users"
        ],
        "answer": "To document findings and recommend remediation"
    },

    // IoT Attack Countermeasures
    {
        "question": "An organization implementing IoT solutions wants to protect against unauthorized access. Which measure should they prioritize?",
        "options": [
            "Implementing strong passwords",
            "Conducting regular backups",
            "Deploying a firewall",
            "Using default settings"
        ],
        "answer": "Implementing strong passwords"
    },
    {
        "question": "To secure IoT devices, a company decides to use encryption for data transmission. What encryption standard is recommended for this purpose?",
        "options": [
            "DES",
            "3DES",
            "AES",
            "RC4"
        ],
        "answer": "AES"
    },
    {
        "question": "A company is concerned about the security of their IoT devices. They decide to implement an update mechanism. What is essential for this mechanism?",
        "options": [
            "Manual updates only",
            "Secure firmware delivery",
            "No need for user authentication",
            "Static IP addresses"
        ],
        "answer": "Secure firmware delivery"
    },
    {
        "question": "An organization wants to prevent DDoS attacks on its IoT infrastructure. Which strategy would be most effective?",
        "options": [
            "Increased bandwidth",
            "Rate limiting",
            "Use of cloud storage",
            "Firewall configuration"
        ],
        "answer": "Rate limiting"
    },
    {
        "question": "To mitigate the risks of IoT vulnerabilities, an organization should adopt which of the following practices?",
        "options": [
            "Ignoring updates to save costs",
            "Regular vulnerability assessments",
            "Limiting device usage to untested models",
            "Restricting network access"
        ],
        "answer": "Regular vulnerability assessments"
    },
    {
        "question": "An IoT device manufacturer implements a security framework for their products. Which framework is known for promoting secure IoT design?",
        "options": [
            "NIST Cybersecurity Framework",
            "ISO 27001",
            "OWASP IoT Top Ten",
            "PCI DSS"
        ],
        "answer": "OWASP IoT Top Ten"
    },
    {
        "question": "In order to enhance the security of IoT devices, which measure should be avoided?",
        "options": [
            "Frequent software updates",
            "Regularly changing default credentials",
            "Using complex passwords",
            "Keeping software static"
        ],
        "answer": "Keeping software static"
    },
    {
        "question": "A business wants to secure its IoT network from unauthorized external access. Which technology would best serve this purpose?",
        "options": [
            "Public Wi-Fi",
            "Virtual Private Network (VPN)",
            "Open networks",
            "Unrestricted access"
        ],
        "answer": "Virtual Private Network (VPN)"
    },
    {
        "question": "To ensure secure communication between IoT devices, what should be implemented?",
        "options": [
            "Open protocols",
            "Encryption mechanisms",
            "Limited access control",
            "Static IP addresses"
        ],
        "answer": "Encryption mechanisms"
    },
    {
        "question": "An organization employs threat modeling to identify risks in their IoT systems. What is the primary purpose of this approach?",
        "options": [
            "To develop new products",
            "To assess system performance",
            "To identify and prioritize security risks",
            "To enhance user experience"
        ],
        "answer": "To identify and prioritize security risks"
    },

    // OT Concepts
    {
        "question": "In the context of Operational Technology (OT), what does the term 'SCADA' refer to?",
        "options": [
            "Supervisory Control and Data Acquisition",
            "System Control and Data Analysis",
            "Safety Control and Data Assessment",
            "Systematic Control and Data Acquisition"
        ],
        "answer": "Supervisory Control and Data Acquisition"
    },
    {
        "question": "Which of the following describes the primary purpose of OT systems?",
        "options": [
            "Data storage and retrieval",
            "Monitoring and controlling physical processes",
            "User interaction and interface design",
            "Software development"
        ],
        "answer": "Monitoring and controlling physical processes"
    },
    {
        "question": "What is a key characteristic that distinguishes OT from IT systems?",
        "options": [
            "OT systems prioritize data integrity",
            "OT systems are often time-sensitive and require real-time operations",
            "OT systems have a user-friendly interface",
            "OT systems focus primarily on software applications"
        ],
        "answer": "OT systems are often time-sensitive and require real-time operations"
    },
    {
        "question": "An organization implements an OT system to manage industrial processes. What is a critical concern for securing this system?",
        "options": [
            "User experience",
            "Software updates",
            "Network segmentation",
            "Database optimization"
        ],
        "answer": "Network segmentation"
    },
    {
        "question": "What does the term 'Industrial Internet of Things' (IIoT) refer to?",
        "options": [
            "Personal consumer IoT devices",
            "Integration of IoT technologies in industrial processes",
            "Cloud computing solutions for industries",
            "Networking protocols for industrial applications"
        ],
        "answer": "Integration of IoT technologies in industrial processes"
    },
    {
        "question": "In an OT environment, what is a common method used for data acquisition from physical devices?",
        "options": [
            "Cloud computing",
            "Remote logging",
            "Telemetry",
            "Data mining"
        ],
        "answer": "Telemetry"
    },
    {
        "question": "Which layer of the Purdue Enterprise Reference Architecture (PERA) primarily deals with physical processes?",
        "options": [
            "Enterprise Level",
            "Site Level",
            "Control Level",
            "Field Level"
        ],
        "answer": "Field Level"
    },
    {
        "question": "An OT network experiences a security breach. What is the most critical immediate action to take?",
        "options": [
            "Reboot all systems",
            "Disconnect affected devices from the network",
            "Inform all employees",
            "Update software patches"
        ],
        "answer": "Disconnect affected devices from the network"
    },
    {
        "question": "A company is looking to integrate OT and IT systems. What is a major challenge they may face?",
        "options": [
            "Enhanced communication protocols",
            "Compatibility of hardware and software",
            "Increased user satisfaction",
            "Cost reduction"
        ],
        "answer": "Compatibility of hardware and software"
    },
    {
        "question": "What is a critical component of an effective OT cybersecurity strategy?",
        "options": [
            "Minimizing hardware usage",
            "Regularly scheduled downtime",
            "Continuous monitoring and incident response",
            "Centralized data management"
        ],
        "answer": "Continuous monitoring and incident response"
    },

    // OT Attacks
    {
        "question": "An attacker uses malware to disrupt the operations of an industrial control system. What type of attack is this?",
        "options": [
            "Phishing Attack",
            "Denial-of-Service Attack",
            "Ransomware Attack",
            "Insider Threat"
        ],
        "answer": "Denial-of-Service Attack"
    },
    {
        "question": "During a security assessment, a vulnerability in a SCADA system is discovered that allows remote command execution. What type of attack could this potentially lead to?",
        "options": [
            "Data Breach",
            "Man-in-the-Middle Attack",
            "Privilege Escalation",
            "Physical Damage to Equipment"
        ],
        "answer": "Physical Damage to Equipment"
    },
    {
        "question": "An organization is targeted by a cyber attack that manipulates data being collected from sensors in a manufacturing plant. What type of attack is this known as?",
        "options": [
            "Data Injection",
            "Spoofing",
            "Phishing",
            "Replay Attack"
        ],
        "answer": "Data Injection"
    },
    {
        "question": "A threat actor gains unauthorized access to an OT system and changes the settings of a critical machine. What type of threat is this?",
        "options": [
            "Physical Threat",
            "Cyber Threat",
            "Environmental Threat",
            "Human Threat"
        ],
        "answer": "Cyber Threat"
    },
    {
        "question": "In an OT environment, what is the primary risk associated with using default passwords on devices?",
        "options": [
            "Data encryption issues",
            "Unauthorized access",
            "Increased operational costs",
            "Performance degradation"
        ],
        "answer": "Unauthorized access"
    },
    {
        "question": "A security breach in an OT environment leads to the unauthorized modification of operational parameters. What type of attack is this considered?",
        "options": [
            "Integrity Attack",
            "Availability Attack",
            "Confidentiality Attack",
            "Denial of Service"
        ],
        "answer": "Integrity Attack"
    },
    {
        "question": "A group of hackers targets a factory's PLC (Programmable Logic Controller) systems to cause physical damage. What type of attack is this?",
        "options": [
            "Cyber Espionage",
            "Sabotage",
            "Data Theft",
            "Social Engineering"
        ],
        "answer": "Sabotage"
    },
    {
        "question": "During an incident response exercise, a simulated attack on an OT system results in loss of control over critical processes. What is the most likely attack type?",
        "options": [
            "Malware Infection",
            "Insider Threat",
            "Network Breach",
            "Man-in-the-Middle Attack"
        ],
        "answer": "Malware Infection"
    },
    {
        "question": "A company discovers that their industrial network has been compromised, allowing an attacker to manipulate system controls. What is the first action they should take?",
        "options": [
            "Notify all employees",
            "Disconnect affected systems",
            "Perform a full system audit",
            "Reboot the network"
        ],
        "answer": "Disconnect affected systems"
    },
    {
        "question": "An employee is tricked into providing access credentials to an external party under false pretenses. What type of attack does this describe?",
        "options": [
            "Phishing",
            "Malware",
            "SQL Injection",
            "Man-in-the-Middle"
        ],
        "answer": "Phishing"
    },

    // OT Hacking Methodology
    {
        "question": "In the context of OT security assessments, what is the first phase of the hacking methodology?",
        "options": [
            "Exploitation",
            "Reconnaissance",
            "Scanning",
            "Reporting"
        ],
        "answer": "Reconnaissance"
    },
    {
        "question": "During a penetration test, a tester identifies network segmentation as a critical factor. What phase of the methodology does this relate to?",
        "options": [
            "Exploitation",
            "Post-Exploitation",
            "Scanning",
            "Reporting"
        ],
        "answer": "Scanning"
    },
    {
        "question": "A security consultant is assessing the security of a PLC. What tool is most suitable for this task?",
        "options": [
            "Wireshark",
            "Nmap",
            "Metasploit",
            "Burp Suite"
        ],
        "answer": "Metasploit"
    },
    {
        "question": "After gathering information about an OT system, a tester attempts to exploit a known vulnerability. What phase is this?",
        "options": [
            "Reconnaissance",
            "Exploitation",
            "Post-Exploitation",
            "Reporting"
        ],
        "answer": "Exploitation"
    },
    {
        "question": "A security professional identifies several outdated components in an OT network. What should be their next step in the methodology?",
        "options": [
            "Reporting findings",
            "Exploiting vulnerabilities",
            "Updating components",
            "Conducting further research"
        ],
        "answer": "Reporting findings"
    },
    {
        "question": "In OT environments, what is a common technique used to assess vulnerabilities in devices?",
        "options": [
            "Social Engineering",
            "Penetration Testing",
            "Data Mining",
            "Compliance Auditing"
        ],
        "answer": "Penetration Testing"
    },
    {
        "question": "A tester analyzes the logs from an OT system to identify suspicious activity. What phase of the hacking methodology does this represent?",
        "options": [
            "Post-Exploitation",
            "Reconnaissance",
            "Exploitation",
            "Reporting"
        ],
        "answer": "Post-Exploitation"
    },
    {
        "question": "During an OT assessment, a tester utilizes fuzz testing to identify vulnerabilities. What type of testing is being employed?",
        "options": [
            "Static Analysis",
            "Dynamic Analysis",
            "Protocol Analysis",
            "Physical Analysis"
        ],
        "answer": "Dynamic Analysis"
    },
    {
        "question": "After successfully exploiting an OT device, a tester implements a mechanism for maintaining access. What does this represent in the hacking methodology?",
        "options": [
            "Post-Exploitation",
            "Exploitation",
            "Reconnaissance",
            "Reporting"
        ],
        "answer": "Post-Exploitation"
    },
    {
        "question": "During the reporting phase, what is the primary goal for a tester?",
        "options": [
            "To exploit vulnerabilities",
            "To document findings and recommend actions",
            "To conduct further assessments",
            "To communicate with end-users"
        ],
        "answer": "To document findings and recommend actions"
    },

    // OT Attack Countermeasures
    {
        "question": "An organization is implementing security measures for their OT environment. Which of the following is a critical step in securing OT networks?",
        "options": [
            "Allowing remote access without restrictions",
            "Regularly changing passwords and access controls",
            "Using the same network for IT and OT",
            "Ignoring physical security measures"
        ],
        "answer": "Regularly changing passwords and access controls"
    },
    {
        "question": "To mitigate risks in OT environments, organizations should implement which of the following?",
        "options": [
            "Minimal logging",
            "Comprehensive monitoring and logging",
            "Static access controls",
            "Open access to all users"
        ],
        "answer": "Comprehensive monitoring and logging"
    },
    {
        "question": "An organization wants to ensure secure communication in their OT systems. What protocol should they use?",
        "options": [
            "HTTP",
            "FTP",
            "HTTPS",
            "MQTT"
        ],
        "answer": "HTTPS"
    },
    {
        "question": "To protect OT systems against unauthorized changes, what should organizations implement?",
        "options": [
            "Regular backups and version control",
            "Open access to all users",
            "Static configurations",
            "Manual logs"
        ],
        "answer": "Regular backups and version control"
    },
    {
        "question": "In order to enhance OT security, which framework should organizations consider?",
        "options": [
            "NIST Cybersecurity Framework",
            "ITIL",
            "COBIT",
            "ISO 9001"
        ],
        "answer": "NIST Cybersecurity Framework"
    },
    {
        "question": "To ensure the integrity of an OT system, which measure is most important?",
        "options": [
            "User education and awareness",
            "Regular system audits",
            "Outdated software usage",
            "Unrestricted access"
        ],
        "answer": "Regular system audits"
    },
    {
        "question": "An organization wants to prevent insider threats in their OT environment. What should be a key focus?",
        "options": [
            "Strong access controls and monitoring",
            "Open communication policies",
            "Limited employee training",
            "Increased remote access"
        ],
        "answer": "Strong access controls and monitoring"
    },
    {
        "question": "In an OT security strategy, what is crucial for incident response?",
        "options": [
            "Reactive measures only",
            "Comprehensive incident response plans",
            "Ignoring user input",
            "Static security policies"
        ],
        "answer": "Comprehensive incident response plans"
    },
    {
        "question": "To improve the resilience of OT systems against attacks, what approach should organizations adopt?",
        "options": [
            "Continuous training and awareness programs",
            "Single point of failure systems",
            "Limited network segmentation",
            "Weak authentication methods"
        ],
        "answer": "Continuous training and awareness programs"
    },
    {
        "question": "An OT system experiences a data breach. What is the first action the organization should take?",
        "options": [
            "Notify all stakeholders",
            "Disconnect affected systems",
            "Conduct a full system audit",
            "Change all passwords"
        ],
        "answer": "Disconnect affected systems"
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

let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "A security analyst is reviewing the architecture of a company’s network. They notice that the IDS is placed in a location where it cannot monitor all traffic. What is a potential consequence of this setup?",
        "options": [
            "Reduced false positives",
            "Increased network speed",
            "Blind spots in threat detection",
            "Simplified management"
        ],
        "answer": "Blind spots in threat detection"
    },
    {
        "question": "During a security assessment, a pen tester finds that the organization uses both an IDS and IPS. What is the primary difference in their functions?",
        "options": [
            "IDS blocks attacks, while IPS only detects them",
            "IPS monitors traffic, while IDS collects data",
            "IDS analyzes data post-event, while IPS prevents attacks in real-time",
            "There is no difference; both serve the same purpose"
        ],
        "answer": "IDS analyzes data post-event, while IPS prevents attacks in real-time"
    },
    {
        "question": "A company is deploying a honeypot to lure attackers. What is the primary purpose of this honeypot?",
        "options": [
            "To store sensitive data",
            "To monitor employee behavior",
            "To gather intelligence on attacker tactics",
            "To prevent data loss"
        ],
        "answer": "To gather intelligence on attacker tactics"
    },
    {
        "question": "In an effort to enhance security, a company decides to implement a firewall. What is one of the key functions of this firewall?",
        "options": [
            "To encrypt sensitive data",
            "To monitor outgoing traffic only",
            "To control incoming and outgoing network traffic based on security rules",
            "To provide VPN access"
        ],
        "answer": "To control incoming and outgoing network traffic based on security rules"
    },
    {
        "question": "An organization has a network-based IDS. What is a key advantage of this type of IDS?",
        "options": [
            "It can detect encrypted traffic",
            "It monitors traffic from a single host",
            "It is less expensive than host-based IDS",
            "It provides more detailed logs of user activities"
        ],
        "answer": "It can detect encrypted traffic"
    },
    {
        "question": "What is a honeypot primarily used for in cybersecurity?",
        "options": [
            "To capture and analyze malware",
            "To block unauthorized access",
            "To act as a decoy for attackers",
            "To enhance network speed"
        ],
        "answer": "To act as a decoy for attackers"
    },
    {
        "question": "In a firewall configuration, what does the term 'stateful inspection' refer to?",
        "options": [
            "Monitoring only incoming packets",
            "Tracking the state of active connections",
            "Blocking traffic based on static rules",
            "Allowing all traffic by default"
        ],
        "answer": "Tracking the state of active connections"
    },
    {
        "question": "Which type of IDS operates at the application layer of the OSI model?",
        "options": [
            "Network-based IDS",
            "Host-based IDS",
            "Application-based IDS",
            "Packet-filtering IDS"
        ],
        "answer": "Application-based IDS"
    },
    {
        "question": "A company is utilizing a firewall that restricts traffic based on specific attributes such as IP address and port number. What type of firewall is being described?",
        "options": [
            "Proxy firewall",
            "Packet-filtering firewall",
            "Stateful firewall",
            "Next-generation firewall"
        ],
        "answer": "Packet-filtering firewall"
    },
    {
        "question": "When an attacker successfully bypasses a firewall, what is this process commonly referred to as?",
        "options": [
            "Firewall evasion",
            "Intrusion detection",
            "Network segmentation",
            "Packet spoofing"
        ],
        "answer": "Firewall evasion"
    },
    {
        "question": "What is the main function of an IPS in a network security environment?",
        "options": [
            "To log user activities",
            "To actively block detected threats",
            "To provide VPN services",
            "To monitor bandwidth usage"
        ],
        "answer": "To actively block detected threats"
    },
    {
        "question": "A penetration tester is assessing a company’s use of a honeypot. What characteristic distinguishes a honeypot from a regular server?",
        "options": [
            "It has real user data",
            "It is intentionally vulnerable",
            "It provides real-time data encryption",
            "It hosts critical business applications"
        ],
        "answer": "It is intentionally vulnerable"
    },
    {
        "question": "Which of the following is NOT a characteristic of an IDS?",
        "options": [
            "Passive monitoring",
            "Real-time alerting",
            "Traffic blocking capabilities",
            "Log analysis"
        ],
        "answer": "Traffic blocking capabilities"
    },
    {
        "question": "An organization implements a honeypot that captures and analyzes attack vectors. What is a significant advantage of this approach?",
        "options": [
            "Reduced attack surface",
            "Direct protection of assets",
            "Valuable insights into attacker behavior",
            "Increased network performance"
        ],
        "answer": "Valuable insights into attacker behavior"
    },
    {
        "question": "A company has implemented an IPS that utilizes signatures to detect known threats. What is the main drawback of this approach?",
        "options": [
            "It can generate a high number of false positives",
            "It cannot detect unknown threats",
            "It is very expensive to maintain",
            "It slows down network traffic significantly"
        ],
        "answer": "It cannot detect unknown threats"
    },
    {
        "question": "During a network security audit, an analyst finds a poorly configured firewall. What might be the risk associated with this configuration?",
        "options": [
            "Enhanced network performance",
            "Increased likelihood of unauthorized access",
            "Better detection of threats",
            "Improved user experience"
        ],
        "answer": "Increased likelihood of unauthorized access"
    },
    {
        "question": "What is a common method used to evade detection by an IDS?",
        "options": [
            "Encryption of payloads",
            "Using standard protocols",
            "Increased logging",
            "Employing strong passwords"
        ],
        "answer": "Encryption of payloads"
    },
    {
        "question": "Which term describes the process of gathering information from a honeypot about the attacker’s techniques and tools?",
        "options": [
            "Threat intelligence",
            "Attack simulation",
            "Incident response",
            "Forensics analysis"
        ],
        "answer": "Threat intelligence"
    },
    {
        "question": "A network administrator wants to ensure that only authorized users can access the network. Which device is most appropriate for this purpose?",
        "options": [
            "Router",
            "Honeypot",
            "Firewall",
            "Switch"
        ],
        "answer": "Firewall"
    },
    {
        "question": "In which scenario would a host-based IDS be more beneficial than a network-based IDS?",
        "options": [
            "When monitoring internal network traffic",
            "When detecting threats from external sources",
            "When logging packet-level data",
            "When monitoring a specific server's activity"
        ],
        "answer": "When monitoring a specific server's activity"
    },
    {
        "question": "What is one of the primary challenges of implementing an IDS in a cloud environment?",
        "options": [
            "Increased latency",
            "Limited access to network data",
            "Higher cost of deployment",
            "Difficulty in maintaining signatures"
        ],
        "answer": "Limited access to network data"
    },
    {
        "question": "During an attack simulation, an attacker targets a firewall’s configuration. What is the goal of this type of attack?",
        "options": [
            "To enhance network security",
            "To gather user credentials",
            "To bypass security controls",
            "To encrypt sensitive data"
        ],
        "answer": "To bypass security controls"
    },
    {
        "question": "An organization’s firewall is configured to allow all outgoing traffic but restricts incoming traffic. What type of firewall policy is this?",
        "options": [
            "Whitelist policy",
            "Blacklist policy",
            "Default allow policy",
            "Default deny policy"
        ],
        "answer": "Default allow policy"
    },
    {
        "question": "A pen tester finds that the IDS in place generates too many alerts, overwhelming the security team. What term describes this situation?",
        "options": [
            "Alert fatigue",
            "False negative",
            "False positive",
            "Overblocking"
        ],
        "answer": "Alert fatigue"
    },
    {
        "question": "Which of the following actions can enhance the effectiveness of an IDS?",
        "options": [
            "Disabling logging features",
            "Regularly updating signatures",
            "Reducing monitoring frequency",
            "Implementing weaker encryption"
        ],
        "answer": "Regularly updating signatures"
    },
    {
        "question": "What is the primary role of a next-generation firewall?",
        "options": [
            "To replace traditional firewalls",
            "To block all traffic by default",
            "To provide advanced features like application awareness",
            "To encrypt all outgoing traffic"
        ],
        "answer": "To provide advanced features like application awareness"
    },
    {
        "question": "A company implements a solution to monitor its network for intrusions. Which type of system is this?",
        "options": [
            "Firewall",
            "IDS",
            "NAC",
            "Honeypot"
        ],
        "answer": "IDS"
    },
    {
        "question": "An organization is experiencing frequent false positives from its IPS. What might be a recommended solution?",
        "options": [
            "Increase the number of alerts",
            "Fine-tune the IPS rules and signatures",
            "Disable the IPS",
            "Switch to a host-based solution"
        ],
        "answer": "Fine-tune the IPS rules and signatures"
    },
    {
        "question": "A penetration test reveals that the company’s firewall is allowing unauthorized traffic. What is a potential fix?",
        "options": [
            "Implement stronger encryption",
            "Update the firewall rules to block the traffic",
            "Increase the bandwidth",
            "Add more logging capabilities"
        ],
        "answer": "Update the firewall rules to block the traffic"
    },
    {
        "question": "During a security assessment, a pen tester finds an open honeypot. What is the best action for the organization?",
        "options": [
            "Leave it as is to gather data",
            "Secure it to prevent data leakage",
            "Disable the honeypot entirely",
            "Make it publicly accessible"
        ],
        "answer": "Secure it to prevent data leakage"
    },
    {
        "question": "An organization uses a cloud-based IDS. What is a potential drawback of this solution?",
        "options": [
            "It can detect internal threats effectively",
            "It may have latency issues",
            "It requires on-premise hardware",
            "It is less scalable"
        ],
        "answer": "It may have latency issues"
    },
    {
        "question": "A company notices a spike in network traffic that corresponds with a security incident. Which solution can help identify the source of the traffic?",
        "options": [
            "Honeypot",
            "Packet capture",
            "NAC",
            "DLP"
        ],
        "answer": "Packet capture"
    },
    {
        "question": "What feature of a next-generation firewall distinguishes it from traditional firewalls?",
        "options": [
            "Packet filtering",
            "Application awareness",
            "Stateful inspection",
            "VPN support"
        ],
        "answer": "Application awareness"
    },
    {
        "question": "An organization is concerned about insider threats. Which security measure would be most effective?",
        "options": [
            "Implementing a honeypot",
            "Using a host-based IDS",
            "Enhancing perimeter firewalls",
            "Employing a packet-filtering firewall"
        ],
        "answer": "Using a host-based IDS"
    },
    {
        "question": "A company has a dedicated team for managing their security infrastructure. Which of the following solutions is most likely to benefit them?",
        "options": [
            "Static firewall rules",
            "Automated IDS/IPS management tools",
            "Passive monitoring systems",
            "Honeypots without analysis"
        ],
        "answer": "Automated IDS/IPS management tools"
    },
    {
        "question": "What is a recommended practice for maintaining the effectiveness of an IPS?",
        "options": [
            "Regularly change passwords",
            "Conduct periodic vulnerability assessments",
            "Ignore minor alerts",
            "Use the default configuration"
        ],
        "answer": "Conduct periodic vulnerability assessments"
    },
    {
        "question": "A business implements a NAC solution to enforce security policies. What is the primary function of NAC?",
        "options": [
            "To monitor external traffic",
            "To manage network devices",
            "To control endpoint access based on security compliance",
            "To replace firewalls"
        ],
        "answer": "To control endpoint access based on security compliance"
    },
    {
        "question": "Which of the following is a best practice when deploying a honeypot?",
        "options": [
            "Making it a replica of critical servers",
            "Isolating it from production systems",
            "Allowing all types of traffic",
            "Disabling logging for privacy"
        ],
        "answer": "Isolating it from production systems"
    },
    {
        "question": "An organization notices that their IDS is being overwhelmed by traffic. What is a potential solution?",
        "options": [
            "Increase bandwidth",
            "Implement traffic filtering",
            "Disable the IDS temporarily",
            "Switch to a packet-filtering firewall"
        ],
        "answer": "Implement traffic filtering"
    },
    {
        "question": "A network administrator is concerned about the threat of zero-day attacks. What solution would provide the best protection?",
        "options": [
            "Signature-based IDS",
            "Behavioral-based IPS",
            "Static firewall rules",
            "NAT configuration"
        ],
        "answer": "Behavioral-based IPS"
    },
    {
        "question": "When assessing the effectiveness of a firewall, which metric is crucial to evaluate?",
        "options": [
            "User satisfaction",
            "Traffic throughput",
            "Number of alerts generated",
            "Firewall uptime"
        ],
        "answer": "Traffic throughput"
    },
    {
        "question": "In what scenario would a company deploy a hybrid IDS/IPS solution?",
        "options": [
            "To lower costs",
            "To maximize detection and prevention capabilities",
            "To simplify security management",
            "To eliminate the need for firewalls"
        ],
        "answer": "To maximize detection and prevention capabilities"
    },
    {
        "question": "What is a common vulnerability that could be exploited in a poorly configured firewall?",
        "options": [
            "Weak encryption standards",
            "Open ports that should be closed",
            "Outdated software",
            "Lack of network segmentation"
        ],
        "answer": "Open ports that should be closed"
    },
    {
        "question": "An organization decides to implement a web application firewall (WAF). What is its primary purpose?",
        "options": [
            "To encrypt data at rest",
            "To filter and monitor HTTP traffic",
            "To prevent insider threats",
            "To block all incoming traffic"
        ],
        "answer": "To filter and monitor HTTP traffic"
    },
    {
        "question": "A penetration tester is tasked with assessing a company’s IDS. What technique can they use to test its effectiveness?",
        "options": [
            "Social engineering",
            "Traffic generation tools",
            "Weak password enforcement",
            "Disabling the IDS"
        ],
        "answer": "Traffic generation tools"
    },
    {
        "question": "Which tool can assist an organization in analyzing traffic patterns and identifying anomalies?",
        "options": [
            "SIEM",
            "Honeypot",
            "NAC",
            "DLP"
        ],
        "answer": "SIEM"
    },
    {
        "question": "An analyst is investigating multiple alerts triggered by the IDS. What is the most effective way to determine if an actual breach occurred?",
        "options": [
            "Increase the alert threshold",
            "Cross-reference alerts with system logs",
            "Ignore the alerts",
            "Reset the IDS"
        ],
        "answer": "Cross-reference alerts with system logs"
    },
    {
        "question": "Which method can be used to improve the performance of an IPS during a high-volume attack?",
        "options": [
            "Implement rate limiting",
            "Disable all alerts",
            "Switch to a honeypot",
            "Increase logging frequency"
        ],
        "answer": "Implement rate limiting"
    },
    {
        "question": "What is the key advantage of deploying a cloud-based security solution over an on-premise solution?",
        "options": [
            "Lower costs",
            "Improved scalability",
            "Greater control over data",
            "Enhanced security"
        ],
        "answer": "Improved scalability"
    },
    {
        "question": "Which solution can automatically enforce security policies across network devices?",
        "options": [
            "Firewall",
            "NAC",
            "IDS",
            "Honeypot"
        ],
        "answer": "NAC"
    },
    {
        "question": "An attacker uses packet fragmentation to bypass an IDS. What is this technique known as?",
        "options": [
            "Evasion technique",
            "Protocol manipulation",
            "Traffic obfuscation",
            "Data exfiltration"
        ],
        "answer": "Evasion technique"
    },
    {
        "question": "A security team discovers that their IDS fails to detect a particular type of payload. What is this issue called?",
        "options": [
            "False positive",
            "False negative",
            "Zero-day exploit",
            "Signature mismatch"
        ],
        "answer": "False negative"
    },
    {
        "question": "What can be used to obfuscate payloads in order to evade an IDS?",
        "options": [
            "Encryption",
            "Traffic shaping",
            "Firewalls",
            "Access control lists"
        ],
        "answer": "Encryption"
    },
    {
        "question": "During a red team exercise, the team successfully bypasses an IDS by using custom scripts. What is this an example of?",
        "options": [
            "Signature evasion",
            "Protocol fuzzing",
            "Anomaly evasion",
            "Payload manipulation"
        ],
        "answer": "Signature evasion"
    },
    {
        "question": "A company’s IDS relies solely on signature-based detection. What is a major vulnerability of this approach?",
        "options": [
            "It is resource-intensive",
            "It cannot detect known threats",
            "It is easily bypassed by new attack vectors",
            "It generates too many false positives"
        ],
        "answer": "It is easily bypassed by new attack vectors"
    },
    {
        "question": "An attacker encodes malicious payloads in different formats to evade detection. What is this practice called?",
        "options": [
            "Data encoding",
            "Traffic manipulation",
            "Payload encoding",
            "Signature obfuscation"
        ],
        "answer": "Payload encoding"
    },
    {
        "question": "An IDS is detecting unusual traffic patterns. What is a potential way an attacker might be evading detection?",
        "options": [
            "Using strong passwords",
            "IP address spoofing",
            "Conducting regular audits",
            "Implementing firewalls"
        ],
        "answer": "IP address spoofing"
    },
    {
        "question": "Which technique can attackers use to make malicious traffic appear legitimate to an IDS?",
        "options": [
            "Encrypting traffic",
            "Increased logging",
            "User training",
            "Network segmentation"
        ],
        "answer": "Encrypting traffic"
    },
    {
        "question": "What type of attack is characterized by sending fragmented packets to bypass IDS detection?",
        "options": [
            "Denial of Service",
            "Packet fragmentation attack",
            "Replay attack",
            "Man-in-the-middle attack"
        ],
        "answer": "Packet fragmentation attack"
    },
    {
        "question": "An organization uses behavior-based detection in their IDS. What advantage does this provide?",
        "options": [
            "Lower costs",
            "Detection of zero-day attacks",
            "Reduced false positives",
            "Simplified management"
        ],
        "answer": "Detection of zero-day attacks"
    },
    {
        "question": "A security analyst finds that their IDS is not detecting certain types of traffic. What is a likely reason for this?",
        "options": [
            "Outdated signatures",
            "Overly complex rules",
            "Too many false positives",
            "Network congestion"
        ],
        "answer": "Outdated signatures"
    },
    {
        "question": "An attacker uses timing attacks to evade detection. What does this technique rely on?",
        "options": [
            "The speed of packet transmission",
            "The timing of responses",
            "The volume of traffic",
            "The encryption method used"
        ],
        "answer": "The timing of responses"
    },
    {
        "question": "When an IDS is configured with overly broad rules, what is the likely outcome?",
        "options": [
            "Increased detection rates",
            "Higher likelihood of false positives",
            "Decreased network speed",
            "Better user experience"
        ],
        "answer": "Higher likelihood of false positives"
    },
    {
        "question": "An attacker decides to send data over non-standard ports to avoid detection. What is this technique known as?",
        "options": [
            "Port scanning",
            "Protocol tunneling",
            "Traffic obfuscation",
            "Packet filtering"
        ],
        "answer": "Protocol tunneling"
    },
    {
        "question": "A security team implements a new IDS that relies on heuristic analysis. What is a key benefit of this approach?",
        "options": [
            "High accuracy for known threats",
            "Ability to learn from network patterns",
            "Reduced resource consumption",
            "Simplified rule management"
        ],
        "answer": "Ability to learn from network patterns"
    },
    {
        "question": "An attacker uses SSL/TLS to encrypt their traffic. What is the primary reason for doing this?",
        "options": [
            "To increase bandwidth",
            "To evade IDS detection",
            "To enhance performance",
            "To simplify access control"
        ],
        "answer": "To evade IDS detection"
    },
    {
        "question": "What is a common way to detect if an attacker is using evasion techniques against an IDS?",
        "options": [
            "Monitoring for high traffic volumes",
            "Analyzing packet contents",
            "Implementing stricter access controls",
            "Using honeypots"
        ],
        "answer": "Analyzing packet contents"
    },
    {
        "question": "A company employs a solution that flags anomalies in traffic. What is this method of detection called?",
        "options": [
            "Signature-based detection",
            "Anomaly-based detection",
            "Behavioral detection",
            "Heuristic detection"
        ],
        "answer": "Anomaly-based detection"
    },
    {
        "question": "In what scenario would an attacker most likely use a decoy to evade an IDS?",
        "options": [
            "During a physical break-in",
            "When conducting a DDoS attack",
            "While exploiting a vulnerability",
            "To mislead incident responders"
        ],
        "answer": "To mislead incident responders"
    },
    {
        "question": "An organization finds that their IDS alerts are often triggered by benign activities. What might be a cause of this?",
        "options": [
            "Poorly configured rules",
            "High bandwidth usage",
            "Inadequate logging",
            "No network segmentation"
        ],
        "answer": "Poorly configured rules"
    },
    {
        "question": "An attacker modifies packet headers to bypass a firewall. What is this technique called?",
        "options": [
            "Spoofing",
            "Evasion",
            "Encryption",
            "Obfuscation"
        ],
        "answer": "Spoofing"
    },
    {
        "question": "A network administrator notices that a specific port is left open on the firewall. What is the risk associated with this?",
        "options": [
            "Increased network speed",
            "Potential unauthorized access",
            "Enhanced traffic monitoring",
            "Improved user experience"
        ],
        "answer": "Potential unauthorized access"
    },
    {
        "question": "A company uses a NAC solution to control access to its network. What is a primary benefit of NAC?",
        "options": [
            "It simplifies user authentication",
            "It prevents all external attacks",
            "It ensures devices meet security policies before accessing the network",
            "It eliminates the need for firewalls"
        ],
        "answer": "It ensures devices meet security policies before accessing the network"
    },
    {
        "question": "An organization implements a firewall rule that allows all outgoing traffic. What is a potential downside of this configuration?",
        "options": [
            "Increased security risks",
            "Reduced network performance",
            "Easier management",
            "Fewer alerts generated"
        ],
        "answer": "Increased security risks"
    },
    {
        "question": "An attacker uses a method to change their source IP address to bypass a firewall. What is this technique known as?",
        "options": [
            "IP spoofing",
            "Traffic shaping",
            "Packet filtering",
            "Protocol manipulation"
        ],
        "answer": "IP spoofing"
    },
    {
        "question": "What is the primary function of a next-generation firewall compared to a traditional firewall?",
        "options": [
            "Packet filtering",
            "Basic logging",
            "Deep packet inspection",
            "Simple rule management"
        ],
        "answer": "Deep packet inspection"
    },
    {
        "question": "A company configures its firewall to block all traffic except that which is explicitly allowed. What type of policy is this?",
        "options": [
            "Default allow policy",
            "Default deny policy",
            "Whitelist policy",
            "Blacklist policy"
        ],
        "answer": "Default deny policy"
    },
    {
        "question": "An organization wants to prevent unauthorized access through its firewall. What is the most effective action?",
        "options": [
            "Open all ports by default",
            "Regularly update firewall rules and policies",
            "Disable logging",
            "Allow all traffic from internal sources"
        ],
        "answer": "Regularly update firewall rules and policies"
    },
    {
        "question": "What type of firewall operates at the application layer and can provide detailed logging of traffic?",
        "options": [
            "Stateful firewall",
            "Packet-filtering firewall",
            "Proxy firewall",
            "Next-generation firewall"
        ],
        "answer": "Proxy firewall"
    },
    {
        "question": "A company has deployed a NAC solution that fails to block non-compliant devices. What is a likely cause of this failure?",
        "options": [
            "Improper configuration of NAC policies",
            "Outdated security software",
            "Too many devices on the network",
            "Lack of user training"
        ],
        "answer": "Improper configuration of NAC policies"
    },
    {
        "question": "When configuring a firewall, what is an important consideration for preventing unauthorized access?",
        "options": [
            "Allowing all incoming traffic",
            "Using strong, unique passwords for administrative access",
            "Setting weak encryption standards",
            "Ignoring logging features"
        ],
        "answer": "Using strong, unique passwords for administrative access"
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
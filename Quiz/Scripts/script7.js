
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "During a recent engagement, a penetration tester discovers that a company’s network has been compromised by an attacker who has gained persistent access. The attacker is using specialized malware to maintain control over the system, avoiding detection by using custom encryption methods for its communications. What type of malware is most likely involved in this situation?",
        "options": [
            "Trojan",
            "RAT (Remote Access Trojan)",
            "Fileless Malware",
            "Advanced Persistent Threat (APT)"
        ],
        "answer": "Advanced Persistent Threat (APT)"
    },
    {
        "question": "A company’s security team detects unusual network traffic from an internal server to an external IP address. Further investigation reveals that a piece of malware is running on the server, collecting sensitive data and sending it to an external location. The malware was specifically designed to evade traditional signature-based detection methods. What is the most likely type of malware being used?",
        "options": [
            "Worm",
            "Spyware",
            "Rootkit",
            "Fileless Malware"
        ],
        "answer": "Fileless Malware"
    },
    {
        "question": "During an investigation, an analyst finds that a piece of malware is using the operating system’s legitimate functions to execute malicious actions without leaving traces on the disk. The malware injects itself directly into the memory and uses in-memory techniques to avoid detection. Which type of malware is most likely involved?",
        "options": [
            "Trojan",
            "Rootkit",
            "Fileless Malware",
            "Worm"
        ],
        "answer": "Fileless Malware"
    },
    {
        "question": "A security analyst is reviewing a newly discovered malware strain. After thorough analysis, the malware is found to be able to self-replicate and propagate across the network without requiring any user interaction. What type of malware is the analyst most likely dealing with?",
        "options": [
            "Trojan",
            "Virus",
            "Worm",
            "Ransomware"
        ],
        "answer": "Worm"
    },
    {
        "question": "During a malware analysis, an analyst discovers that a piece of malware has infected a system and is sending back system information, including the host’s location and installed software. The malware uses a backdoor that allows an attacker to control the system remotely. What is the most likely type of malware?",
        "options": [
            "Spyware",
            "Trojan",
            "RAT (Remote Access Trojan)",
            "Adware"
        ],
        "answer": "RAT (Remote Access Trojan)"
    },
    {
        "question": "A penetration tester receives a suspicious email attachment labeled as a PDF file. Upon opening the file, malicious code is executed on the system, and the system begins to behave unusually, sending outbound traffic to an external server. What type of malware is most likely delivered by this file?",
        "options": [
            "Trojan",
            "Worm",
            "Ransomware",
            "Virus"
        ],
        "answer": "Trojan"
    },
    {
        "question": "A security analyst discovers that a piece of malware is replicating itself across multiple systems in the corporate network without any user intervention. The malware is exploiting a vulnerability in the operating system’s network protocol. Which type of malware is the analyst dealing with?",
        "options": [
            "Ransomware",
            "Trojan",
            "Worm",
            "Rootkit"
        ],
        "answer": "Worm"
    },
    {
        "question": "An organization has been infected with malware that encrypts files on its systems, demanding a ransom for the decryption key. This malware is preventing users from accessing their important data unless a ransom is paid. What type of malware is this?",
        "options": [
            "Trojan",
            "Ransomware",
            "Spyware",
            "Worm"
        ],
        "answer": "Ransomware"
    },
    {
        "question": "A hacker is using a sophisticated form of malware to exploit a vulnerability in the operating system. The malware injects malicious code directly into kernel-level processes, hiding its presence and manipulating system operations. What type of malware is most likely being used?",
        "options": [
            "Spyware",
            "Rootkit",
            "Worm",
            "Trojan"
        ],
        "answer": "Rootkit"
    },
    {
        "question": "A security analyst is reviewing a malware sample and finds that it contains an embedded keylogger that logs keystrokes on the infected system. The malware then sends these keystrokes to an external server. What type of malware is this?",
        "options": [
            "Spyware",
            "Trojan",
            "Keylogger",
            "Adware"
        ],
        "answer": "Keylogger"
    },
    {
        "question": "While conducting an analysis of malware samples, an analyst finds a piece of code that appears to have no harmful behavior initially. However, when the system becomes idle, the malware activates, consuming system resources and causing the system to slow down. What type of malware is most likely responsible for this behavior?",
        "options": [
            "Spyware",
            "Adware",
            "Rootkit",
            "Ransomware"
        ],
        "answer": "Adware"
    },
    {
        "question": "A penetration tester discovers that a newly deployed system is infected with malware that manipulates system logs, making it difficult for investigators to determine the nature of the attack. This malware is specifically designed to hide its tracks. What type of malware is most likely responsible for this behavior?",
        "options": [
            "Trojan",
            "Rootkit",
            "Worm",
            "Spyware"
        ],
        "answer": "Rootkit"
    },
    {
        "question": "An organization recently experienced a malware infection that involved a malicious payload being delivered to its users through a phishing email. The email contained a link to a fake login page that harvested credentials. What type of malware is most likely responsible for this incident?",
        "options": [
            "Spyware",
            "Trojan",
            "Phishing",
            "Keylogger"
        ],
        "answer": "Trojan"
    },
    {
        "question": "Sarah is conducting a security audit and discovers a vulnerability in a company’s web application where user input in a search box is not properly sanitized. This leads to unauthorized database queries. What type of vulnerability is most likely present?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "Path Traversal"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "During a penetration test, Max discovers a web application that fails to validate user-uploaded files. He uploads a malicious file and executes arbitrary code on the server. What kind of attack is Max likely conducting?",
        "options": [
            "Command Injection",
            "Remote File Inclusion",
            "Arbitrary File Upload",
            "Buffer Overflow"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "A hacker is exploiting a vulnerability in a web application that allows the inclusion of remote files using user input. After including the file, the attacker is able to run arbitrary code on the server. Which type of attack is the hacker conducting?",
        "options": [
            "Remote File Inclusion",
            "Local File Inclusion",
            "SQL Injection",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Remote File Inclusion"
    },
    {
        "question": "Max, a penetration tester, is trying to exploit a vulnerability in a network device that is improperly configured, allowing him to send specially crafted packets to the device and crash it. What type of attack is Max performing?",
        "options": [
            "Denial of Service (DoS)",
            "Man-in-the-Middle (MitM)",
            "Spoofing",
            "Buffer Overflow"
        ],
        "answer": "Denial of Service (DoS)"
    },
    {
        "question": "An attacker is able to intercept and manipulate packets between two communicating devices to eavesdrop on sensitive information. Which type of attack is the attacker performing?",
        "options": [
            "Denial of Service (DoS)",
            "Man-in-the-Middle (MitM)",
            "Replay Attack",
            "Evasion Attack"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "John, a penetration tester, discovers that an organization’s network firewall is improperly configured, allowing unauthorized IP addresses to access sensitive internal systems. What type of attack does this misconfiguration expose the network to?",
        "options": [
            "IP Spoofing",
            "Denial of Service",
            "SQL Injection",
            "Evasion Attack"
        ],
        "answer": "IP Spoofing"
    },
    {
        "question": "A company’s web server is being attacked by an adversary who is sending specially crafted packets that exploit a vulnerability in the web server’s network protocol, causing it to crash. Which type of attack is this?",
        "options": [
            "Denial of Service (DoS)",
            "Remote Code Execution",
            "Cross-Site Scripting (XSS)",
            "SQL Injection"
        ],
        "answer": "Denial of Service (DoS)"
    },
    {
        "question": "An attacker is using a keylogger to capture all keystrokes on a victim's computer. The keylogger sends these keystrokes to a remote server. Which type of malware is the attacker using?",
        "options": [
            "Spyware",
            "Trojan",
            "RAT",
            "Keylogger"
        ],
        "answer": "Keylogger"
    },
    {
        "question": "An attacker injects malicious JavaScript code into a website, allowing them to steal session cookies from legitimate users. What type of attack is the attacker conducting?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Command Injection",
            "Buffer Overflow"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "Max is analyzing an exploit for a vulnerability in a web application. The exploit uses a script embedded in a webpage to trick the victim into running it. Which type of attack does this describe?",
        "options": [
            "Cross-Site Request Forgery (CSRF)",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Man-in-the-Middle (MitM)"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "A company’s network is compromised, and an attacker has gained unauthorized access to several systems. The attacker is now using a backdoor to maintain persistent access. What type of malware is most likely being used to establish this backdoor?",
        "options": [
            "Worm",
            "Trojan",
            "Rootkit",
            "Spyware"
        ],
        "answer": "Rootkit"
    },
    {
        "question": "An attacker deploys a malicious script that automatically activates when a user visits a compromised website. The script gathers sensitive data, such as browser history and cookies. What type of attack is being performed?",
        "options": [
            "Drive-by Download",
            "Phishing",
            "SQL Injection",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Drive-by Download"
    },
    {
        "question": "A hacker is able to exploit an unpatched vulnerability in a company’s email server, allowing him to inject malicious code into the email content. What type of attack is the hacker likely executing?",
        "options": [
            "Email Spoofing",
            "Phishing",
            "Cross-Site Scripting (XSS)",
            "Email Injection"
        ],
        "answer": "Email Injection"
    },
    {
        "question": "An attacker compromises a website and injects malicious JavaScript code into its forms. When legitimate users submit the forms, the attacker is able to execute unauthorized commands. What is this type of attack called?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Command Injection",
            "Buffer Overflow"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "An attacker is attempting to gain control of a victim's computer by sending malicious payloads that exploit vulnerabilities in the operating system. The payload is executed without the victim's knowledge. What type of attack is the attacker conducting?",
        "options": [
            "Rootkit Installation",
            "Trojan Deployment",
            "Ransomware Attack",
            "Buffer Overflow"
        ],
        "answer": "Trojan Deployment"
    },
    {
        "question": "Max is analyzing a newly discovered malware sample. He notices that the malware is able to spread across the network without user interaction and infect other systems by exploiting a known vulnerability in the network protocol. What type of malware is Max most likely analyzing?",
        "options": [
            "Worm",
            "Trojan",
            "Spyware",
            "Ransomware"
        ],
        "answer": "Worm"
    },
    {
        "question": "A security analyst finds that a piece of malware is disguising its activities by injecting itself into legitimate processes, hiding its presence from security tools. What type of malware is likely used in this scenario?",
        "options": [
            "Rootkit",
            "Trojan",
            "RAT",
            "Worm"
        ],
        "answer": "Rootkit"
    },
    {
        "question": "A company’s web application is under attack. The attacker is injecting malicious scripts into web forms that run in the users' browsers. These scripts are designed to steal cookies and session tokens. What type of attack is being carried out?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Command Injection",
            "Session Fixation"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "An attacker is using a tool to flood a target web server with a massive amount of requests in an attempt to make the server unavailable to legitimate users. What type of attack is the attacker performing?",
        "options": [
            "Distributed Denial of Service (DDoS)",
            "Man-in-the-Middle (MitM)",
            "DNS Spoofing",
            "SQL Injection"
        ],
        "answer": "Distributed Denial of Service (DDoS)"
    },
    {
        "question": "Max is performing a network assessment and discovers that an attacker has gained unauthorized access by exploiting an unpatched vulnerability in a router. The attacker is now able to intercept and modify traffic. What type of attack is the attacker using?",
        "options": [
            "Packet Sniffing",
            "Man-in-the-Middle (MitM)",
            "Replay Attack",
            "Denial of Service (DoS)"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "John notices that a malware sample is designed to make the target system unusable by flooding it with excessive traffic, causing a crash. What type of attack is being carried out?",
        "options": [
            "Denial of Service (DoS)",
            "Worm",
            "SQL Injection",
            "Buffer Overflow"
        ],
        "answer": "Denial of Service (DoS)"
    },
    {
        "question": "A hacker is using a social engineering attack to trick employees into revealing their passwords by sending them a phishing email. The email contains a link to a fake login page. What type of attack is this?",
        "options": [
            "Phishing",
            "Ransomware",
            "SQL Injection",
            "Man-in-the-Middle (MitM)"
        ],
        "answer": "Phishing"
    },
    {
        "question": "During a penetration test, Max discovers a flaw in a web application that allows an attacker to execute arbitrary commands on the server by sending a specially crafted input. What type of vulnerability is Max exploiting?",
        "options": [
            "Command Injection",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Path Traversal"
        ],
        "answer": "Command Injection"
    },
    {
        "question": "During a network penetration test, an attacker is able to perform ARP spoofing to intercept traffic between two devices on a local network. What type of attack is this?",
        "options": [
            "Man-in-the-Middle (MitM)",
            "Denial of Service (DoS)",
            "Replay Attack",
            "Session Hijacking"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "John is reviewing a web application that allows users to submit feedback through a form. He notices that the input is not validated properly, and it allows HTML tags. He submits a form with an embedded script that executes in users’ browsers. What type of attack is John conducting?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Buffer Overflow",
            "Command Injection"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "A penetration tester has identified a web application vulnerability where users can upload files, and the system does not check file extensions or contents. After uploading a malicious file, the tester executes commands on the server. What type of vulnerability is this?",
        "options": [
            "Arbitrary File Upload",
            "SQL Injection",
            "Remote Code Execution",
            "Directory Traversal"
        ],
        "answer": "Arbitrary File Upload"
    },
    {
        "question": "An attacker is attempting to compromise an email server by sending emails with malicious scripts embedded in the email content. The script automatically downloads and executes malicious code when the recipient opens the email. What type of attack is this?",
        "options": [
            "Phishing",
            "Email Injection",
            "Drive-by Download",
            "Email Spoofing"
        ],
        "answer": "Drive-by Download"
    },
    {
        "question": "An attacker has exploited a vulnerability in a server and is now using a script to gather sensitive information, including usernames and passwords, by continuously sending requests to the server. What type of attack is the attacker conducting?",
        "options": [
            "Brute Force Attack",
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Password Spraying"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "A security analyst discovers that a piece of malware is designed to gather and send sensitive data from an infected system, but it is specifically targeting user credentials from saved web browsers. What type of malware is this?",
        "options": [
            "RAT (Remote Access Trojan)",
            "Keylogger",
            "Spyware",
            "Adware"
        ],
        "answer": "Spyware"
    },
    {
        "question": "A company’s server has been compromised, and an attacker has planted a malicious payload that encrypts files on the system and demands a ransom for the decryption key. What type of malware is this?",
        "options": [
            "Ransomware",
            "Worm",
            "Spyware",
            "Rootkit"
        ],
        "answer": "Ransomware"
    },
    {
        "question": "An attacker deploys a malware strain that propagates across the network, exploiting unpatched vulnerabilities to infect multiple systems automatically. What type of malware is the attacker using?",
        "options": [
            "Worm",
            "Trojan",
            "RAT",
            "Virus"
        ],
        "answer": "Worm"
    },
    {
        "question": "An attacker gains unauthorized access to a target system by exploiting a vulnerability in an outdated network protocol. The attacker then uses this access to launch a man-in-the-middle attack. What kind of attack is the attacker performing?",
        "options": [
            "Session Hijacking",
            "Man-in-the-Middle (MitM)",
            "Spoofing",
            "Phishing"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "While reviewing the traffic logs, you notice a suspicious packet with an incorrect checksum. The attacker is likely trying to manipulate or bypass network defenses. What type of attack is the attacker conducting?",
        "options": [
            "Denial of Service (DoS)",
            "Replay Attack",
            "Fragmentation Attack",
            "Session Fixation"
        ],
        "answer": "Fragmentation Attack"
    },
    {
        "question": "An attacker uses a tool to flood a target’s server with an excessive number of requests, overwhelming its resources. What type of attack is the attacker performing?",
        "options": [
            "Distributed Denial of Service (DDoS)",
            "Man-in-the-Middle (MitM)",
            "SQL Injection",
            "Session Hijacking"
        ],
        "answer": "Distributed Denial of Service (DDoS)"
    },
    {
        "question": "Max is performing a penetration test on a network where he discovers a vulnerability in the DNS server that allows the attacker to respond to DNS queries with malicious IP addresses. What type of attack is Max most likely witnessing?",
        "options": [
            "DNS Spoofing",
            "ARP Spoofing",
            "Man-in-the-Middle (MitM)",
            "Phishing"
        ],
        "answer": "DNS Spoofing"
    },
    {
        "question": "An attacker has gained access to a victim’s computer and is intercepting communication between two devices on the same local network. The attacker is then able to modify or inject data into the communication. What type of attack is the attacker conducting?",
        "options": [
            "Denial of Service",
            "Man-in-the-Middle (MitM)",
            "Buffer Overflow",
            "SQL Injection"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "During a vulnerability assessment, you discover that an organization’s firewall is improperly configured and allows a TCP connection on port 443, which is typically used for secure communications. What type of attack does this configuration vulnerability expose the organization to?",
        "options": [
            "Session Hijacking",
            "Man-in-the-Middle (MitM)",
            "IP Spoofing",
            "Command Injection"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "An attacker injects a malicious payload into a website's comment section. When other users view the comment, the payload is executed, allowing the attacker to steal their session cookies. What type of attack is this?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Session Hijacking",
            "Phishing"
        ],
        "answer": "Cross-Site Scripting (XSS)"
    },
    {
        "question": "A penetration tester successfully executes a buffer overflow attack on an application, gaining control over the process memory. What type of attack has the tester carried out?",
        "options": [
            "Denial of Service (DoS)",
            "Buffer Overflow",
            "SQL Injection",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Buffer Overflow"
    },
    {
        "question": "An attacker is sending a large amount of invalid data to a target system, causing it to crash. This attack is aimed at disrupting the normal functioning of the system. What type of attack is the attacker performing?",
        "options": [
            "Denial of Service (DoS)",
            "SQL Injection",
            "Session Hijacking",
            "Command Injection"
        ],
        "answer": "Denial of Service (DoS)"
    },
    {
        "question": "A penetration tester is reviewing network traffic and finds that some packets are being intercepted and altered without the knowledge of the legitimate users. What type of attack is the attacker most likely performing?",
        "options": [
            "Denial of Service (DoS)",
            "Man-in-the-Middle (MitM)",
            "IP Spoofing",
            "Session Fixation"
        ],
        "answer": "Man-in-the-Middle (MitM)"
    },
    {
        "question": "An attacker uses a tool to repeatedly send multiple login requests with different passwords to an application’s login page in an attempt to gain access to a system. What type of attack is the attacker performing?",
        "options": [
            "Brute Force Attack",
            "Phishing",
            "Denial of Service (DoS)",
            "Cross-Site Scripting (XSS)"
        ],
        "answer": "Brute Force Attack"
    },
    {
        "question": "A hacker gains unauthorized access to a system and uses a trojan horse to collect sensitive information from the system. What type of malware is being used in this scenario?",
        "options": [
            "Rootkit",
            "Trojan",
            "Spyware",
            "Adware"
        ],
        "answer": "Trojan"
    },
    {
        "question": "A network administrator is reviewing logs and notices that there are several unauthorized IP addresses making requests to an internal system. The traffic appears to be coming from a spoofed source. What type of attack is being observed?",
        "options": [
            "Denial of Service (DoS)",
            "Session Hijacking",
            "IP Spoofing",
            "Phishing"
        ],
        "answer": "IP Spoofing"
    },
    {
        "question": "A hacker has discovered an unpatched vulnerability in an organization’s web application. The hacker uses a tool to send malicious SQL queries to extract sensitive data from the database. What type of attack is this?",
        "options": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Command Injection",
            "Path Traversal"
        ],
        "answer": "SQL Injection"
    },
    {
        "question": "An attacker has compromised a vulnerable web server and installed a piece of malware that allows them to control the server remotely. What type of malware is likely being used in this scenario?",
        "options": [
            "Trojan",
            "Worm",
            "Spyware",
            "Rootkit"
        ],
        "answer": "Trojan"
    },
    {
        "question": "A hacker is using a phishing email to trick users into downloading a malicious attachment that contains ransomware. Once executed, the ransomware encrypts the victim's files and demands payment for the decryption key. What type of malware is this?",
        "options": [
            "Ransomware",
            "Worm",
            "Spyware",
            "Keylogger"
        ],
        "answer": "Ransomware"
    },
    {
        "question": "A security analyst is analyzing a network where an attacker has planted a malware strain capable of replicating itself and spreading across the network. What type of malware is this?",
        "options": [
            "Worm",
            "Trojan",
            "Virus",
            "Spyware"
        ],
        "answer": "Worm"
    },
    {
        "question": "An attacker intercepts traffic between two devices on a local network by sending forged ARP messages. What type of attack is this?",
        "options": [
            "ARP Spoofing",
            "Session Fixation",
            "DNS Spoofing",
            "Man-in-the-Middle (MitM)"
        ],
        "answer": "ARP Spoofing"
    },
    {
        "question": "A hacker uses a man-in-the-middle attack to intercept and alter sensitive data being transmitted between two devices over an unsecured Wi-Fi network. What type of attack is being executed?",
        "options": [
            "Packet Sniffing",
            "Denial of Service (DoS)",
            "Man-in-the-Middle (MitM)",
            "Phishing"
        ],
        "answer": "Man-in-the-Middle (MitM)"
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
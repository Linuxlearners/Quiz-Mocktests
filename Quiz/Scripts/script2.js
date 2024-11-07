let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "What is the primary purpose of footprinting?",
        "options": [
            "To exploit vulnerabilities in a system",
            "To gather information about a target",
            "To encrypt sensitive data",
            "To monitor network traffic"
        ],
        "answer": "To gather information about a target"
    },
    {
        "question": "Which of the following is a method to gather information from a domain's WHOIS record?",
        "options": [
            "Checking DNS records",
            "Identifying registered domain owners",
            "Analyzing server response headers",
            "Performing port scans"
        ],
        "answer": "Identifying registered domain owners"
    },
    {
        "question": "During a footprinting phase, an attacker discovers an organization’s public-facing IP range. Which technique is primarily used here?",
        "options": [
            "Social Engineering",
            "Network Scanning",
            "Email Footprinting",
            "Search Engine Footprinting"
        ],
        "answer": "Network Scanning"
    },
    {
        "question": "Max is researching a company’s online presence. He uses Google to find specific file types that may contain sensitive information. What is this technique called?",
        "options": [
            "Google Dorking",
            "Footprinting",
            "Social Engineering",
            "Malware Analysis"
        ],
        "answer": "Google Dorking"
    },
    {
        "question": "An attacker uses a social networking site to gather information about an employee's work habits and location. This technique is known as:",
        "options": [
            "Passive Footprinting",
            "Active Footprinting",
            "Social Engineering",
            "Public Information Gathering"
        ],
        "answer": "Social Engineering"
    },
    {
        "question": "What is the risk of performing a DNS zone transfer without authorization?",
        "options": [
            "Exposing sensitive data",
            "Causing a denial of service",
            "Altering DNS records",
            "None of the above"
        ],
        "answer": "Exposing sensitive data"
    },
    {
        "question": "Which of the following is NOT a tool typically used for footprinting?",
        "options": [
            "Nmap",
            "Maltego",
            "Recon-ng",
            "Wireshark"
        ],
        "answer": "Wireshark"  // Correct
    },
    {
        "question": "In email footprinting, what information can be extracted from the email headers?",
        "options": [
            "The sender’s IP address",
            "The recipient’s name",
            "The content of the email",
            "The email service provider"
        ],
        "answer": "The sender’s IP address"
    },
    {
        "question": "What type of footprinting involves collecting information through direct interaction with individuals?",
        "options": [
            "Active Footprinting",
            "Passive Footprinting",
            "Social Engineering",
            "Network Mapping"
        ],
        "answer": "Social Engineering"
    },
    {
        "question": "Which of the following methods can be used for footprinting through search engines?",
        "options": [
            "DNS Spoofing",
            "Google Dorks",
            "Port Scanning",
            "Network Sniffing"
        ],
        "answer": "Google Dorks"
    },
    {
        "question": "If a penetration tester uses DNS interrogation to discover mail servers for a target, what type of footprinting is this?",
        "options": [
            "Email Footprinting",
            "Website Footprinting",
            "DNS Footprinting",
            "Network Footprinting"
        ],
        "answer": "DNS Footprinting"
    },
    {
        "question": "What is the goal of footprinting in the context of ethical hacking?",
        "options": [
            "To exploit vulnerabilities",
            "To gather reconnaissance data",
            "To install malware",
            "To breach firewall security"
        ],
        "answer": "To gather reconnaissance data"
    },
    {
        "question": "Which of the following is a common countermeasure to mitigate the risks of footprinting?",
        "options": [
            "Using encryption",
            "Conducting employee training",
            "Implementing access controls",
            "Hiding sensitive information"
        ],
        "answer": "Implementing access controls"
    },
    {
        "question": "An attacker performs a query to find all subdomains of a target domain. This is an example of:",
        "options": [
            "Social Engineering",
            "DNS Footprinting",
            "Network Scanning",
            "Information Leakage"
        ],
        "answer": "DNS Footprinting"
    },
    {
        "question": "Which type of information can be obtained from footprinting through social media?",
        "options": [
            "Financial records",
            "Employee usernames and passwords",
            "Technical infrastructure details",
            "Employee names and job roles"
        ],
        "answer": "Employee names and job roles"
    },
    {
        "question": "What technique involves collecting data without direct interaction with the target?",
        "options": [
            "Active Footprinting",
            "Passive Footprinting",
            "Network Mapping",
            "Packet Sniffing"
        ],
        "answer": "Passive Footprinting"
    },
    {
        "question": "A penetration tester uses a web application to retrieve a list of files available on a target server. What type of footprinting is this?",
        "options": [
            "Web Application Footprinting",
            "Website Footprinting",
            "Email Footprinting",
            "Social Engineering"
        ],
        "answer": "Web Application Footprinting"
    },
    {
        "question": "During a penetration test, which tool can be used to automate the footprinting process?",
        "options": [
            "Nessus",
            "Burp Suite",
            "Maltego",
            "Wireshark"
        ],
        "answer": "Maltego"
    },
    {
        "question": "When an attacker uses a reconnaissance tool to discover network services running on a target machine, this is known as:",
        "options": [
            "Port Scanning",
            "Vulnerability Scanning",
            "Service Enumeration",
            "Footprinting"
        ],
        "answer": "Service Enumeration"  // Correct
    
    },
    {
        "question": "Which of the following is a risk associated with email footprinting?",
        "options": [
            "Phishing attacks",
            "Identity theft",
            "Information leakage",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "In the context of footprinting, what does DNS stand for?",
        "options": [
            "Dynamic Network Services",
            "Domain Name System",
            "Data Network Security",
            "Digital Name Service"
        ],
        "answer": "Domain Name System"
    },
    {
        "question": "A penetration tester conducts a search for specific file types using advanced search operators. What is this practice called?",
        "options": [
            "Google Dorking",
            "Footprinting",
            "Data Mining",
            "Information Gathering"
        ],
        "answer": "Google Dorking"
    },
    {
        "question": "An attacker uses social engineering to gain confidential information from an employee. This is an example of:",
        "options": [
            "Passive Footprinting",
            "Active Footprinting",
            "Social Engineering",
            "Network Sniffing"
        ],
        "answer": "Social Engineering"
    },
    {
        "question": "Footprinting can reveal which of the following?",
        "options": [
            "Network architecture",
            "IP address range",
            "System vulnerabilities",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is the main function of footprinting tools?",
        "options": [
            "To exploit vulnerabilities",
            "To automate vulnerability scanning",
            "To gather and analyze information about a target", // Incorrect
            "To detect malware"
        ],
        "answer": "To gather and analyze information about a target"  // Incorrect
    },
    {
        "question": "Which of the following can be a countermeasure against footprinting?",
        "options": [
            "Firewall configuration",
            "Employee education on social engineering",
            "Restricting public access to information",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "A hacker retrieves sensitive information through an unprotected DNS server. This is known as:",
        "options": [
            "DNS Spoofing",
            "DNS Zone Transfer",
            "DNS Cache Poisoning",
            "DNS Sniffing"
        ],
        "answer": "DNS Zone Transfer"
    },
    {
        "question": "What type of information is commonly collected during email footprinting?",
        "options": [
            "Sender's IP address",
            "Recipient's address",
            "Subject line",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is a common technique for extracting information from public websites?",
        "options": [
            "Web Scraping",
            "Phishing",
            "Data Injection",
            "Session Hijacking"
        ],
        "answer": "Web Scraping"
    },
    {
        "question": "What kind of information is typically NOT gathered during footprinting?",
        "options": [
            "Publicly available employee details",
            "Internal server configurations", // Incorrect
            "Domain registration details",
            "Network infrastructure details"
        ],
        "answer": "Internal server configurations"  // Incorrect
    },
    {
        "question": "An attacker finds out that a company uses a specific software version known for vulnerabilities. This information was gathered through:",
        "options": [
            "OS Fingerprinting",
            "Social Engineering",
            "Service Enumeration",
            "Network Scanning"
        ],
        "answer": "OS Fingerprinting"
    },
    {
        "question": "Which type of footprinting involves analyzing a target's website for sensitive information?",
        "options": [
            "Website Footprinting",
            "Social Engineering",
            "Network Mapping",
            "Passive Footprinting"
        ],
        "answer": "Website Footprinting"
    },
    {
        "question": "Which tool would be most effective for conducting DNS footprinting?",
        "options": [
            "Nmap",
            "nslookup",
            "Wireshark",
            "Metasploit"
        ],
        "answer": "nslookup"
    },
    {
        "question": "An organization restricts information about its employees on its website. What is this an example of?",
        "options": [
            "Good Security Practice",
            "Information Leakage",
            "Poor Footprinting",
            "Social Engineering"
        ],
        "answer": "Good Security Practice"
    },
    {
        "question": "Which of the following techniques can be employed to perform footprinting through social networking sites?",
        "options": [
            "Searching public profiles",
            "Using bots to scrape data",
            "Creating fake profiles",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What type of information can be found in a DNS record?",
        "options": [
            "IP address of the mail server",
            "Registered domain owner's contact details",
            "Subdomains",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "Which of the following best describes active footprinting?",
        "options": [
            "Gathering information without direct interaction",
            "Collecting data through direct queries and scans",
            "Using social engineering tactics",
            "Analyzing public records"
        ],
        "answer": "Collecting data through direct queries and scans"
    },
    {
        "question": "Max finds out that a company's website has a directory listing enabled, revealing sensitive files. What vulnerability does this indicate?",
        "options": [
            "Directory Traversal",
            "Sensitive Data Exposure",
            "Information Disclosure",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "What is one of the main challenges when conducting passive footprinting?",
        "options": [
            "It requires technical skills",
            "It's time-consuming",
            "Information may be outdated",
            "It can be easily detected" // Incorrect
        ],
        "answer": "Information may be outdated"  // Correct
    },
    {
        "question": "When performing footprinting, what is the significance of checking an organization’s social media presence?",
        "options": [
            "It provides real-time information",
            "It is illegal",
            "It has no value",
            "It can only provide generic information"
        ],
        "answer": "It provides real-time information"
    },
    {
        "question": "What is a common method for attackers to perform footprinting through email?",
        "options": [
            "Spoofing",
            "Phishing",
            "Analyzing email headers",
            "None of the above"
        ],
        "answer": "Analyzing email headers"
    },
    {
        "question": "An attacker discovers that an organization has a public DNS server. What potential risk does this pose?",
        "options": [
            "It can expose sensitive information.",
            "It can improve network performance.",
            "It can enhance security.",
            "It has no risks."
        ],
        "answer": "It can expose sensitive information."
    },
    {
        "question": "Which of the following methods is commonly used for website footprinting?",
        "options": [
            "Directory enumeration",
            "Social media analysis",
            "Email spoofing",
            "DNS zone transfer"
        ],
        "answer": "Directory enumeration"
    },
    {
        "question": "What kind of information can be found by analyzing a website’s HTTP response headers?",
        "options": [
            "Server software version",
            "User credentials",
            "Internal IP addresses",
            "All of the above"
        ],
        "answer": "Server software version"
    },
    {
        "question": "Which of the following is NOT a technique used for footprinting?",
        "options": [
            "Social Engineering",
            "Network Scanning",
            "Email Injection", // Correct
            "Web Scraping"
        ],
        "answer": "Email Injection" // Correct
    },
    {
        "question": "What information can be inferred from an organization’s online job postings?",
        "options": [
            "Network infrastructure details",
            "Employee skill sets",
            "Financial status",
            "Internal security policies"
        ],
        "answer": "Employee skill sets"
    },
    {
        "question": "An attacker uses various online tools to gather publicly available information about a target. This is an example of:",
        "options": [
            "Active Footprinting",
            "Passive Footprinting",
            "Social Engineering",
            "Network Scanning"
        ],
        "answer": "Passive Footprinting"
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
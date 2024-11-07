
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    // Information Security Overview
    {
        "question": "A company has recently experienced a data breach and wants to strengthen its defenses. What is the first step in developing an information security strategy?",
        "options": [
            "Implementing new firewalls",
            "Conducting a risk assessment",
            "Hiring a security consultant",
            "Training employees on security policies"
        ],
        "answer": "Conducting a risk assessment"
    },
    {
        "question": "Which of the following is a key principle of information security?",
        "options": [
            "Availability",
            "Popularity",
            "Cost-effectiveness",
            "Ease of access"
        ],
        "answer": "Availability"
    },
    {
        "question": "What is the primary goal of information security?",
        "options": [
            "To eliminate all risks",
            "To protect data from unauthorized access",
            "To ensure compliance with regulations",
            "To maximize productivity"
        ],
        "answer": "To protect data from unauthorized access"
    },
    {
        "question": "Which of the following describes the concept of 'defense in depth'?",
        "options": [
            "Relying on a single security measure",
            "Implementing multiple layers of security controls",
            "Using complex passwords",
            "Educating users about security"
        ],
        "answer": "Implementing multiple layers of security controls"
    },
    {
        "question": "A company has decided to implement a new information security policy. What is the best way to ensure employee compliance?",
        "options": [
            "Sending an email about the new policy",
            "Conducting mandatory training sessions",
            "Posting the policy on the company intranet",
            "Notifying employees during meetings"
        ],
        "answer": "Conducting mandatory training sessions"
    },

    // Hacking Methodologies and Frameworks
    {
        "question": "What is the primary purpose of a penetration testing framework?",
        "options": [
            "To provide guidelines for ethical hacking",
            "To automate vulnerability scanning",
            "To monitor network traffic",
            "To enforce security policies"
        ],
        "answer": "To provide guidelines for ethical hacking"
    },
    {
        "question": "Which phase of the penetration testing methodology involves gathering information about the target?",
        "options": [
            "Exploitation",
            "Scanning",
            "Planning",
            "Reconnaissance"
        ],
        "answer": "Reconnaissance"
    },
    {
        "question": "What does the acronym OSSTMM stand for in the context of ethical hacking?",
        "options": [
            "Open Source Security Testing Methodology Manual",
            "Operational Security Testing and Management Method",
            "Organizational Security Threat Mitigation Model",
            "Online Security Testing and Methodology Management"
        ],
        "answer": "Open Source Security Testing Methodology Manual"
    },
    {
        "question": "Which framework is commonly used for managing information security in organizations?",
        "options": [
            "NIST Cybersecurity Framework",
            "OWASP Top Ten",
            "ISO 27001",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "In which phase of ethical hacking would you prioritize vulnerabilities based on risk?",
        "options": [
            "Planning",
            "Exploitation",
            "Reporting",
            "Scanning"
        ],
        "answer": "Reporting"
    },

    // Hacking Concepts
    {
        "question": "What is the primary difference between black hat and white hat hackers?",
        "options": [
            "Their level of expertise",
            "Their intentions and legality of actions",
            "The tools they use",
            "Their target environments"
        ],
        "answer": "Their intentions and legality of actions"
    },
    {
        "question": "Which type of hacker is typically employed by organizations to identify vulnerabilities?",
        "options": [
            "Black hat",
            "White hat",
            "Gray hat",
            "Script kiddie"
        ],
        "answer": "White hat"
    },
    {
        "question": "What is social engineering in the context of hacking?",
        "options": [
            "Using software vulnerabilities to gain access",
            "Manipulating individuals to divulge confidential information",
            "Analyzing network traffic for weaknesses",
            "Developing malicious software"
        ],
        "answer": "Manipulating individuals to divulge confidential information"
    },
    {
        "question": "A hacker uses a phishing email to steal credentials. What kind of attack is this?",
        "options": [
            "Denial of Service",
            "Social engineering",
            "Man-in-the-middle",
            "SQL injection"
        ],
        "answer": "Social engineering"
    },
    {
        "question": "What is the primary goal of exploiting a vulnerability?",
        "options": [
            "To gather information",
            "To test security measures",
            "To gain unauthorized access or control",
            "To create awareness"
        ],
        "answer": "To gain unauthorized access or control"
    },

    // Ethical Hacking Concepts
    {
        "question": "Which of the following best defines ethical hacking?",
        "options": [
            "Hacking for malicious purposes",
            "Testing systems without permission",
            "Authorized testing to identify vulnerabilities",
            "Hacking for fun"
        ],
        "answer": "Authorized testing to identify vulnerabilities"
    },
    {
        "question": "What is a key characteristic of ethical hackers?",
        "options": [
            "They operate without oversight",
            "They have permission to test systems",
            "They avoid documentation",
            "They target government systems"
        ],
        "answer": "They have permission to test systems"
    },
    {
        "question": "What is the first step an ethical hacker should take before conducting a penetration test?",
        "options": [
            "Gather intelligence on the target",
            "Obtain written consent from the organization",
            "Scan the target for vulnerabilities",
            "Develop a testing plan"
        ],
        "answer": "Obtain written consent from the organization"
    },
    {
        "question": "In ethical hacking, what is meant by 'scope'?",
        "options": [
            "The size of the target network",
            "The boundaries of the testing activities",
            "The number of vulnerabilities found",
            "The timeframe for the engagement"
        ],
        "answer": "The boundaries of the testing activities"
    },
    {
        "question": "Which ethical hacking framework focuses specifically on web applications?",
        "options": [
            "NIST Cybersecurity Framework",
            "OWASP Testing Guide",
            "ISO 27001",
            "MITRE ATT&CK"
        ],
        "answer": "OWASP Testing Guide"
    },

    // Information Security Controls
    {
        "question": "Which type of control is implemented to prevent unauthorized access?",
        "options": [
            "Physical control",
            "Technical control",
            "Administrative control",
            "Deterrent control"
        ],
        "answer": "Technical control"
    },
    {
        "question": "What is the purpose of access control policies?",
        "options": [
            "To improve user experience",
            "To manage user permissions and protect resources",
            "To monitor network traffic",
            "To enforce hardware standards"
        ],
        "answer": "To manage user permissions and protect resources"
    },
    {
        "question": "What is an example of a physical security control?",
        "options": [
            "Firewalls",
            "Encryption",
            "Security cameras",
            "Antivirus software"
        ],
        "answer": "Security cameras"
    },
    {
        "question": "Which control is used to ensure compliance with laws and regulations?",
        "options": [
            "Preventive control",
            "Detective control",
            "Corrective control",
            "Administrative control"
        ],
        "answer": "Detective control"
    },
    {
        "question": "What is the role of a security policy in an organization?",
        "options": [
            "To define security measures and practices",
            "To serve as a guideline for user behavior",
            "To monitor network performance",
            "To increase productivity"
        ],
        "answer": "To define security measures and practices"
    },

    // Information Security Laws and Standards
    {
        "question": "What is the primary purpose of information security laws?",
        "options": [
            "To increase data access",
            "To protect personal and organizational data",
            "To eliminate all security risks",
            "To regulate technology companies"
        ],
        "answer": "To protect personal and organizational data"
    },
    {
        "question": "Which regulation requires organizations to protect personal data of EU citizens?",
        "options": [
            "HIPAA",
            "SOX",
            "GDPR",
            "PCI DSS"
        ],
        "answer": "GDPR"
    },
    {
        "question": "Which standard provides a framework for managing information security risks?",
        "options": [
            "ISO 9001",
            "ISO 27001",
            "NIST SP 800-53",
            "PCI DSS"
        ],
        "answer": "ISO 27001"
    },
    {
        "question": "What is the focus of the Sarbanes-Oxley Act (SOX)?",
        "options": [
            "Protecting consumer data",
            "Financial reporting and accountability",
            "Data privacy regulations",
            "Health information security"
        ],
        "answer": "Financial reporting and accountability"
    },
    {
        "question": "Which of the following is a common information security standard in the payment card industry?",
        "options": [
            "ISO 27001",
            "NIST SP 800-53",
            "PCI DSS",
            "HIPAA"
        ],
        "answer": "PCI DSS"
    },
    // Information Security Overview
    {
        "question": "What is a common method for assessing the effectiveness of an organization's information security program?",
        "options": [
            "Social engineering tests",
            "Regular audits and assessments",
            "User surveys",
            "Productivity analysis"
        ],
        "answer": "Regular audits and assessments"
    },
    {
        "question": "Which type of attack is characterized by overwhelming a system with traffic to make it unavailable?",
        "options": [
            "Phishing",
            "Denial of Service (DoS)",
            "Man-in-the-middle",
            "SQL injection"
        ],
        "answer": "Denial of Service (DoS)"
    },
    {
        "question": "What does the term 'confidentiality' refer to in information security?",
        "options": [
            "Ensuring data is accessible to authorized users",
            "Preventing unauthorized access to data",
            "Maintaining the integrity of data",
            "Backing up data regularly"
        ],
        "answer": "Preventing unauthorized access to data"
    },
    {
        "question": "Which of the following is a critical component of an incident response plan?",
        "options": [
            "Data encryption",
            "Access controls",
            "Incident detection and analysis",
            "Employee training"
        ],
        "answer": "Incident detection and analysis"
    },
    {
        "question": "What is the purpose of conducting a vulnerability assessment?",
        "options": [
            "To eliminate all vulnerabilities",
            "To identify weaknesses in systems and applications",
            "To ensure compliance with laws",
            "To reduce costs"
        ],
        "answer": "To identify weaknesses in systems and applications"
    },

    // Hacking Methodologies and Frameworks
    {
        "question": "Which ethical hacking framework emphasizes the importance of a controlled testing environment?",
        "options": [
            "MITRE ATT&CK",
            "NIST Cybersecurity Framework",
            "OWASP Testing Guide",
            "ISO 27001"
        ],
        "answer": "NIST Cybersecurity Framework"
    },
    {
        "question": "What does the 'exploitation' phase in penetration testing involve?",
        "options": [
            "Identifying potential vulnerabilities",
            "Gaining unauthorized access to systems",
            "Reporting findings to management",
            "Planning the testing approach"
        ],
        "answer": "Gaining unauthorized access to systems"
    },
    {
        "question": "What is the primary focus of the Penetration Testing Execution Standard (PTES)?",
        "options": [
            "Threat modeling",
            "Web application testing",
            "General penetration testing methodology",
            "Social engineering"
        ],
        "answer": "General penetration testing methodology"
    },
    {
        "question": "In the context of ethical hacking, what is 'pivoting'?",
        "options": [
            "Gaining access to additional systems from a compromised system",
            "Switching from one attack method to another",
            "Changing the target during an assessment",
            "Improving network performance"
        ],
        "answer": "Gaining access to additional systems from a compromised system"
    },
    {
        "question": "What is the importance of documenting findings during a penetration test?",
        "options": [
            "To increase the complexity of the report",
            "To provide a basis for remediation and compliance",
            "To share information with competitors",
            "To complicate the testing process"
        ],
        "answer": "To provide a basis for remediation and compliance"
    },

    // Hacking Concepts
    {
        "question": "Which of the following best describes a 'script kiddie'?",
        "options": [
            "An experienced hacker using their own tools",
            "A novice who uses existing tools without understanding them",
            "A security professional",
            "A hacker who develops their own exploits"
        ],
        "answer": "A novice who uses existing tools without understanding them"
    },
    {
        "question": "What is the main goal of a white hat hacker when testing a system?",
        "options": [
            "To steal sensitive information",
            "To help organizations improve their security posture",
            "To create chaos in the system",
            "To demonstrate hacking skills"
        ],
        "answer": "To help organizations improve their security posture"
    },
    {
        "question": "A company is concerned about insider threats. What preventive measure can they implement?",
        "options": [
            "Implementing stricter access controls",
            "Ignoring user behavior",
            "Relying solely on antivirus software",
            "Increasing internet access speed"
        ],
        "answer": "Implementing stricter access controls"
    },
    {
        "question": "What does the term 'vulnerability' refer to in the context of information security?",
        "options": [
            "A weakness that can be exploited",
            "A security breach",
            "An attack method",
            "A preventive measure"
        ],
        "answer": "A weakness that can be exploited"
    },
    {
        "question": "What role does employee training play in information security?",
        "options": [
            "It is optional and can be skipped",
            "It helps prevent human errors that can lead to breaches",
            "It complicates security procedures",
            "It is only necessary for IT staff"
        ],
        "answer": "It helps prevent human errors that can lead to breaches"
    },

    // Ethical Hacking Concepts
    {
        "question": "Which of the following is NOT a characteristic of ethical hacking?",
        "options": [
            "Legitimate purpose",
            "Authorization from the target organization",
            "Malicious intent",
            "Reporting vulnerabilities to the organization"
        ],
        "answer": "Malicious intent"
    },
    {
        "question": "What is the significance of the 'rules of engagement' in ethical hacking?",
        "options": [
            "To define legal consequences for hackers",
            "To outline the scope and limitations of the testing",
            "To determine the cost of the assessment",
            "To select the tools used for testing"
        ],
        "answer": "To outline the scope and limitations of the testing"
    },
    {
        "question": "What is a common outcome of a successful ethical hacking engagement?",
        "options": [
            "Exploitation of vulnerabilities",
            "Increased vulnerability exposure",
            "Improved security measures and protocols",
            "Unreported vulnerabilities"
        ],
        "answer": "Improved security measures and protocols"
    },
    {
        "question": "What ethical principle is critical for ethical hackers to adhere to?",
        "options": [
            "Profit maximization",
            "Respecting privacy and confidentiality",
            "Minimizing documentation",
            "Maximizing system disruption"
        ],
        "answer": "Respecting privacy and confidentiality"
    },
    {
        "question": "What should an ethical hacker do if they discover a serious vulnerability during a test?",
        "options": [
            "Exploit it further to demonstrate impact",
            "Report it immediately to the organization",
            "Ignore it if it seems minor",
            "Publicly disclose it without permission"
        ],
        "answer": "Report it immediately to the organization"
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
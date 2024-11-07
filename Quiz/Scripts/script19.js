
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    // Cloud Computing Concepts
    {
        "question": "A company is considering moving its infrastructure to the cloud to improve scalability and flexibility. Which model should they consider if they want full control over the underlying infrastructure?",
        "options": [
            "Infrastructure as a Service (IaaS)",
            "Platform as a Service (PaaS)",
            "Software as a Service (SaaS)",
            "Function as a Service (FaaS)"
        ],
        "answer": "Infrastructure as a Service (IaaS)"
    },
    {
        "question": "During a discussion about cloud service models, a developer mentions that they are focused on building applications without managing servers. Which cloud model are they utilizing?",
        "options": [
            "IaaS",
            "PaaS",
            "SaaS",
            "FaaS"
        ],
        "answer": "Platform as a Service (PaaS)"
    },
    {
        "question": "An organization is exploring hybrid cloud solutions. What is a key benefit of this approach?",
        "options": [
            "Increased dependency on a single cloud provider",
            "Improved data security through local storage",
            "Elimination of on-premises infrastructure",
            "Simplified disaster recovery"
        ],
        "answer": "Improved data security through local storage"
    },
    {
        "question": "A startup wants to leverage cloud resources to reduce initial costs. Which cloud pricing model would be most beneficial?",
        "options": [
            "Pay-as-you-go",
            "Reserved instances",
            "Dedicated hosting",
            "Subscription-based pricing"
        ],
        "answer": "Pay-as-you-go"
    },
    {
        "question": "What is the primary characteristic of cloud computing that allows users to access resources from anywhere?",
        "options": [
            "Resource pooling",
            "Broad network access",
            "Rapid elasticity",
            "Measured service"
        ],
        "answer": "Broad network access"
    },

    // Container Technology
    {
        "question": "A company is deploying microservices architecture and uses containers to manage applications. Which technology would they likely use for orchestration?",
        "options": [
            "Docker Swarm",
            "Apache Hadoop",
            "Kubernetes",
            "OpenStack"
        ],
        "answer": "Kubernetes"
    },
    {
        "question": "During a security audit, a containerized application is found to have vulnerabilities in its images. What practice should be implemented to enhance security?",
        "options": [
            "Using outdated base images",
            "Regularly scanning container images",
            "Deploying containers with root privileges",
            "Ignoring image updates"
        ],
        "answer": "Regularly scanning container images"
    },
    {
        "question": "An organization wants to ensure their containers are isolated from each other. What is the best practice to achieve this?",
        "options": [
            "Deploy all containers on a single host",
            "Use different namespaces for each container",
            "Allow containers to share the same user",
            "Avoid network segmentation"
        ],
        "answer": "Use different namespaces for each container"
    },
    {
        "question": "A team is tasked with monitoring container performance. What key metric should they focus on?",
        "options": [
            "CPU and memory usage",
            "User engagement",
            "Storage throughput",
            "Network latency"
        ],
        "answer": "CPU and memory usage"
    },
    {
        "question": "When designing a cloud-native application, which approach allows for automatic scaling of resources?",
        "options": [
            "Manual deployment",
            "Serverless architecture",
            "Monolithic architecture",
            "Static resource allocation"
        ],
        "answer": "Serverless architecture"
    },

    // Serverless Computing
    {
        "question": "A developer is creating a web application that requires a backend service with automatic scaling and minimal management. Which model should they consider?",
        "options": [
            "IaaS",
            "PaaS",
            "SaaS",
            "Function as a Service (FaaS)"
        ],
        "answer": "Function as a Service (FaaS)"
    },
    {
        "question": "An organization adopts serverless computing for their applications. What is a potential downside of this approach?",
        "options": [
            "Increased operational overhead",
            "Reduced cost-effectiveness",
            "Vendor lock-in",
            "More control over infrastructure"
        ],
        "answer": "Vendor lock-in"
    },
    {
        "question": "During a project review, a team discusses the event-driven nature of serverless computing. What does this imply?",
        "options": [
            "Resources are allocated based on scheduled time",
            "Functions are executed in response to events or triggers",
            "Applications are entirely stateless",
            "All services must be manually initiated"
        ],
        "answer": "Functions are executed in response to events or triggers"
    },
    {
        "question": "A company wants to integrate serverless functions into their existing microservices architecture. What is a key consideration?",
        "options": [
            "Using only one cloud provider",
            "Ensuring functions can scale independently",
            "Avoiding any API gateway usage",
            "Relying on synchronous processing"
        ],
        "answer": "Ensuring functions can scale independently"
    },
    {
        "question": "In a serverless architecture, how is billing typically handled?",
        "options": [
            "Fixed monthly fee",
            "Based on resource usage",
            "No charges for idle time",
            "Charged for provisioned resources"
        ],
        "answer": "Based on resource usage"
    },

    // Cloud Computing Threats
    {
        "question": "An organization experiences unauthorized access to its cloud storage due to weak credentials. What type of threat does this represent?",
        "options": [
            "Insider threat",
            "Credential stuffing",
            "Malware attack",
            "DDoS attack"
        ],
        "answer": "Credential stuffing"
    },
    {
        "question": "A company’s cloud infrastructure is targeted by a DDoS attack, leading to service disruptions. What is a primary method to mitigate such attacks?",
        "options": [
            "Increasing server capacity",
            "Implementing a web application firewall",
            "Using rate limiting",
            "Deploying redundant systems"
        ],
        "answer": "Using rate limiting"
    },
    {
        "question": "A cloud provider experiences a data breach exposing client data. What is the primary responsibility of the organization using the cloud service?",
        "options": [
            "Ensure the provider has adequate security measures",
            "Ignore the incident as it’s the provider's issue",
            "Conduct a full audit of the provider",
            "Stop using the cloud services"
        ],
        "answer": "Ensure the provider has adequate security measures"
    },
    {
        "question": "An employee inadvertently exposes sensitive data in a public cloud environment. What type of threat does this represent?",
        "options": [
            "Data leak",
            "Phishing attack",
            "Man-in-the-middle attack",
            "Malware attack"
        ],
        "answer": "Data leak"
    },
    {
        "question": "A threat actor targets an organization’s cloud application to exploit an unpatched vulnerability. What type of attack is this?",
        "options": [
            "Ransomware",
            "Zero-day attack",
            "Phishing",
            "Social engineering"
        ],
        "answer": "Zero-day attack"
    },

    // Cloud Hacking
    {
        "question": "During a penetration test of a cloud application, a tester discovers that APIs are exposed without authentication. What type of vulnerability is this?",
        "options": [
            "Broken authentication",
            "Insecure direct object references",
            "Excessive data exposure",
            "Misconfiguration"
        ],
        "answer": "Broken authentication"
    },
    {
        "question": "An organization’s cloud service is compromised due to the use of hardcoded credentials. What is the primary recommendation to prevent this?",
        "options": [
            "Using strong encryption for all data",
            "Implementing secrets management solutions",
            "Regularly rotating all passwords",
            "Increasing firewall rules"
        ],
        "answer": "Implementing secrets management solutions"
    },
    {
        "question": "A hacker gains access to cloud resources by exploiting misconfigured security groups. What type of attack is this?",
        "options": [
            "Network intrusion",
            "Data breach",
            "Phishing",
            "Social engineering"
        ],
        "answer": "Network intrusion"
    },
    {
        "question": "A company’s cloud instance is breached due to lack of multi-factor authentication. What security measure should they prioritize?",
        "options": [
            "Implementing MFA for all users",
            "Restricting IP addresses",
            "Disabling user accounts",
            "Using VPN exclusively"
        ],
        "answer": "Implementing MFA for all users"
    },
    {
        "question": "An attacker utilizes phishing to gain access to a company's cloud management console. What type of attack is this?",
        "options": [
            "Spear phishing",
            "Social engineering",
            "Man-in-the-middle",
            "Credential stuffing"
        ],
        "answer": "Spear phishing"
    },

    // Cloud Security
    {
        "question": "An organization is implementing cloud security best practices. What should be their first step?",
        "options": [
            "Deploying additional security appliances",
            "Conducting a cloud security assessment",
            "Increasing server capacity",
            "Implementing user access controls"
        ],
        "answer": "Conducting a cloud security assessment"
    },
    {
        "question": "To secure their cloud data, a company decides to encrypt sensitive information at rest and in transit. What type of security is this?",
        "options": [
            "Data encryption",
            "Access control",
            "Network security",
            "Identity management"
        ],
        "answer": "Data encryption"
    },
    {
        "question": "A cloud security team is tasked with protecting user data from unauthorized access. Which strategy is most effective?",
        "options": [
            "Implementing strong access controls",
            "Using default permissions",
            "Allowing unrestricted access",
            "Disabling logging"
        ],
        "answer": "Implementing strong access controls"
    },
    {
        "question": "An organization adopts a zero-trust security model for their cloud infrastructure. What does this approach entail?",
        "options": [
            "Trusting all internal users by default",
            "Verifying every access request regardless of location",
            "Only allowing access to external users",
            "Automatically granting permissions"
        ],
        "answer": "Verifying every access request regardless of location"
    },
    {
        "question": "To ensure compliance with regulations in their cloud environment, what should organizations implement?",
        "options": [
            "Regular audits and assessments",
            "Ignoring compliance requirements",
            "Minimal data retention policies",
            "Limited user training"
        ],
        "answer": "Regular audits and assessments"
    },
    {
        "question": "A company is transitioning from on-premises infrastructure to the cloud and wants to minimize operational overhead. Which model should they consider?",
        "options": [
            "IaaS",
            "PaaS",
            "SaaS",
            "DaaS"
        ],
        "answer": "SaaS"
    },
    {
        "question": "In a cloud environment, which principle ensures that resources are allocated dynamically based on demand?",
        "options": [
            "Resource pooling",
            "Rapid elasticity",
            "Measured service",
            "Broad network access"
        ],
        "answer": "Rapid elasticity"
    },
    {
        "question": "An organization is looking to ensure data residency compliance in their cloud deployment. What should they prioritize?",
        "options": [
            "Using a global cloud provider",
            "Selecting data centers in specific regions",
            "Deploying in multiple regions",
            "Using hybrid cloud solutions"
        ],
        "answer": "Selecting data centers in specific regions"
    },
    {
        "question": "What is a primary benefit of multi-cloud strategies?",
        "options": [
            "Vendor lock-in",
            "Increased complexity",
            "Redundancy and reliability",
            "Higher costs"
        ],
        "answer": "Redundancy and reliability"
    },
    {
        "question": "An organization is reviewing their cloud service contracts. Which aspect is crucial for ensuring service reliability?",
        "options": [
            "Service Level Agreements (SLAs)",
            "Cost structures",
            "Provider's market reputation",
            "User reviews"
        ],
        "answer": "Service Level Agreements (SLAs)"
    },

    // Container Technology
    {
        "question": "A development team is considering using containers for their applications. What is a significant advantage of using containers?",
        "options": [
            "Increased resource consumption",
            "Enhanced portability across environments",
            "Complex dependency management",
            "Increased boot time"
        ],
        "answer": "Enhanced portability across environments"
    },
    {
        "question": "What is a common challenge associated with container orchestration?",
        "options": [
            "Simplified deployments",
            "Managing scaling and load balancing",
            "Increased container isolation",
            "Reduced networking complexity"
        ],
        "answer": "Managing scaling and load balancing"
    },
    {
        "question": "In a CI/CD pipeline, how do containers improve the deployment process?",
        "options": [
            "By eliminating the need for testing",
            "By providing a consistent environment for all stages",
            "By increasing manual interventions",
            "By requiring more extensive configuration"
        ],
        "answer": "By providing a consistent environment for all stages"
    },
    {
        "question": "A team is deploying a containerized application and is concerned about network security. What should they implement?",
        "options": [
            "Open all network ports for accessibility",
            "Use firewalls and network segmentation",
            "Disable logging to improve performance",
            "Allow unrestricted API access"
        ],
        "answer": "Use firewalls and network segmentation"
    },
    {
        "question": "A company is adopting Kubernetes for their container management. What is a key component of Kubernetes responsible for scheduling and managing containers?",
        "options": [
            "Kubelet",
            "Kube-Proxy",
            "Kubernetes API Server",
            "Etcd"
        ],
        "answer": "Kubernetes API Server"
    },

    // Serverless Computing
    {
        "question": "An organization is utilizing serverless functions for event-driven processing. Which service should they use to trigger these functions based on HTTP requests?",
        "options": [
            "API Gateway",
            "Load Balancer",
            "Cloud Storage",
            "VPC"
        ],
        "answer": "API Gateway"
    },
    {
        "question": "A developer is implementing serverless architecture and wants to monitor performance. What tool would be most effective for this purpose?",
        "options": [
            "Traditional APM tools",
            "Cloud provider's monitoring service",
            "Static code analysis",
            "Manual logging"
        ],
        "answer": "Cloud provider's monitoring service"
    },
    {
        "question": "A team wants to ensure their serverless functions have low latency. What strategy should they implement?",
        "options": [
            "Deploy functions in multiple regions",
            "Increase function memory allocation",
            "Use only synchronous functions",
            "Disable caching"
        ],
        "answer": "Deploy functions in multiple regions"
    },
    {
        "question": "What is a common challenge when using serverless computing?",
        "options": [
            "Increased manual management",
            "Cold starts for functions",
            "Higher operational costs",
            "Static resource allocation"
        ],
        "answer": "Cold starts for functions"
    },
    {
        "question": "When designing serverless applications, which architectural pattern should developers consider to handle failures gracefully?",
        "options": [
            "Event sourcing",
            "Saga pattern",
            "Circuit breaker pattern",
            "Layered architecture"
        ],
        "answer": "Circuit breaker pattern"
    },

    // Cloud Computing Threats
    {
        "question": "An organization discovers their cloud storage has been publicly accessible due to misconfigured permissions. What type of risk does this pose?",
        "options": [
            "Data breach",
            "Insider threat",
            "Service disruption",
            "Account hijacking"
        ],
        "answer": "Data breach"
    },
    {
        "question": "A cloud provider experiences a massive outage impacting multiple clients. What is a potential cause of this incident?",
        "options": [
            "Overprovisioning resources",
            "Insufficient redundancy and failover",
            "Increased user activity",
            "Regular maintenance"
        ],
        "answer": "Insufficient redundancy and failover"
    },
    {
        "question": "A cybercriminal deploys malware on a cloud instance to exfiltrate data. What type of attack is this?",
        "options": [
            "Ransomware",
            "Data exfiltration",
            "Phishing",
            "Denial of Service"
        ],
        "answer": "Data exfiltration"
    },
    {
        "question": "To prevent unauthorized access to cloud resources, what security measure is critical?",
        "options": [
            "Weak password policies",
            "Multi-factor authentication",
            "Public access permissions",
            "Shared credentials"
        ],
        "answer": "Multi-factor authentication"
    },
    {
        "question": "A company discovers their cloud resources are being used for cryptocurrency mining without authorization. What type of attack is this?",
        "options": [
            "Cryptojacking",
            "DDoS attack",
            "Ransomware",
            "SQL Injection"
        ],
        "answer": "Cryptojacking"
    },

    // Cloud Hacking
    {
        "question": "During a security assessment, a tester exploits a vulnerability in a cloud application to access sensitive data. What type of attack is this?",
        "options": [
            "Injection attack",
            "Cross-Site Scripting (XSS)",
            "Man-in-the-middle attack",
            "Privilege escalation"
        ],
        "answer": "Privilege escalation"
    },
    {
        "question": "An attacker successfully uses stolen API keys to manipulate a cloud application. What type of security issue does this represent?",
        "options": [
            "Weak API security",
            "Insufficient logging",
            "Misconfigured network settings",
            "Excessive permissions"
        ],
        "answer": "Weak API security"
    },
    {
        "question": "A company experiences a breach due to unpatched vulnerabilities in their cloud environment. What should they prioritize to prevent future incidents?",
        "options": [
            "Regular software updates and patches",
            "Increased user permissions",
            "Ignoring vulnerability reports",
            "Using outdated libraries"
        ],
        "answer": "Regular software updates and patches"
    },
    {
        "question": "What is a common tactic used by attackers to gain access to cloud environments?",
        "options": [
            "Brute force attacks",
            "Data encryption",
            "API documentation review",
            "User training"
        ],
        "answer": "Brute force attacks"
    },
    {
        "question": "An organization implements logging and monitoring but fails to analyze logs effectively. What risk does this pose?",
        "options": [
            "Increased visibility",
            "Delayed response to incidents",
            "Improved security posture",
            "Reduced overhead"
        ],
        "answer": "Delayed response to incidents"
    },

    // Cloud Security
    {
        "question": "A company wants to ensure their data is encrypted in the cloud. What type of encryption should they implement?",
        "options": [
            "At-rest and in-transit encryption",
            "Only at-rest encryption",
            "Only in-transit encryption",
            "No encryption needed"
        ],
        "answer": "At-rest and in-transit encryption"
    },
    {
        "question": "What is a key component of a cloud security strategy?",
        "options": [
            "Trusting the cloud provider completely",
            "Regularly reviewing security policies",
            "Ignoring user permissions",
            "Using weak authentication methods"
        ],
        "answer": "Regularly reviewing security policies"
    },
    {
        "question": "To improve their cloud security posture, a company should implement which type of access control?",
        "options": [
            "Role-based access control (RBAC)",
            "Mandatory access control (MAC)",
            "Discretionary access control (DAC)",
            "No access control"
        ],
        "answer": "Role-based access control (RBAC)"
    },
    {
        "question": "A cloud security team is establishing a data loss prevention (DLP) strategy. What should be a primary focus?",
        "options": [
            "Monitoring user activity and data access",
            "Disabling user permissions",
            "Allowing unrestricted access",
            "Ignoring data classification"
        ],
        "answer": "Monitoring user activity and data access"
    },
    {
        "question": "To enhance incident response in a cloud environment, organizations should implement what?",
        "options": [
            "Clear response plans and playbooks",
            "Limited communication channels",
            "Static security measures",
            "No monitoring"
        ],
        "answer": "Clear response plans and playbooks"
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
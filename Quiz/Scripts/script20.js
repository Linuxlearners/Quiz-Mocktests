
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    // Cryptography Concepts
    {
        "question": "Alice needs to ensure that only Bob can read her message. What cryptographic technique should she use?",
        "options": [
            "Hashing",
            "Symmetric encryption",
            "Asymmetric encryption",
            "Salting"
        ],
        "answer": "Asymmetric encryption"
    },
    {
        "question": "Which property of cryptography ensures that a message cannot be altered without detection?",
        "options": [
            "Confidentiality",
            "Integrity",
            "Authentication",
            "Non-repudiation"
        ],
        "answer": "Integrity"
    },
    {
        "question": "A company wants to ensure that its data remains confidential during transmission. Which cryptographic method should they implement?",
        "options": [
            "Hashing",
            "Symmetric encryption",
            "Digital signatures",
            "Checksum"
        ],
        "answer": "Symmetric encryption"
    },
    {
        "question": "What is the primary purpose of a cryptographic hash function?",
        "options": [
            "Encrypting data",
            "Creating digital signatures",
            "Generating random keys",
            "Ensuring data integrity"
        ],
        "answer": "Ensuring data integrity"
    },
    {
        "question": "Which term describes the process of converting plaintext into ciphertext?",
        "options": [
            "Encryption",
            "Decryption",
            "Hashing",
            "Salting"
        ],
        "answer": "Encryption"
    },

    // Encryption Algorithms
    {
        "question": "A company is considering using AES for encryption. What type of algorithm is AES?",
        "options": [
            "Asymmetric",
            "Symmetric",
            "Hashing",
            "Public-key"
        ],
        "answer": "Symmetric"
    },
    {
        "question": "Which encryption algorithm is commonly used for securing web traffic?",
        "options": [
            "RSA",
            "DES",
            "AES",
            "Blowfish"
        ],
        "answer": "AES"
    },
    {
        "question": "An organization needs to encrypt data for secure email transmission. Which algorithm would be appropriate for this purpose?",
        "options": [
            "RSA",
            "SHA-256",
            "RC4",
            "AES"
        ],
        "answer": "RSA"
    },
    {
        "question": "A developer is tasked with implementing a hashing function. Which algorithm should they use to ensure a secure hash?",
        "options": [
            "MD5",
            "SHA-1",
            "SHA-256",
            "Base64"
        ],
        "answer": "SHA-256"
    },
    {
        "question": "Which encryption algorithm uses a fixed-length key of 128, 192, or 256 bits?",
        "options": [
            "3DES",
            "RSA",
            "AES",
            "Blowfish"
        ],
        "answer": "AES"
    },

    // Cryptography Tools
    {
        "question": "A security analyst wants to implement a secure file transfer method. Which tool should they consider using?",
        "options": [
            "SSH",
            "FTP",
            "HTTP",
            "Telnet"
        ],
        "answer": "SSH"
    },
    {
        "question": "Which tool can be used to generate strong cryptographic keys?",
        "options": [
            "Keylogger",
            "Password manager",
            "Random number generator",
            "Public key directory"
        ],
        "answer": "Random number generator"
    },
    {
        "question": "A team is using GnuPG for encrypting files. What type of tool is GnuPG?",
        "options": [
            "Hashing tool",
            "Public key infrastructure tool",
            "Encryption tool",
            "Network security tool"
        ],
        "answer": "Encryption tool"
    },
    {
        "question": "What is the purpose of a certificate authority (CA) in cryptography?",
        "options": [
            "To encrypt data",
            "To generate random numbers",
            "To issue digital certificates",
            "To hash passwords"
        ],
        "answer": "To issue digital certificates"
    },
    {
        "question": "An organization uses OpenSSL to manage its encryption keys. What type of tool is OpenSSL?",
        "options": [
            "Encryption library",
            "Hashing algorithm",
            "Firewall",
            "Monitoring tool"
        ],
        "answer": "Encryption library"
    },

    // Public Key Infrastructure (PKI)
    {
        "question": "A company wants to secure its communications using PKI. What is the role of a digital certificate in this framework?",
        "options": [
            "To encrypt messages",
            "To authenticate users",
            "To hash data",
            "To store public keys"
        ],
        "answer": "To authenticate users"
    },
    {
        "question": "Which component of PKI is responsible for managing the creation, distribution, and revocation of digital certificates?",
        "options": [
            "Certificate Authority (CA)",
            "Registration Authority (RA)",
            "Digital Signature",
            "Public Key"
        ],
        "answer": "Certificate Authority (CA)"
    },
    {
        "question": "What is a key characteristic of asymmetric encryption used in PKI?",
        "options": [
            "Same key for encryption and decryption",
            "Two keys: public and private",
            "Faster than symmetric encryption",
            "Uses fixed-length keys only"
        ],
        "answer": "Two keys: public and private"
    },
    {
        "question": "An organization needs to ensure that its digital signatures cannot be forged. What PKI component is essential for this?",
        "options": [
            "Public key",
            "Private key",
            "Registration Authority (RA)",
            "Certificate Revocation List (CRL)"
        ],
        "answer": "Private key"
    },
    {
        "question": "A client connects to a secure server using SSL/TLS. What role does the server's digital certificate play in this connection?",
        "options": [
            "Encrypts the data",
            "Authenticates the server's identity",
            "Manages session keys",
            "Generates random numbers"
        ],
        "answer": "Authenticates the server's identity"
    },

    // Email Encryption
    {
        "question": "A user wants to send an encrypted email to a colleague. Which encryption standard should they consider using?",
        "options": [
            "PGP",
            "SSL",
            "HTTPS",
            "SSH"
        ],
        "answer": "PGP"
    },
    {
        "question": "What is the primary purpose of S/MIME in email communication?",
        "options": [
            "To ensure email delivery",
            "To encrypt email content and provide digital signatures",
            "To compress email attachments",
            "To categorize emails"
        ],
        "answer": "To encrypt email content and provide digital signatures"
    },
    {
        "question": "Which of the following is a limitation of email encryption?",
        "options": [
            "Ensures confidentiality",
            "Requires both sender and recipient to have compatible encryption methods",
            "Protects against all types of attacks",
            "Is simple to implement"
        ],
        "answer": "Requires both sender and recipient to have compatible encryption methods"
    },
    {
        "question": "A company implements end-to-end email encryption. What does this guarantee?",
        "options": [
            "Only the sender and recipient can read the email content",
            "Email is secure during transit only",
            "All email providers can read the content",
            "Emails are never stored on servers"
        ],
        "answer": "Only the sender and recipient can read the email content"
    },
    {
        "question": "When using PGP for email encryption, what is the primary use of the recipient's public key?",
        "options": [
            "To decrypt the email",
            "To encrypt the email content",
            "To generate a digital signature",
            "To validate the sender's identity"
        ],
        "answer": "To encrypt the email content"
    },

    // Disk Encryption
    {
        "question": "A security officer is tasked with implementing disk encryption for sensitive data. What is a popular tool for this purpose?",
        "options": [
            "TrueCrypt",
            "Wireshark",
            "Nmap",
            "Metasploit"
        ],
        "answer": "TrueCrypt"
    },
    {
        "question": "What is the primary benefit of full disk encryption?",
        "options": [
            "Increased performance",
            "Protection of data at rest",
            "Ease of access",
            "Reduced complexity"
        ],
        "answer": "Protection of data at rest"
    },
    {
        "question": "When implementing disk encryption, which key management strategy is crucial?",
        "options": [
            "Using weak passwords",
            "Regularly changing encryption keys",
            "Storing keys with the encrypted data",
            "Using a single key for all disks"
        ],
        "answer": "Regularly changing encryption keys"
    },
    {
        "question": "A user wants to encrypt a specific folder rather than the entire disk. Which type of encryption should they consider?",
        "options": [
            "Full disk encryption",
            "File-level encryption",
            "Database encryption",
            "Volume encryption"
        ],
        "answer": "File-level encryption"
    },
    {
        "question": "What is a potential downside of using disk encryption?",
        "options": [
            "Enhanced security",
            "Access speed can be reduced",
            "Ease of data recovery",
            "Simplified key management"
        ],
        "answer": "Access speed can be reduced"
    },

    // Cryptanalysis
    {
        "question": "A cryptanalyst is trying to determine the key used in a cipher without knowing it. What is this process called?",
        "options": [
            "Encryption",
            "Decryption",
            "Brute forcing",
            "Cryptanalysis"
        ],
        "answer": "Cryptanalysis"
    },
    {
        "question": "An organization discovers that its encrypted data was compromised due to weak encryption. What should they consider strengthening?",
        "options": [
            "The hash function used",
            "The encryption algorithm and key length",
            "The data structure",
            "User permissions"
        ],
        "answer": "The encryption algorithm and key length"
    },
    {
        "question": "In a known-plaintext attack, what does the attacker have access to?",
        "options": [
            "Only the ciphertext",
            "The plaintext and the corresponding ciphertext",
            "Only the encryption key",
            "The decryption algorithm"
        ],
        "answer": "The plaintext and the corresponding ciphertext"
    },
    {
        "question": "A cryptanalyst successfully exploits a vulnerability in a cipher's algorithm. What type of attack does this represent?",
        "options": [
            "Social engineering attack",
            "Ciphertext-only attack",
            "Side-channel attack",
            "Cryptanalysis attack"
        ],
        "answer": "Cryptanalysis attack"
    },
    {
        "question": "Which method is often used in cryptanalysis to analyze the frequency of characters in ciphertext?",
        "options": [
            "Brute-force analysis",
            "Frequency analysis",
            "Key space analysis",
            "Statistical analysis"
        ],
        "answer": "Frequency analysis"
    },

    // Cryptography Attack Countermeasures
    {
        "question": "To protect against brute-force attacks on passwords, which measure should be implemented?",
        "options": [
            "Short password length",
            "Multi-factor authentication",
            "Weak password policies",
            "No password complexity rules"
        ],
        "answer": "Multi-factor authentication"
    },
    {
        "question": "An organization is concerned about man-in-the-middle attacks. What countermeasure can they use?",
        "options": [
            "Using encryption for all data in transit",
            "Ignoring SSL/TLS warnings",
            "Allowing public Wi-Fi connections",
            "Disabling authentication methods"
        ],
        "answer": "Using encryption for all data in transit"
    },
    {
        "question": "Which security measure helps protect against replay attacks?",
        "options": [
            "Timestamps in messages",
            "Weak encryption",
            "Fixed session tokens",
            "Static passwords"
        ],
        "answer": "Timestamps in messages"
    },
    {
        "question": "To mitigate risks of key exposure, what practice should organizations adopt?",
        "options": [
            "Hardcoding keys in applications",
            "Using strong key management protocols",
            "Storing keys in plaintext",
            "Sharing keys over unsecured channels"
        ],
        "answer": "Using strong key management protocols"
    },
    {
        "question": "What is an effective way to combat cryptographic attacks targeting weak algorithms?",
        "options": [
            "Continuing to use the old algorithm",
            "Upgrading to stronger encryption standards",
            "Ignoring security advisories",
            "Limiting the use of encryption"
        ],
        "answer": "Upgrading to stronger encryption standards"
    },
    {
        "question": "In which scenario would you use a digital signature?",
        "options": [
            "To encrypt a message",
            "To verify the authenticity of a message",
            "To hash a password",
            "To compress data"
        ],
        "answer": "To verify the authenticity of a message"
    },
    {
        "question": "What is the main purpose of salting a password before hashing?",
        "options": [
            "To speed up the hashing process",
            "To ensure uniqueness and mitigate rainbow table attacks",
            "To encrypt the password",
            "To store the password in plaintext"
        ],
        "answer": "To ensure uniqueness and mitigate rainbow table attacks"
    },
    {
        "question": "Which of the following best describes symmetric encryption?",
        "options": [
            "Uses two different keys for encryption and decryption",
            "Uses the same key for both encryption and decryption",
            "Is slower than asymmetric encryption",
            "Relies on public key infrastructure"
        ],
        "answer": "Uses the same key for both encryption and decryption"
    },
    {
        "question": "What is the purpose of a nonce in cryptographic protocols?",
        "options": [
            "To encrypt data",
            "To prevent replay attacks",
            "To hash passwords",
            "To create public keys"
        ],
        "answer": "To prevent replay attacks"
    },
    {
        "question": "What does the term 'key exchange' refer to in cryptography?",
        "options": [
            "Transmitting keys securely",
            "Storing keys in a secure location",
            "Using keys for encryption and decryption",
            "Generating random keys"
        ],
        "answer": "Transmitting keys securely"
    },

    // Encryption Algorithms
    {
        "question": "Which algorithm is commonly considered broken due to vulnerabilities?",
        "options": [
            "AES",
            "DES",
            "RSA",
            "ECC"
        ],
        "answer": "DES"
    },
    {
        "question": "A company needs to ensure quick decryption of data. Which encryption algorithm is likely the best choice?",
        "options": [
            "AES",
            "RSA",
            "Blowfish",
            "Twofish"
        ],
        "answer": "Blowfish"
    },
    {
        "question": "What is the primary function of the RSA algorithm?",
        "options": [
            "Symmetric encryption",
            "Hashing",
            "Asymmetric encryption",
            "Digital signing"
        ],
        "answer": "Asymmetric encryption"
    },
    {
        "question": "When selecting an encryption algorithm, what is a crucial factor to consider?",
        "options": [
            "Length of the algorithm's name",
            "Key length and complexity",
            "Popularity among users",
            "Cost of implementation"
        ],
        "answer": "Key length and complexity"
    },
    {
        "question": "Which of the following is a feature of the AES encryption standard?",
        "options": [
            "It can only encrypt data in blocks of 64 bits",
            "It supports key lengths of 128, 192, and 256 bits",
            "It is only used in symmetric key systems",
            "It is a hashing algorithm"
        ],
        "answer": "It supports key lengths of 128, 192, and 256 bits"
    },

    // Cryptography Tools
    {
        "question": "Which tool is commonly used for managing SSL/TLS certificates?",
        "options": [
            "GnuPG",
            "OpenSSL",
            "TrueCrypt",
            "FileZilla"
        ],
        "answer": "OpenSSL"
    },
    {
        "question": "What is the function of a password manager?",
        "options": [
            "To encrypt files on the disk",
            "To store and encrypt passwords securely",
            "To generate public-private key pairs",
            "To manage digital certificates"
        ],
        "answer": "To store and encrypt passwords securely"
    },
    {
        "question": "Which cryptographic tool is primarily used for creating secure network communications?",
        "options": [
            "HTTPS",
            "SSH",
            "PGP",
            "NTP"
        ],
        "answer": "SSH"
    },
    {
        "question": "A security engineer is implementing data encryption on a cloud storage solution. Which tool would be the most appropriate?",
        "options": [
            "GnuPG",
            "VeraCrypt",
            "Cloud service provider's encryption solution",
            "Wireshark"
        ],
        "answer": "Cloud service provider's encryption solution"
    },
    {
        "question": "Which type of tool would you use to analyze network traffic for encrypted communications?",
        "options": [
            "Firewall",
            "IDS/IPS",
            "Packet sniffer",
            "VPN"
        ],
        "answer": "Packet sniffer"
    },

    // Public Key Infrastructure (PKI)
    {
        "question": "What role does the Registration Authority (RA) play in PKI?",
        "options": [
            "Issuing digital certificates",
            "Verifying identities before certificate issuance",
            "Revoking certificates",
            "Managing private keys"
        ],
        "answer": "Verifying identities before certificate issuance"
    },
    {
        "question": "In PKI, what does a certificate revocation list (CRL) contain?",
        "options": [
            "A list of valid certificates",
            "A list of expired certificates",
            "A list of revoked certificates",
            "A list of all users"
        ],
        "answer": "A list of revoked certificates"
    },
    {
        "question": "What is the main purpose of using PKI in digital transactions?",
        "options": [
            "To encrypt all data",
            "To provide secure key exchange",
            "To ensure user identities are verified",
            "To create digital signatures"
        ],
        "answer": "To ensure user identities are verified"
    },
    {
        "question": "A user wants to ensure their communications are private using PKI. Which component should they primarily rely on?",
        "options": [
            "Public key",
            "Private key",
            "Digital certificate",
            "Hash function"
        ],
        "answer": "Private key"
    },
    {
        "question": "What is a potential vulnerability in PKI systems?",
        "options": [
            "Strong encryption algorithms",
            "Public key exposure",
            "Digital signatures",
            "Certificate expiration"
        ],
        "answer": "Public key exposure"
    },

    // Email Encryption
    {
        "question": "What is one advantage of using PGP for email encryption?",
        "options": [
            "It does not require a key pair",
            "It is easy to implement for all users",
            "It provides confidentiality and authentication",
            "It is a government-standard encryption"
        ],
        "answer": "It provides confidentiality and authentication"
    },
    {
        "question": "Which protocol is designed to secure email communications by providing encryption and authentication?",
        "options": [
            "IMAP",
            "SMTP",
            "S/MIME",
            "POP3"
        ],
        "answer": "S/MIME"
    },
    {
        "question": "A user sends an encrypted email using PGP. What must the recipient have to decrypt it?",
        "options": [
            "A password",
            "The sender's private key",
            "The recipient's private key",
            "A public key certificate"
        ],
        "answer": "The recipient's private key"
    },
    {
        "question": "When implementing email encryption, what is crucial for maintaining security?",
        "options": [
            "Using the same password for all accounts",
            "Regularly updating encryption keys",
            "Disabling email filters",
            "Using public Wi-Fi for sending emails"
        ],
        "answer": "Regularly updating encryption keys"
    },
    {
        "question": "What is the main challenge associated with using email encryption?",
        "options": [
            "Ensuring confidentiality",
            "Managing key pairs effectively",
            "Providing user education",
            "Securing email servers"
        ],
        "answer": "Managing key pairs effectively"
    },

    // Disk Encryption
    {
        "question": "What is the primary function of disk encryption software?",
        "options": [
            "To optimize disk performance",
            "To secure data at rest",
            "To manage file permissions",
            "To monitor disk usage"
        ],
        "answer": "To secure data at rest"
    },
    {
        "question": "Which encryption method would you use to encrypt an entire hard drive?",
        "options": [
            "File-level encryption",
            "Full disk encryption",
            "Application-level encryption",
            "Database encryption"
        ],
        "answer": "Full disk encryption"
    },
    {
        "question": "What potential issue can arise from using disk encryption?",
        "options": [
            "Increased data accessibility",
            "Loss of access due to forgotten passwords",
            "Improved data integrity",
            "Faster data retrieval"
        ],
        "answer": "Loss of access due to forgotten passwords"
    },
    {
        "question": "Which standard is often used for disk encryption in enterprises?",
        "options": [
            "FIPS 140-2",
            "ISO 27001",
            "PCI DSS",
            "SOX"
        ],
        "answer": "FIPS 140-2"
    },
    {
        "question": "What is a key feature of BitLocker disk encryption?",
        "options": [
            "Works only on Linux",
            "Integrated with Windows operating systems",
            "Requires a third-party application",
            "Exclusively for external drives"
        ],
        "answer": "Integrated with Windows operating systems"
    },

    // Cryptanalysis
    {
        "question": "In a ciphertext-only attack, what does the attacker have access to?",
        "options": [
            "Only the plaintext",
            "Only the ciphertext",
            "The encryption key",
            "The decryption algorithm"
        ],
        "answer": "Only the ciphertext"
    },
    {
        "question": "Which type of attack relies on knowledge of the plaintext and its corresponding ciphertext?",
        "options": [
            "Ciphertext-only attack",
            "Chosen plaintext attack",
            "Known plaintext attack",
            "Brute-force attack"
        ],
        "answer": "Known plaintext attack"
    },
    {
        "question": "A cryptanalyst uses statistical methods to identify patterns in ciphertext. What type of analysis is this?",
        "options": [
            "Brute-force analysis",
            "Frequency analysis",
            "Known plaintext analysis",
            "Chosen ciphertext analysis"
        ],
        "answer": "Frequency analysis"
    },
    {
        "question": "What is a common method to defend against differential cryptanalysis?",
        "options": [
            "Using weak keys",
            "Incorporating non-linear functions in the algorithm",
            "Reducing key length",
            "Using only block ciphers"
        ],
        "answer": "Incorporating non-linear functions in the algorithm"
    },
    {
        "question": "What type of cryptanalysis targets the key management process rather than the algorithm itself?",
        "options": [
            "Ciphertext analysis",
            "Key recovery attack",
            "Linear cryptanalysis",
            "Differential cryptanalysis"
        ],
        "answer": "Key recovery attack"
    },

    // Cryptography Attack Countermeasures
    {
        "question": "To protect sensitive data during transmission, which measure should be employed?",
        "options": [
            "Using plain text",
            "Implementing encryption protocols",
            "Relying on firewalls alone",
            "Using outdated protocols"
        ],
        "answer": "Implementing encryption protocols"
    },
    {
        "question": "What is a primary defense against phishing attacks that exploit encryption weaknesses?",
        "options": [
            "User training and awareness",
            "Regular software updates",
            "Using public Wi-Fi",
            "Ignoring SSL warnings"
        ],
        "answer": "User training and awareness"
    },
    {
        "question": "Which countermeasure helps protect against cryptographic key exposure?",
        "options": [
            "Storing keys in plaintext",
            "Using secure key management practices",
            "Disabling encryption",
            "Hardcoding keys into applications"
        ],
        "answer": "Using secure key management practices"
    },
    {
        "question": "To mitigate risks associated with using outdated encryption algorithms, organizations should:",
        "options": [
            "Continue using the old algorithms",
            "Regularly review and update cryptographic standards",
            "Ignore security advisories",
            "Limit encryption to non-sensitive data"
        ],
        "answer": "Regularly review and update cryptographic standards"
    },
    {
        "question": "What is an effective way to combat potential vulnerabilities in cryptographic implementations?",
        "options": [
            "Using proprietary algorithms",
            "Conducting regular security audits",
            "Neglecting updates",
            "Reusing keys"
        ],
        "answer": "Conducting regular security audits"
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
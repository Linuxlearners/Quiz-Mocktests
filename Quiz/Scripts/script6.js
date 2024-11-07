
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        question: "Alex is attempting to compromise a system by exploiting a vulnerability in the operating system. He uses an exploit to gain access with limited privileges, but now he needs to escalate his privileges to gain full control. What type of attack is Alex performing?",
        options: [
            "Buffer Overflow",
            "Privilege Escalation",
            "Password Cracking",
            "Denial of Service"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "Sarah successfully gains access to a system using an exploited vulnerability. She now wants to ensure that her access remains undetected by creating a backdoor for future access. Which method is most commonly used to maintain access to a compromised system?",
        options: [
            "Keylogging",
            "Rootkit Installation",
            "Password Sniffing",
            "Session Hijacking"
        ],
        answer: "Rootkit Installation"
    },
    {
        question: "An attacker compromises a system and installs a remote access tool (RAT) to ensure continued access even after the initial exploit has been patched. What type of malware is the attacker using to maintain access?",
        options: [
            "Trojan",
            "Backdoor",
            "Worm",
            "Virus"
        ],
        answer: "Backdoor"
    },
    {
        question: "Max is conducting a penetration test and gains root access on a target machine. To avoid detection, he deletes log files that contain evidence of his actions. What is Max trying to cover up?",
        options: [
            "Brute Force Attack",
            "Privilege Escalation",
            "Log Cleansing",
            "Denial of Service"
        ],
        answer: "Log Cleansing"
    },
    {
        question: "During a penetration test, a system is compromised and the attacker needs to ensure that the access remains persistent even after system reboots. Which technique should the attacker use?",
        options: [
            "Install a rootkit",
            "Add a cron job",
            "Modify boot loader",
            "Add a new user with root privileges"
        ],
        answer: "Install a rootkit"
    },
    {
        question: "John is conducting a security audit on a compromised system. The attacker used a tool that hides malicious activity by ensuring that it doesn't appear in system logs. What technique is being used here?",
        options: [
            "Log Spoofing",
            "Log Tampering",
            "Rootkit",
            "Timestamp Manipulation"
        ],
        answer: "Rootkit"
    },
    {
        question: "Nina gains access to a remote system and creates a hidden user account with administrative privileges. The user account remains undetected for future access. What type of attack has Nina performed?",
        options: [
            "Privilege Escalation",
            "Backdoor Creation",
            "Keylogging",
            "Pass-the-Hash Attack"
        ],
        answer: "Backdoor Creation"
    },
    {
        question: "While analyzing a compromised system, you notice that the attacker has replaced important system binaries with modified versions that allow continued access. Which technique has the attacker likely used?",
        options: [
            "Keylogger",
            "Rootkit",
            "Bootkit",
            "Exploit Kit"
        ],
        answer: "Rootkit"
    },
    {
        question: "After exploiting a vulnerability, the attacker wants to make sure that their malicious code survives a system reboot. They modify the system's startup scripts to ensure the malicious code is executed on every reboot. Which method is the attacker using?",
        options: [
            "Startup Trojan",
            "Cron Job Modification",
            "Bootkit",
            "Log Cleaning"
        ],
        answer: "Bootkit"
    },
    {
        question: "A system administrator notices that some files related to the compromised user account have been deleted. The attacker used a tool to clean the logs and remove all traces of their actions. Which tool is likely responsible for this?",
        options: [
            "Nmap",
            "Netcat",
            "Clearev",
            "Metasploit"
        ],
        answer: "Clearev"
    },
    {
        question: "During a penetration test, an attacker exploits a vulnerability in a service running on the target machine to gain access with user privileges. The attacker now wants to escalate privileges to gain administrative access. Which of the following techniques is most likely used?",
        options: [
            "Buffer Overflow",
            "Stack Smashing",
            "Local Privilege Escalation",
            "Denial of Service"
        ],
        answer: "Local Privilege Escalation"
    },
    {
        question: "A hacker has compromised a system and wants to ensure persistent access even after the target machine reboots. The hacker configures a cron job to execute a malicious script on every boot. What type of access is the hacker ensuring?",
        options: [
            "Backdoor Access",
            "Rootkit Installation",
            "Log Cleansing",
            "Fileless Malware"
        ],
        answer: "Backdoor Access"
    },
    {
        question: "Max is working on a test network and gains administrator access. To ensure that he can regain access at a later time, Max installs a remote access tool that can be activated over a network connection. Which type of malware has Max installed?",
        options: [
            "Virus",
            "Worm",
            "Trojan",
            "Rootkit"
        ],
        answer: "Trojan"
    },
    {
        question: "An attacker is attempting to gain administrator access on a system. They try to execute a malicious payload but are stopped by user privilege restrictions. What kind of attack should the attacker attempt to bypass these restrictions?",
        options: [
            "Password Cracking",
            "Privilege Escalation",
            "SQL Injection",
            "Denial of Service"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "After successfully gaining access to a system, the attacker deploys a script that modifies system files to ensure they will not be detected in the event of a reboot. Which technique is the attacker most likely using?",
        options: [
            "Backdoor Creation",
            "Bootkit",
            "Rootkit",
            "Keylogging"
        ],
        answer: "Bootkit"
    },
    {
        question: "An attacker gains unauthorized access to a system and uses a tool to overwrite the event logs to erase evidence of the attack. Which tool or technique is likely being used?",
        options: [
            "Rootkit",
            "Log Cleaning",
            "Backdoor",
            "Keylogger"
        ],
        answer: "Log Cleaning"
    },
    {
        question: "An attacker compromised a web application and exploited a vulnerability to gain unauthorized access. To escalate privileges, they leverage a known privilege escalation technique for the web server's OS. Which of the following is most likely the technique used?",
        options: [
            "Buffer Overflow",
            "Directory Traversal",
            "Local Privilege Escalation",
            "SQL Injection"
        ],
        answer: "Local Privilege Escalation"
    },
    {
        question: "An attacker gains access to a system with low-level user privileges and then uses a system command to switch to root privileges without logging out. Which type of attack is this?",
        options: [
            "Password Cracking",
            "Privilege Escalation",
            "Password Sniffing",
            "Session Hijacking"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "A hacker is attempting to maintain access to a compromised system by creating a hidden user account with administrative privileges. What is this process called?",
        options: [
            "Rootkit Installation",
            "Backdoor Creation",
            "Session Hijacking",
            "Log Tampering"
        ],
        answer: "Backdoor Creation"
    },
    {
        question: "An attacker uses a tool that exploits a system vulnerability to gain root access on a target machine. The tool installs a backdoor to ensure that the attacker can regain access. What is this tool called?",
        options: [
            "Rootkit",
            "Exploit Kit",
            "Keylogger",
            "Trojan Horse"
        ],
        answer: "Rootkit"
    },
    {
        question: "After compromising a server, the attacker wants to remain unnoticed by covering up their tracks. They use a tool that erases system logs that could reveal the time of compromise. What is the attacker using?",
        options: [
            "Clearev",
            "Netcat",
            "Metasploit",
            "Nmap"
        ],
        answer: "Clearev"
    },
    {
        question: "A penetration tester notices that a system has been compromised, but no traces of the attack can be found in the logs. Which method is most likely used to remove the traces of the attack?",
        options: [
            "Rootkit",
            "Log Cleansing",
            "Privilege Escalation",
            "Buffer Overflow"
        ],
        answer: "Log Cleansing"
    },
    {
        question: "An attacker gains access to a system using a phishing attack. After gaining initial access, the attacker escalates privileges using a well-known OS vulnerability. What type of vulnerability is the attacker exploiting?",
        options: [
            "Buffer Overflow",
            "Privilege Escalation",
            "Denial of Service",
            "SQL Injection"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "To avoid detection after gaining access to a target system, the attacker modifies the system's boot loader to execute a malicious script every time the system reboots. What type of attack is this?",
        options: [
            "Backdoor Installation",
            "Bootkit",
            "Rootkit",
            "Privilege Escalation"
        ],
        answer: "Bootkit"
    },
    {
        question: "A hacker gains access to a compromised system and wants to ensure the integrity of the system remains intact even after the system reboots. Which technique will the hacker use to persist the malicious activity?",
        options: [
            "Keylogging",
            "Backdoor Creation",
            "Installing a Rootkit",
            "Cron Job Modification"
        ],
        answer: "Installing a Rootkit"
    },
    {
        question: "The attacker is able to modify system logs to prevent the detection of the attack. What type of malicious activity has the attacker performed?",
        options: [
            "Log Tampering",
            "Privilege Escalation",
            "Buffer Overflow",
            "Worm Infection"
        ],
        answer: "Log Tampering"
    },
    {
        question: "An attacker has compromised an internal web server and needs to elevate their privileges to gain root access. They use an old unpatched vulnerability in the web server’s underlying operating system. Which kind of attack is being executed?",
        options: [
            "Buffer Overflow",
            "Privilege Escalation",
            "SQL Injection",
            "DNS Spoofing"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "While performing a penetration test, you find that the target system has an active backdoor that opens a port on the server for remote access. Which tool might the attacker use to maintain persistent access to the system?",
        options: [
            "Rootkit",
            "Trojan",
            "Netcat",
            "Worm"
        ],
        answer: "Netcat"
    },
    {
        question: "After compromising a system, an attacker installs a malware that modifies core system files and hides them from the operating system. What type of attack is this?",
        options: [
            "Backdoor Installation",
            "Rootkit Deployment",
            "Log Tampering",
            "Privilege Escalation"
        ],
        answer: "Rootkit Deployment"
    },
    {
        question: "A hacker has compromised a system and now wants to remove all traces of the attack from the logs to avoid detection. Which of the following actions should the hacker take?",
        options: [
            "Clear Event Logs",
            "Rootkit Deployment",
            "Escalate Privileges",
            "Modify System Configurations"
        ],
        answer: "Clear Event Logs"
    },
    {
        question: "An attacker uses an exploit to gain access to a system and installs a tool to continuously monitor the system for suspicious activities. This tool also ensures that the attacker can maintain access in the event of a reboot. Which type of tool is this?",
        options: [
            "Rootkit",
            "Keylogger",
            "Backdoor",
            "Exploit Kit"
        ],
        answer: "Rootkit"
    },
    {
        question: "An attacker compromises a system and needs to avoid detection. To do so, the attacker deletes all log files and uses a tool that rewrites the logs to make them appear normal. What is the attacker performing?",
        options: [
            "Log Tampering",
            "Privilege Escalation",
            "Rootkit Installation",
            "Denial of Service"
        ],
        answer: "Log Tampering"
    },
    {
        question: "Max has successfully gained access to a system through a web application vulnerability. To maintain access, he installs a malicious script that executes when the system is rebooted. What technique is Max employing?",
        options: [
            "Rootkit Installation",
            "Backdoor Creation",
            "Log Cleaning",
            "Privilege Escalation"
        ],
        answer: "Backdoor Creation"
    },
    {
        question: "An attacker is able to elevate their privileges on a compromised system by exploiting a known vulnerability in the OS. What type of attack is being used to gain root access?",
        options: [
            "Denial of Service",
            "Privilege Escalation",
            "Password Cracking",
            "Backdoor Installation"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "The attacker uses an exploit that allows them to inject commands into a system and gain root access. To ensure continued access, the attacker installs a rootkit that hides the malicious processes. What is the primary purpose of this rootkit?",
        options: [
            "Exploiting a Vulnerability",
            "Ensuring Persistence",
            "Privilege Escalation",
            "Denial of Service"
        ],
        answer: "Ensuring Persistence"
    },
    {
        question: "After a successful system compromise, an attacker gains access through a vulnerable service. They now want to elevate privileges to perform administrative tasks. What technique would they likely use?",
        options: [
            "Buffer Overflow",
            "Privilege Escalation",
            "SQL Injection",
            "Man-in-the-Middle"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "An attacker gains unauthorized access to a system by exploiting a vulnerability in a web application. They now want to escalate privileges to install malware on the system. What technique would they likely use?",
        options: [
            "Privilege Escalation",
            "Log Tampering",
            "Rootkit Installation",
            "Buffer Overflow"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "An attacker gains access to a system using an old vulnerability in a server’s web application. After successfully exploiting the vulnerability, they install a malicious kernel module to maintain access. What type of malware has the attacker installed?",
        options: [
            "Worm",
            "Rootkit",
            "Keylogger",
            "Botnet"
        ],
        answer: "Rootkit"
    },
    {
        question: "After gaining access to a system, an attacker attempts to make their presence less detectable by altering configuration files to hide suspicious processes. Which technique is the attacker employing?",
        options: [
            "Privilege Escalation",
            "Log Cleansing",
            "Rootkit Installation",
            "System File Modification"
        ],
        answer: "Rootkit Installation"
    },
    {
        question: "Max is testing the security of a Linux system and exploits a vulnerability to gain a low-privileged user account. He now wants to elevate his privileges. Which of the following tools would he most likely use to escalate his privileges?",
        options: [
            "Metasploit",
            "John the Ripper",
            "Sudo Exploit",
            "Nmap"
        ],
        answer: "Sudo Exploit"
    },
    {
        question: "An attacker gains access to a target system and installs a backdoor. They configure the backdoor to automatically start every time the system reboots. Which of the following methods would most likely be used to ensure this persistence?",
        options: [
            "Modify Crontab",
            "Install a Keylogger",
            "Modify System Logs",
            "Password Sniffing"
        ],
        answer: "Modify Crontab"
    },
    {
        question: "An attacker gains access to a system by exploiting a zero-day vulnerability. To cover their tracks, they modify the system logs to erase any trace of the attack. What is the attacker performing?",
        options: [
            "Log Cleansing",
            "Privilege Escalation",
            "Session Hijacking",
            "Port Scanning"
        ],
        answer: "Log Cleansing"
    },
    {
        question: "During a penetration test, an attacker gains access to a system through an application vulnerability. The attacker now needs to cover their traces by modifying log files. What type of tool is likely being used?",
        options: [
            "Clearev",
            "Netcat",
            "Metasploit",
            "Wireshark"
        ],
        answer: "Clearev"
    },
    {
        question: "An attacker gains access to a Windows server using a vulnerability in a service. After gaining access, the attacker installs a malicious rootkit to hide their activity. Which of the following is a common symptom of rootkit activity?",
        options: [
            "Slow system performance",
            "System files missing",
            "Unusual network traffic",
            "Hidden processes or files"
        ],
        answer: "Hidden processes or files"
    },
    {
        question: "An attacker successfully compromises a system with administrative privileges. To maintain access after a system reboot, the attacker installs a malware that hides itself in the system’s startup process. What is the name of this malware?",
        options: [
            "Backdoor",
            "Rootkit",
            "Trojan",
            "Keylogger"
        ],
        answer: "Rootkit"
    },
    {
        question: "During an investigation of a compromised system, an administrator finds evidence of an attacker using a tool to elevate their privileges. The tool was executed by exploiting a vulnerability in the system’s kernel. Which attack is most likely being used?",
        options: [
            "Privilege Escalation",
            "Log Tampering",
            "Denial of Service",
            "Phishing"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "An attacker wants to ensure that their malicious activities persist on a target system even after the system is restarted. Which of the following techniques would be most effective in maintaining persistent access?",
        options: [
            "Installing a bootkit",
            "Rootkit Installation",
            "Keylogging",
            "Installing a botnet"
        ],
        answer: "Installing a bootkit"
    },
    {
        question: "A system administrator notices unusual behavior on a compromised server. Upon investigation, they find that system files have been modified, and hidden files are running in the background. What is the attacker most likely using to maintain access?",
        options: [
            "Botnet",
            "Backdoor",
            "Rootkit",
            "Worm"
        ],
        answer: "Rootkit"
    },
    {
        question: "John is performing a security audit on a server that has been compromised. He notices the attacker installed a kernel module to ensure that the system always boots with malicious code. What technique is being employed by the attacker?",
        options: [
            "Privilege Escalation",
            "Bootkit Installation",
            "Log Tampering",
            "Rootkit Installation"
        ],
        answer: "Bootkit Installation"
    },
    {
        question: "An attacker uses an exploit to gain root access to a Linux server. After gaining access, they want to remove all evidence of the attack. What is the attacker most likely going to do next?",
        options: [
            "Install a rootkit",
            "Clear system logs",
            "Modify kernel parameters",
            "Change user passwords"
        ],
        answer: "Clear system logs"
    },
    {
        question: "An attacker gains unauthorized access to a system and wants to hide their activity from detection. They replace the system’s legitimate kernel with a malicious one that hides their presence. What technique is being used?",
        options: [
            "Rootkit",
            "Worm",
            "Backdoor",
            "Trojan"
        ],
        answer: "Rootkit"
    },
    {
        question: "A hacker compromises a system and installs a malicious kernel module to ensure that their access is not detected. The hacker then modifies the boot loader to execute their code on boot. What is this type of malware called?",
        options: [
            "Rootkit",
            "Bootkit",
            "Backdoor",
            "Spyware"
        ],
        answer: "Bootkit"
    },
    {
        question: "An attacker gains access to a system and installs a remote access tool (RAT) to control the system. To ensure persistence, the RAT is configured to execute automatically every time the system restarts. What method is being employed?",
        options: [
            "Backdoor",
            "Trojan Horse",
            "Worm",
            "Rootkit"
        ],
        answer: "Backdoor"
    },
    {
        question: "After compromising a system, the attacker installs a tool that allows them to continue operating even after the system is restarted. What type of malware is typically used to ensure this persistence?",
        options: [
            "Worm",
            "Keylogger",
            "Rootkit",
            "Backdoor"
        ],
        answer: "Rootkit"
    },
    {
        question: "An attacker uses an exploit to gain access to a system and then escalates privileges to install a tool that hides its presence from detection tools. Which technique is most likely being used?",
        options: [
            "Privilege Escalation",
            "Rootkit Installation",
            "Log Tampering",
            "Port Scanning"
        ],
        answer: "Rootkit Installation"
    },
    {
        question: "During a system compromise, an attacker uses a tool to exploit an unpatched kernel vulnerability to gain root access. After gaining access, the attacker installs a persistent backdoor. What technique did the attacker use to maintain access?",
        options: [
            "Rootkit Installation",
            "Privilege Escalation",
            "Keylogging",
            "Port Scanning"
        ],
        answer: "Rootkit Installation"
    },
    {
        question: "An attacker installs a malware that modifies the system’s boot process to load malicious software automatically. Which type of attack is this?",
        options: [
            "Backdoor",
            "Rootkit",
            "Bootkit",
            "Privilege Escalation"
        ],
        answer: "Bootkit"
    },
    {
        question: "The attacker compromises a system and deletes log files to cover up the attack. What technique is being used to remove traces of the attack?",
        options: [
            "Log Tampering",
            "Keylogging",
            "Privilege Escalation",
            "Session Hijacking"
        ],
        answer: "Log Tampering"
    },
    {
        question: "After compromising a server, an attacker installs a tool to remove the logs containing evidence of the attack. Which tool is most commonly used for this purpose?",
        options: [
            "Clearev",
            "Metasploit",
            "John the Ripper",
            "Nmap"
        ],
        answer: "Clearev"
    },
    {
        question: "An attacker has compromised a system and now wants to cover up the attack by deleting logs and resetting timestamps on the log files. Which method is the attacker likely to use?",
        options: [
            "Clearev",
            "Log Tampering",
            "Rootkit",
            "Privilege Escalation"
        ],
        answer: "Log Tampering"
    },
    {
        question: "An attacker uses an exploit to gain access to a system and escalates their privileges using a known kernel vulnerability. To ensure persistence, they configure the system’s boot loader to run malicious code on startup. What type of attack is this?",
        options: [
            "Privilege Escalation",
            "Rootkit",
            "Bootkit",
            "Backdoor"
        ],
        answer: "Bootkit"
    },
    {
        question: "An attacker gains root access to a compromised system and installs a malicious kernel module that hides the attacker's presence from the system’s logs. What is the most likely attack method?",
        options: [
            "Privilege Escalation",
            "Log Cleansing",
            "Rootkit Installation",
            "Bootkit Installation"
        ],
        answer: "Rootkit Installation"
    },
    {
        question: "An attacker gains access to a system and installs a malware that modifies the boot sequence to execute malicious code each time the system starts up. What type of attack is this?",
        options: [
            "Bootkit",
            "Backdoor",
            "Rootkit",
            "Keylogger"
        ],
        answer: "Bootkit"
    },
    {
        question: "A hacker has compromised a system and installed a tool that allows them to continue accessing the system even after a reboot. The tool is hidden and runs in the background without detection. What type of tool is this?",
        options: [
            "Backdoor",
            "Worm",
            "Rootkit",
            "Trojan"
        ],
        answer: "Rootkit"
    },
    {
        question: "An attacker gains unauthorized access to a system and installs a kernel-level backdoor to maintain persistent access. What kind of malware is the attacker likely using?",
        options: [
            "Worm",
            "Rootkit",
            "Trojan",
            "Botnet"
        ],
        answer: "Rootkit"
    },
    {
        question: "During a penetration test, an attacker exploits a vulnerability in a system’s SSH service to gain access. After exploiting the vulnerability, the attacker wants to ensure that they retain access by installing a hidden backdoor. What technique is the attacker using?",
        options: [
            "Privilege Escalation",
            "Backdoor Installation",
            "SQL Injection",
            "Network Sniffing"
        ],
        answer: "Backdoor Installation"
    },
    {
        question: "Max is performing a penetration test and exploits a system vulnerability to access a target machine. To escalate his privileges, Max attempts to exploit a buffer overflow vulnerability in the system’s kernel. What type of attack is Max trying to execute?",
        options: [
            "Rootkit Installation",
            "Privilege Escalation",
            "SQL Injection",
            "Log Tampering"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "An attacker successfully compromises a system and installs a backdoor that opens port 443 on the machine. The backdoor ensures that the attacker can access the system over SSL. Which type of attack is the attacker using to maintain access?",
        options: [
            "Rootkit",
            "Trojan",
            "Keylogger",
            "Botnet"
        ],
        answer: "Trojan"
    },
    {
        question: "An attacker uses a vulnerability in a web server to gain initial access. They escalate privileges on the target system by exploiting an OS vulnerability in the kernel. What technique is the attacker using?",
        options: [
            "Denial of Service",
            "Privilege Escalation",
            "Buffer Overflow",
            "Network Sniffing"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "After compromising a target machine, the attacker installs a software that creates a hidden user account and monitors system activities for abnormal behavior. The tool ensures that the attacker can regain access at any time. What type of software did the attacker install?",
        options: [
            "Worm",
            "Rootkit",
            "Backdoor",
            "Keylogger"
        ],
        answer: "Rootkit"
    },
    {
        question: "An attacker compromises a system, then attempts to erase all logs and history files that would indicate malicious activity. What is the attacker most likely performing?",
        options: [
            "Privilege Escalation",
            "Log Tampering",
            "Rootkit Installation",
            "Port Scanning"
        ],
        answer: "Log Tampering"
    },
    {
        question: "An attacker gains unauthorized access to a system using an exploit in an outdated web application. After gaining access, the attacker installs a keylogger to capture user credentials. Which type of malware did the attacker use?",
        options: [
            "Backdoor",
            "Rootkit",
            "Trojan",
            "Keylogger"
        ],
        answer: "Keylogger"
    },
    {
        question: "During a penetration test, an attacker exploits a vulnerability to gain access to a target machine. To escalate privileges, the attacker uses a known exploit that allows them to overwrite the system’s critical files. What type of attack is being conducted?",
        options: [
            "Privilege Escalation",
            "Buffer Overflow",
            "Denial of Service",
            "SQL Injection"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "An attacker gains unauthorized access to a system using a brute force attack. After gaining access, the attacker installs a tool that hides their presence by replacing system files with malicious ones. What type of tool did the attacker install?",
        options: [
            "Backdoor",
            "Rootkit",
            "Trojan",
            "Botnet"
        ],
        answer: "Rootkit"
    },
    {
        question: "An attacker compromises a system and installs a backdoor with a malicious payload. The attacker also modifies the system’s startup configuration to ensure the backdoor starts every time the machine reboots. What type of malware is being used?",
        options: [
            "Backdoor",
            "Bootkit",
            "Rootkit",
            "Keylogger"
        ],
        answer: "Bootkit"
    },
    {
        question: "An attacker is able to escalate privileges on a target system by exploiting a vulnerability in the kernel. After gaining root access, they install a tool that allows them to maintain persistent access. What is this tool likely to be?",
        options: [
            "Keylogger",
            "Rootkit",
            "Worm",
            "Botnet"
        ],
        answer: "Rootkit"
    },
    {
        question: "An attacker gains access to a Linux system by exploiting an outdated service. They then modify the system's crontab to ensure a malicious script runs every time the system reboots. What is the attacker trying to achieve?",
        options: [
            "Privilege Escalation",
            "Persistence",
            "Log Tampering",
            "SQL Injection"
        ],
        answer: "Persistence"
    },
    {
        question: "John, a penetration tester, exploits a web server vulnerability and gains access to the target machine. John now wants to escalate his privileges using an OS-level exploit. What type of exploit is John most likely using?",
        options: [
            "Local Privilege Escalation",
            "Buffer Overflow",
            "SQL Injection",
            "Session Hijacking"
        ],
        answer: "Local Privilege Escalation"
    },
    {
        question: "An attacker gains root access to a target machine using a well-known exploit. To cover up their tracks, the attacker deletes logs and resets timestamps. What method is the attacker most likely using to avoid detection?",
        options: [
            "Privilege Escalation",
            "Log Tampering",
            "Backdoor Installation",
            "Rootkit Deployment"
        ],
        answer: "Log Tampering"
    },
    {
        question: "An attacker uses an exploit to gain access to a system and then modifies the system’s boot sequence to load malicious code upon restart. Which type of attack is the attacker performing?",
        options: [
            "Backdoor Installation",
            "Bootkit Installation",
            "Rootkit Installation",
            "Privilege Escalation"
        ],
        answer: "Bootkit Installation"
    },
    {
        question: "An attacker exploits a vulnerability in a target system’s SSH service to gain access. After exploiting the vulnerability, the attacker installs a tool that allows them to maintain access by launching malicious code upon reboot. What is the attacker installing?",
        options: [
            "Rootkit",
            "Bootkit",
            "Trojan",
            "Keylogger"
        ],
        answer: "Bootkit"
    },
    {
        question: "A hacker compromises a system by exploiting a vulnerable FTP service. To escalate privileges, the hacker uses an unpatched kernel vulnerability. What technique is the hacker using to gain elevated privileges?",
        options: [
            "Privilege Escalation",
            "Rootkit Installation",
            "Backdoor Installation",
            "Log Tampering"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "An attacker gains access to a system and escalates privileges using a kernel exploit. To maintain access, the attacker installs a malware that hides the attacker’s processes from the system’s process list. What type of malware is the attacker likely using?",
        options: [
            "Backdoor",
            "Rootkit",
            "Worm",
            "Trojan"
        ],
        answer: "Rootkit"
    },
    {
        question: "During a penetration test, an attacker exploits a vulnerability in a service running on a target system to gain initial access. After successfully compromising the system, the attacker uses a known exploit to escalate privileges to root. What technique is the attacker using?",
        options: [
            "Buffer Overflow",
            "Privilege Escalation",
            "SQL Injection",
            "Phishing"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "Max exploits a vulnerability in a target system to gain access. After gaining control, Max installs a tool that ensures that even after the system restarts, the attacker can maintain access. What is this technique called?",
        options: [
            "Rootkit Installation",
            "Backdoor Installation",
            "Keylogger Installation",
            "Bootkit Installation"
        ],
        answer: "Bootkit Installation"
    },
    {
        question: "An attacker gains access to a Linux system and escalates privileges by exploiting a kernel vulnerability. To maintain persistent access, the attacker installs a rootkit that hides its presence from detection tools. What is this type of malware called?",
        options: [
            "Rootkit",
            "Backdoor",
            "Worm",
            "Botnet"
        ],
        answer: "Rootkit"
    },
    {
        question: "An attacker compromises a system and installs a tool that hides suspicious network traffic to avoid detection. What technique is the attacker employing to evade detection?",
        options: [
            "Rootkit Installation",
            "Log Tampering",
            "Backdoor Installation",
            "Session Hijacking"
        ],
        answer: "Rootkit Installation"
    },
    {
        question: "After compromising a system, the attacker needs to clear logs to avoid detection. What is the best tool for clearing event logs in a Windows environment?",
        options: [
            "Clearev",
            "Metasploit",
            "Wireshark",
            "Nmap"
        ],
        answer: "Clearev"
    },
    {
        question: "An attacker is able to escalate privileges on a system by exploiting a vulnerability in the kernel. After obtaining root access, the attacker installs a malicious payload that modifies system files to avoid detection. What type of attack is the attacker conducting?",
        options: [
            "Privilege Escalation",
            "Log Tampering",
            "Rootkit Installation",
            "Denial of Service"
        ],
        answer: "Rootkit Installation"
    },
    {
        question: "An attacker gains access to a system by exploiting a vulnerability in a web server. After gaining access, the attacker escalates privileges using a local exploit. What technique is being used to escalate privileges?",
        options: [
            "Buffer Overflow",
            "Privilege Escalation",
            "SQL Injection",
            "Worm Deployment"
        ],
        answer: "Privilege Escalation"
    },
    {
        question: "An attacker successfully compromises a system using a kernel vulnerability and gains root access. To maintain access, the attacker installs a custom rootkit that avoids detection by bypassing traditional antivirus scanning. Which advanced technique is the attacker using to ensure stealth?",
        options: [
            "Hooking System Calls",
            "Modifying Kernel Space",
            "Rootkit Polymorphism",
            "Bootkit Installation"
        ],
        answer: "Hooking System Calls"
    },
    {
        question: "An attacker exploits a zero-day vulnerability in the system’s kernel and gains root access. To maintain a low profile, they install a kernel module that hides the attacker’s processes and files from system utilities like 'ps' and 'ls'. Which technique is the attacker likely using?",
        options: [
            "Ring 0 Exploitation",
            "Rootkit Installation",
            "Direct Kernel Object Manipulation (DKOM)",
            "Memory Injection"
        ],
        answer: "Direct Kernel Object Manipulation (DKOM)"
    },
    {
        question: "During a post-exploitation phase, an attacker uses a known privilege escalation vulnerability in a system’s Sudo configuration. However, the attacker also uses an advanced technique to escalate privileges by bypassing system integrity checks and manipulating the ‘/etc/sudoers’ file. What is this technique called?",
        options: [
            "Sudo Caching",
            "Sudo Bypass via PATH Manipulation",
            "Sudoers File Overwrite",
            "Symbolic Link Attack"
        ],
        answer: "Sudo Bypass via PATH Manipulation"
    },
    {
        question: "An attacker gains root access to a target system using an unpatched vulnerability in the kernel. To maintain persistence, the attacker injects malicious code into the kernel’s memory space to hide any suspicious activities. What advanced technique is the attacker using?",
        options: [
            "Process Injection",
            "Kernel Exploitation",
            "Memory-based Rootkit",
            "Firmware Modification"
        ],
        answer: "Memory-based Rootkit"
    },
    {
        question: "After exploiting a vulnerability in the target system’s SSH service, the attacker attempts to cover their tracks by modifying timestamps on files and deleting event logs. Which advanced tool or technique can the attacker use to automate this process and avoid detection?",
        options: [
            "Meterpreter's Event Log Manipulation",
            "PowerShell Empire",
            "LogCleaner",
            "Clearev"
        ],
        answer: "Meterpreter's Event Log Manipulation"
    },
    {
        question: "An attacker gains access to a Windows server and needs to escalate privileges. They use a technique known as 'DLL hijacking' to execute arbitrary code with SYSTEM privileges. Which Windows function is being exploited in this case?",
        options: [
            "CreateProcess",
            "LoadLibrary",
            "SetThreadContext",
            "NtQuerySystemInformation"
        ],
        answer: "LoadLibrary"
    },
    {
        question: "An attacker installs a kernel-level rootkit that intercepts system calls to hide its presence from detection tools. The rootkit modifies system function pointers to redirect calls. What is the name of this technique, which allows the rootkit to remain undetected?",
        options: [
            "Hooking",
            "Bypassing SELinux",
            "Process Injection",
            "Userland Exploitation"
        ],
        answer: "Hooking"
    },
    {
        question: "An attacker gains root access to a Linux system and installs a persistent backdoor by injecting malicious code into the init process (PID 1). This backdoor is designed to remain active even after rebooting. What type of persistence technique is being employed?",
        options: [
            "Bash Script Injection",
            "Initkit",
            "Cronjob Hijacking",
            "Bootkit"
        ],
        answer: "Initkit"
    },
    {
        question: "An attacker gains root access to a system and wants to ensure they can always access the system even if it is rebooted or the network interface is disabled. The attacker uses a technique that allows them to inject their malicious code into a trusted process that starts before the system’s network stack. What is this technique called?",
        options: [
            "Bootkit",
            "BIOS Rootkit",
            "Firmware Manipulation",
            "Injection into Initrd"
        ],
        answer: "Injection into Initrd"
    },
    {
        question: "An attacker gains control over a system by exploiting a vulnerability in the service manager. After obtaining root access, the attacker uses a powerful exploit to inject malicious code into the system's critical memory space. What technique does the attacker use to evade detection from advanced monitoring tools?",
        options: [
            "Memory Injection",
            "Privilege Escalation via sudo",
            "Fileless Malware",
            "Dynamic Link Library Injection"
        ],
        answer: "Fileless Malware"
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
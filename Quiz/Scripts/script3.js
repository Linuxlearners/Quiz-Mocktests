let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
        {
            "question": "What is the primary objective of network scanning?",
            "options": [
                "To exploit vulnerabilities",
                "To identify active devices and services",
                "To monitor network traffic",
                "To analyze application performance"
            ],
            "answer": "To identify active devices and services"
        },
        {
            "question": "Which of the following tools is specifically designed for network scanning?",
            "options": [
                "Wireshark",
                "Metasploit",
                "Nmap",
                "Burp Suite"
            ],
            "answer": "Nmap"
        },
        {
            "question": "What type of scan does Nmap use to identify open ports without establishing a full TCP connection?",
            "options": [
                "SYN scan",
                "UDP scan",
                "Connect scan",
                "Ping scan"
            ],
            "answer": "SYN scan"
        },
        {
            "question": "In the context of host discovery, which ICMP message is typically used to determine if a host is reachable?",
            "options": [
                "ICMP Echo Request",
                "ICMP Time Exceeded",
                "ICMP Destination Unreachable",
                "ICMP Redirect"
            ],
            "answer": "ICMP Echo Request"
        },
        {
            "question": "An attacker performs a port scan and discovers an open SSH port. What can they infer about the target system?",
            "options": [
                "The system is likely using weak passwords.",
                "The system has no security measures.",
                "The system is vulnerable to SQL injection.",
                "The system is not connected to the internet."
            ],
            "answer": "The system is likely using weak passwords."
        },
        {
            "question": "Which scanning technique involves identifying the operating system of a target device?",
            "options": [
                "Port Scanning",
                "OS Fingerprinting",
                "Service Enumeration",
                "Vulnerability Scanning"
            ],
            "answer": "OS Fingerprinting"
        },
        {
            "question": "What is the purpose of banner grabbing?",
            "options": [
                "To gather information about active services",
                "To collect sensitive user credentials",
                "To perform denial-of-service attacks",
                "To bypass firewalls"
            ],
            "answer": "To gather information about active services"
        },
        {
            "question": "What can help to evade detection by an Intrusion Detection System (IDS) during a scan?",
            "options": [
                "Using a slower scanning technique",
                "Scanning during peak hours",
                "Increasing packet sizes",
                "Performing a full TCP handshake"
            ],
            "answer": "Using a slower scanning technique"
        },
        {
            "question": "Which scanning technique is most effective for discovering services running on closed ports?",
            "options": [
                "SYN Scan",
                "TCP Connect Scan",
                "Null Scan",
                "Xmas Tree Scan"
            ],
            "answer": "Null Scan"
        },
        {
            "question": "During network scanning, an attacker uses fragmented packets. What is the primary purpose of this technique?",
            "options": [
                "To bypass firewalls",
                "To speed up scanning",
                "To identify open ports",
                "To confuse network devices"
            ],
            "answer": "To bypass firewalls"
        },
        {
            "question": "Which Nmap option would you use to perform a service version detection scan?",
            "options": [
                "nmap -sP",
                "nmap -sV",
                "nmap -sS",
                "nmap -O"
            ],
            "answer": "nmap -sV"
        },
        {
            "question": "What type of scan is performed when a tester uses the command 'nmap -sA'?",
            "options": [
                "TCP ACK Scan",
                "SYN Scan",
                "TCP Connect Scan",
                "UDP Scan"
            ],
            "answer": "TCP ACK Scan"
        },
        {
            "question": "Which of the following commands in Nmap would perform an operating system detection scan?",
            "options": [
                "-sV",
                "-O",
                "-sS",
                "-sP"
            ],
            "answer": "-O"
        },
        {
            "question": "Which of the following is NOT a technique used for footprinting?",
            "options": [
                "Social Engineering",
                "Network Scanning",
                "Email Injection",
                "Web Scraping"
            ],
            "answer": "Email Injection"
        },
        {
            "question": "What is the purpose of a 'Ping Sweep' in network scanning?",
            "options": [
                "To find the number of open ports",
                "To identify live hosts on a network",
                "To assess network performance",
                "To gather information about services"
            ],
            "answer": "To identify live hosts on a network"
        },
        {
            "question": "What type of information can be gathered through port scanning?",
            "options": [
                "Running services and their versions",
                "Open ports",
                "Potential vulnerabilities",
                "All of the above"
            ],
            "answer": "All of the above"
        },
        {
            "question": "Which technique can be used to detect firewall rules during scanning?",
            "options": [
                "ICMP Redirect",
                "TCP Connect Scan",
                "TCP ACK Scan",
                "Xmas Scan"
            ],
            "answer": "TCP ACK Scan"
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
            "question": "When conducting OS fingerprinting, which method would typically provide the most accurate results?",
            "options": [
                "Banner Grabbing",
                "TCP/IP Stack Fingerprinting",
                "Port Scanning",
                "Network Traffic Analysis"
            ],
            "answer": "TCP/IP Stack Fingerprinting"
        },
        {
            "question": "Which Nmap option would you use to disable reverse DNS resolution?",
            "options": [
                "-n",
                "-sL",
                "-Pn",
                "-r"
            ],
            "answer": "-n"
        },
        {
            "question": "What is the main purpose of network scanning during a penetration test?",
            "options": [
                "To access sensitive data",
                "To evaluate the effectiveness of security controls",
                "To disrupt normal operations",
                "To bypass security measures"
            ],
            "answer": "To evaluate the effectiveness of security controls"
        },
        {
            "question": "Which of the following is a key limitation of using tools like Nmap for scanning?",
            "options": [
                "They cannot perform OS fingerprinting.",
                "They require physical access to the network.",
                "They may produce false positives.",
                "They can only scan open ports."
            ],
            "answer": "They may produce false positives."
        },
        {
            "question": "What is one of the main benefits of using a 'SYN Scan'?",
            "options": [
                "It is stealthy and fast.",
                "It provides detailed service information.",
                "It requires less network bandwidth.",
                "It is more accurate than other scans."
            ],
            "answer": "It is stealthy and fast."
        },
        {
            "question": "An organization employs a firewall that blocks all incoming traffic except for HTTP and HTTPS. How would a penetration tester typically bypass this restriction?",
            "options": [
                "Using a non-standard port for HTTP",
                "Performing a DNS query",
                "Sending fragmented packets",
                "Using SSL/TLS encryption"
            ],
            "answer": "Sending fragmented packets"
        },
        {
            "question": "Which scanning technique is least likely to be detected by IDS?",
            "options": [
                "SYN Scan",
                "TCP Connect Scan",
                "UDP Scan",
                "Stealth Scan"
            ],
            "answer": "Stealth Scan"
        },
        {
            "question": "Which of the following describes a 'TCP Connect Scan'?",
            "options": [
                "It only sends SYN packets.",
                "It establishes a full TCP connection.",
                "It sends FIN packets to detect open ports.",
                "It is a stealthy scanning method."
            ],
            "answer": "It establishes a full TCP connection."
        },
        {
            "question": "What is a key benefit of using network scanning tools during a penetration test?",
            "options": [
                "They can automatically exploit vulnerabilities.",
                "They provide real-time traffic analysis.",
                "They can identify potential attack vectors.",
                "They eliminate the need for manual testing."
            ],
            "answer": "They can identify potential attack vectors."
        },
        {
            "question": "What does the term 'stealth scanning' refer to?",
            "options": [
                "Scanning without sending packets",
                "Using methods to evade detection",
                "Scanning during off-peak hours",
                "Using automated scripts"
            ],
            "answer": "Using methods to evade detection"
        },
        {
            "question": "During a penetration test, a tester finds that the target is using a web application firewall (WAF). What is the primary implication of this finding?",
            "options": [
                "It guarantees that the application is secure.",
                "It may block or alter the behavior of scanning tools.",
                "It indicates that the application has no vulnerabilities.",
                "It makes the application invulnerable to attacks."
            ],
            "answer": "It may block or alter the behavior of scanning tools."
        },
        {
            "question": "Which Nmap command would be used to perform a stealth SYN scan on a target?",
            "options": [
                "nmap -sS <target>",
                "nmap -sT <target>",
                "nmap -sU <target>",
                "nmap -sP <target>"
            ],
            "answer": "nmap -sS <target>"
        },
        {
            "question": "What is the purpose of performing a 'Service Version Detection' scan?",
            "options": [
                "To identify live hosts",
                "To discover operating systems",
                "To determine the versions of services running on open ports",
                "To assess firewall rules"
            ],
            "answer": "To determine the versions of services running on open ports"
        },
        {
            "question": "Which type of scan is used to determine whether a port is open or closed without establishing a full connection?",
            "options": [
                "TCP Connect Scan",
                "SYN Scan",
                "UDP Scan",
                "Ping Scan"
            ],
            "answer": "SYN Scan"
        },
        {
            "question": "What is the primary risk associated with unauthorized network scanning?",
            "options": [
                "It can lead to data loss.",
                "It may compromise the integrity of the scanned devices.",
                "It could trigger legal consequences.",
                "It has no significant risks."
            ],
            "answer": "It could trigger legal consequences."
        },
        {
            "question": "Which technique can be used to avoid detection while scanning networks?",
            "options": [
                "Increasing scan speed",
                "Using common scanning tools",
                "IP Spoofing",
                "Scanning in bulk"
            ],
            "answer": "IP Spoofing"
        },
        {
            "question": "What does the 'host discovery' phase involve during network scanning?",
            "options": [
                "Identifying live hosts on a network",
                "Discovering open ports",
                "Finding network vulnerabilities",
                "Assessing network performance"
            ],
            "answer": "Identifying live hosts on a network"
        },
        {
            "question": "Which of the following describes a 'FIN Scan'?",
            "options": [
                "It sends SYN packets to probe open ports.",
                "It establishes a full TCP connection.",
                "It sends FIN packets to detect open ports.",
                "It uses ICMP messages for detection."
            ],
            "answer": "It sends FIN packets to detect open ports."
        },
        {
            "question": "What type of packets are sent during a 'FIN Scan'?",
            "options": [
                "FIN packets",
                "SYN packets",
                "ACK packets",
                "ICMP packets"
            ],
            "answer": "FIN packets"
        },
        {
            "question": "Which of the following is NOT a countermeasure for network scanning?",
            "options": [
                "Implementing a strong firewall",
                "Using an IDS/IPS",
                "Allowing all incoming traffic",
                "Regularly updating software"
            ],
            "answer": "Allowing all incoming traffic"
        },
        {
            "question": "In which scenario would a 'Stealth Scan' be most useful?",
            "options": [
                "When speed is a priority",
                "To avoid detection by IDS",
                "When probing for UDP ports",
                "When identifying service versions"
            ],
            "answer": "To avoid detection by IDS"
        },
        {
            "question": "What type of information can be gathered through a DNS zone transfer?",
            "options": [
                "User credentials",
                "Hostnames and IP addresses",
                "Network traffic data",
                "Operating system details"
            ],
            "answer": "Hostnames and IP addresses"
        },
        {
            "question": "Which of the following is an effective countermeasure to prevent unauthorized network scanning?",
            "options": [
                "Allow all inbound traffic",
                "Implement network segmentation",
                "Disable firewalls",
                "Use a single-layer security approach"
            ],
            "answer": "Implement network segmentation"
        },    
        {
            "question": "Which of the following techniques helps in determining the network topology during a scan?",
            "options": [
                "Ping Sweeps",
                "Traceroute",
                "Port Scanning",
                "OS Fingerprinting"
            ],
            "answer": "Traceroute"
        },
        {
            "question": "What does a 'UDP Scan' primarily aim to identify?",
            "options": [
                "Open TCP ports",
                "Active services on UDP ports",
                "ICMP responses",
                "All devices on a network"
            ],
            "answer": "Active services on UDP ports"
        },
        {
            "question": "Which tool is known for its ability to perform comprehensive network scans and OS fingerprinting?",
            "options": [
                "Netcat",
                "Nmap",
                "Wireshark",
                "Metasploit"
            ],
            "answer": "Nmap"
        },
        {
            "question": "During a scan, an attacker discovers an open port running a web server. What is the next logical step?",
            "options": [
                "Launch a denial-of-service attack",
                "Perform service enumeration",
                "Change the web server's configuration",
                "Ignore the open port"
            ],
            "answer": "Perform service enumeration"
        },
        {
            "question": "Which type of scan can be used to bypass firewall restrictions by sending fragmented packets?",
            "options": [
                "SYN Scan",
                "FIN Scan",
                "UDP Scan",
                "Fragmented Scan"
            ],
            "answer": "Fragmented Scan"
        },
        {
            "question": "What is the purpose of conducting a 'Null Scan'?",
            "options": [
                "To detect open ports without sending any flags",
                "To send a TCP packet with the RST flag",
                "To establish a full TCP connection",
                "To analyze ICMP traffic"
            ],
            "answer": "To detect open ports without sending any flags"
        },
        {
            "question": "Which of the following Nmap options will perform a quick scan on a target?",
            "options": [
                "-sS",
                "-F",
                "-O",
                "-Pn"
            ],
            "answer": "-F"
        },
        {
            "question": "What is one advantage of using a 'SYN Stealth Scan'?",
            "options": [
                "It is very loud and easily detectable.",
                "It requires a full TCP connection.",
                "It can evade some IDS/IPS systems.",
                "It is faster than a full TCP scan."
            ],
            "answer": "It can evade some IDS/IPS systems."
        },
        {
            "question": "Which type of scanning might reveal a firewall's filtering rules?",
            "options": [
                "TCP Connect Scan",
                "ACK Scan",
                "UDP Scan",
                "Ping Scan"
            ],
            "answer": "ACK Scan"
        },
        {
            "question": "An attacker is scanning for vulnerabilities on a target. What is the primary goal of vulnerability scanning?",
            "options": [
                "To disrupt services",
                "To identify security weaknesses",
                "To perform denial-of-service attacks",
                "To gather user credentials"
            ],
            "answer": "To identify security weaknesses"
        },
        {
            "question": "What is the typical response of a closed port during a TCP SYN scan?",
            "options": [
                "No response",
                "TCP RST packet",
                "TCP SYN-ACK packet",
                "ICMP Destination Unreachable"
            ],
            "answer": "TCP RST packet"
        },
        {
            "question": "Which of the following describes a 'Xmas Tree Scan'?",
            "options": [
                "A scan that sends packets with FIN, URG, and PSH flags set",
                "A scan that only checks for open UDP ports",
                "A simple ping sweep to identify hosts",
                "A standard TCP connect scan"
            ],
            "answer": "A scan that sends packets with FIN, URG, and PSH flags set"
        },
        {
            "question": "When scanning a network, which of the following tools would be least effective for identifying closed ports?",
            "options": [
                "Nmap",
                "Telnet",
                "Netcat",
                "Traceroute"
            ],
            "answer": "Traceroute"
        },
        {
            "question": "What does the '-Pn' option do in Nmap?",
            "options": [
                "Performs a ping scan",
                "Skips the host discovery phase",
                "Performs a full TCP connect scan",
                "Ignores firewalls"
            ],
            "answer": "Skips the host discovery phase"
        },
        {
            "question": "What is a potential drawback of performing network scans during business hours?",
            "options": [
                "Increased likelihood of detection",
                "Reduced scan effectiveness",
                "Greater chance of network disruptions",
                "Inability to access certain services"
            ],
            "answer": "Increased likelihood of detection"
        },
        {
            "question": "Which scanning method is best suited for identifying UDP services on a target network?",
            "options": [
                "SYN Scan",
                "UDP Scan",
                "TCP Connect Scan",
                "Port Scanning"
            ],
            "answer": "UDP Scan"
        },
        {
            "question": "Which of the following is an effective strategy to counteract network scanning?",
            "options": [
                "Deploy honeypots",
                "Use encrypted communication",
                "Allow all traffic to minimize detection",
                "Use outdated software"
            ],
            "answer": "Deploy honeypots"
        },
        {
            "question": "What type of scan would provide information on both open ports and the services running on them?",
            "options": [
                "Service Scan",
                "SYN Scan",
                "ICMP Scan",
                "Ping Scan"
            ],
            "answer": "Service Scan"
        },
        {
            "question": "During network reconnaissance, what is the value of obtaining a list of open ports?",
            "options": [
                "To avoid triggering alarms",
                "To identify potential entry points for attacks",
                "To enhance network speed",
                "To assess user activity"
            ],
            "answer": "To identify potential entry points for attacks"
        },
        {
            "question": "Which of the following is a sign of a possible network scanning activity?",
            "options": [
                "Frequent DNS queries",
                "Unusual spikes in bandwidth usage",
                "A single HTTP request",
                "All of the above"
            ],
            "answer": "All of the above"
        },
        {
            "question": "What is the main purpose of using 'TCP/IP Stack Fingerprinting' during a scan?",
            "options": [
                "To identify the operating system of a target device",
                "To gather information about open ports",
                "To exploit known vulnerabilities",
                "To map the network structure"
            ],
            "answer": "To identify the operating system of a target device"
        },
        {
            "question": "What is the primary objective of network scanning?",
            "options": [
                "To exploit vulnerabilities",
                "To identify active devices and services",
                "To monitor network traffic",
                "To analyze application performance"
            ],
            "answer": "To identify active devices and services"
        },
        {
            "question": "Which of the following tools is specifically designed for network scanning?",
            "options": [
                "Wireshark",
                "Metasploit",
                "Nmap",
                "Burp Suite"
            ],
            "answer": "Nmap"
        },
        {
            "question": "What type of scan does Nmap use to identify open ports without establishing a full TCP connection?",
            "options": [
                "SYN scan",
                "UDP scan",
                "Connect scan",
                "Ping scan"
            ],
            "answer": "SYN scan"
        },
        {
            "question": "In the context of host discovery, which ICMP message is typically used to determine if a host is reachable?",
            "options": [
                "ICMP Echo Request",
                "ICMP Time Exceeded",
                "ICMP Destination Unreachable",
                "ICMP Redirect"
            ],
            "answer": "ICMP Echo Request"
        },
        {
            "question": "An attacker performs a port scan and discovers an open SSH port. What can they infer about the target system?",
            "options": [
                "The system is likely using weak passwords.",
                "The system has no security measures.",
                "The system is vulnerable to SQL injection.",
                "The system is not connected to the internet."
            ],
            "answer": "The system is likely using weak passwords."
        },
        {
            "question": "Which scanning technique involves identifying the operating system of a target device?",
            "options": [
                "Port Scanning",
                "OS Fingerprinting",
                "Service Enumeration",
                "Vulnerability Scanning"
            ],
            "answer": "OS Fingerprinting"
        },
        {
            "question": "What is the purpose of banner grabbing?",
            "options": [
                "To gather information about active services",
                "To collect sensitive user credentials",
                "To perform denial-of-service attacks",
                "To bypass firewalls"
            ],
            "answer": "To gather information about active services"
        },
        {
            "question": "What can help to evade detection by an Intrusion Detection System (IDS) during a scan?",
            "options": [
                "Using a slower scanning technique",
                "Scanning during peak hours",
                "Increasing packet sizes",
                "Performing a full TCP handshake"
            ],
            "answer": "Using a slower scanning technique"
        },
        {
            "question": "Which of the following techniques can be employed to detect firewall rules?",
            "options": [
                "TCP Half-Open Scan",
                "Ping Sweep",
                "UDP Flood",
                "Fragmentation Attack"
            ],
            "answer": "TCP Half-Open Scan"
        },
        {
            "question": "During network scanning, an attacker uses fragmented packets. What is the primary purpose of this technique?",
            "options": [
                "To bypass firewalls",
                "To speed up scanning",
                "To identify open ports",
                "To confuse network devices"
            ],
            "answer": "To bypass firewalls"
        },
        {
            "question": "Which of the following commands in Nmap would perform a service version detection scan?",
            "options": [
                "nmap -sP",
                "nmap -sV",
                "nmap -sS",
                "nmap -O"
            ],
            "answer": "nmap -sV"
        },
        {
            "question": "What type of scan is performed when a tester uses the command 'nmap -sA'?",
            "options": [
                "TCP ACK Scan",
                "SYN Scan",
                "TCP Connect Scan",
                "UDP Scan"
            ],
            "answer": "TCP ACK Scan"
        },
        {
            "question": "Which scanning technique is most effective for discovering services running on closed ports?",
            "options": [
                "SYN Scan",
                "TCP Connect Scan",
                "Null Scan",
                "Xmas Tree Scan"
            ],
            "answer": "Null Scan"
        },
        {
            "question": "When conducting OS fingerprinting, which method would typically provide the most accurate results?",
            "options": [
                "Banner Grabbing",
                "TCP/IP Stack Fingerprinting",
                "Port Scanning",
                "Network Traffic Analysis"
            ],
            "answer": "TCP/IP Stack Fingerprinting"
        },
        {
            "question": "What is the purpose of a 'Ping Sweep' in network scanning?",
            "options": [
                "To find the number of open ports",
                "To identify live hosts on a network",
                "To assess network performance",
                "To gather information about services"
            ],
            "answer": "To identify live hosts on a network"
        },
        {
            "question": "Which of the following methods can help identify a target's operating system?",
            "options": [
                "Traceroute",
                "SNMP Enumeration",
                "TCP Fingerprinting",
                "All of the above"
            ],
            "answer": "All of the above"
        },
        {
            "question": "What is a key benefit of using network scanning tools during a penetration test?",
            "options": [
                "They can automatically exploit vulnerabilities.",
                "They provide real-time traffic analysis.",
                "They can identify potential attack vectors.",
                "They eliminate the need for manual testing."
            ],
            "answer": "They can identify potential attack vectors."
        },
        {
            "question": "An organization employs a firewall that blocks all incoming traffic except for HTTP and HTTPS. How would a penetration tester typically bypass this restriction?",
            "options": [
                "Using a non-standard port for HTTP",
                "Performing a DNS query",
                "Sending fragmented packets",
                "Using SSL/TLS encryption"
            ],
            "answer": "Sending fragmented packets"
        },
        {
            "question": "Which Nmap option would you use to disable reverse DNS resolution?",
            "options": [
                "-n",
                "-sL",
                "-Pn",
                "-r"
            ],
            "answer": "-n"
        },
        {
            "question": "Which scanning tool is primarily used for OS discovery and service version detection?",
            "options": [
                "Wireshark",
                "Nessus",
                "Nmap",
                "Netcat"
            ],
            "answer": "Nmap"
        },
        {
            "question": "What is the potential drawback of using aggressive scanning techniques?",
            "options": [
                "They are less accurate.",
                "They may trigger alerts in security systems.",
                "They provide less information.",
                "They require more time."
            ],
            "answer": "They may trigger alerts in security systems."
        },
        {
            "question": "Which type of scan is least likely to be detected by IDS?",
            "options": [
                "SYN Scan",
                "TCP Connect Scan",
                "UDP Scan",
                "Stealth Scan"
            ],
            "answer": "Stealth Scan"
        },
        {
            "question": "What does the term 'stealth scanning' refer to?",
            "options": [
                "Scanning without sending packets",
                "Using methods to evade detection",
                "Scanning during off-peak hours",
                "Using automated scripts"
            ],
            "answer": "Using methods to evade detection"
        },
        {
            "question": "What type of information can be gathered through port scanning?",
            "options": [
                "Running services and their versions",
                "Open ports",
                "Potential vulnerabilities",
                "All of the above"
            ],
            "answer": "All of the above"
        },
        {
            "question": "Which of the following is a technique to detect firewall rules during scanning?",
            "options": [
                "ICMP Redirect",
                "TCP Connect Scan",
                "TCP ACK Scan",
                "Xmas Scan"
            ],
            "answer": "TCP ACK Scan"
        },
        {
            "question": "When conducting a UDP scan, which Nmap option is used?",
            "options": [
                "-sU",
                "-sS",
                "-sP",
                "-sT"
            ],
            "answer": "-sU"
        },
        {
            "question": "An attacker utilizes a technique that sends packets to various ports to determine which are open. This method is known as:",
            "options": [
                "Service Enumeration",
                "Port Scanning",
                "OS Fingerprinting",
                "Network Mapping"
            ],
            "answer": "Port Scanning"
        },
        {
            "question": "During a penetration test, a tester finds that the target is using a web application firewall (WAF). What is the primary implication of this finding?",
            "options": [
                "It guarantees that the application is secure.",
                "It may block or alter the behavior of scanning tools.",
                "It is a sign of poor security practices.",
                "It indicates a lack of network security."
            ],
            "answer": "It may block or alter the behavior of scanning tools."
        },
        {
            "question": "Which command in Nmap can be used to perform an operating system detection scan?",
            "options": [
                "-sV",
                "-O",
                "-sS",
                "-sP"
            ],
            "answer": "-O"
        },
        {
            "question": "What is the primary risk associated with unauthorized network scanning?",
            "options": [
                "It can lead to data loss.",
                "It may compromise the integrity of the scanned devices.",
                "It could trigger legal consequences.",
                "It has no significant risks."
            ],
            "answer": "It could trigger legal consequences."
        },
        {
            "question": "Which technique can be used to avoid detection while scanning networks?",
            "options": [
                "Increasing scan speed",
                "Using common scanning tools",
                "IP Spoofing",
                "Scanning in bulk"
            ],
            "answer": "IP Spoofing"
        },
        {
            "question": "What does the 'host discovery' phase involve during network scanning?",
            "options": [
                "Identifying live hosts on a network",
                "Discovering open ports",
                "Finding network vulnerabilities",
                "Assessing network performance"
            ],
            "answer": "Identifying live hosts on a network"
        },
        {
            "question": "Which of the following describes a 'TCP Connect Scan'?",
            "options": [
                "It only sends SYN packets.",
                "It establishes a full TCP connection.",
                "It sends FIN packets to detect open ports.",
                "It is a stealthy scanning method."
            ],
            "answer": "It establishes a full TCP connection."
        },
        {
            "question": "What type of packets are sent during a 'FIN Scan'?",
            "options": [
                "FIN packets",
                "SYN packets",
                "ACK packets",
                "ICMP packets"
            ],
            "answer": "FIN packets"
        },
        {
            "question": "Which of the following is NOT a countermeasure for network scanning?",
            "options": [
                "Implementing a strong firewall",
                "Using an IDS/IPS",
                "Allowing all incoming traffic",
                "Regularly updating software"
            ],
            "answer": "Allowing all incoming traffic"
        },
        {
            "question": "In which scenario would a 'Stealth Scan' be most useful?",
            "options": [
                "When speed is a priority",
                "To avoid detection by IDS",
                "When probing for UDP ports",
                "When identifying service versions"
            ],
            "answer": "To avoid detection by IDS"
        },
        {
            "question": "What is the main purpose of network scanning during a penetration test?",
            "options": [
                "To access sensitive data",
                "To evaluate the effectiveness of security controls",
                "To disrupt normal operations",
                "To bypass security measures"
            ],
            "answer": "To evaluate the effectiveness of security controls"
        },
        {
            "question": "Which of the following is a key limitation of using tools like Nmap for scanning?",
            "options": [
                "They cannot perform OS fingerprinting.",
                "They require physical access to the network.",
                "They may produce false positives.",
                "They can only scan open ports."
            ],
            "answer": "They may produce false positives."
        },
        {
            "question": "What is one of the main benefits of using a 'SYN Scan'?",
            "options": [
                "It is stealthy and fast.",
                "It provides detailed service information.",
                "It requires less network bandwidth.",
                "It is more accurate than other scans."
            ],
            "answer": "It is stealthy and fast."
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
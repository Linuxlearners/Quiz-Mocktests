
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [

    {
        question: "Max is a penetration tester monitoring network traffic using a tool like Wireshark. He notices that he can capture the traffic of devices that are not directly connected to his machine. What type of attack is Max most likely using to achieve this?",
        options: [
            "MAC Spoofing",
            "ARP Poisoning",
            "DHCP Spoofing",
            "Man-in-the-Middle Attack"
        ],
        answer: "ARP Poisoning"
    },
    {
        question: "A company has a vulnerable DHCP server, and an attacker is able to send false DHCP responses to clients on the network, causing them to receive incorrect gateway information. What attack is the attacker performing?",
        options: [
            "DHCP Starvation",
            "DHCP Spoofing",
            "DNS Spoofing",
            "ARP Poisoning"
        ],
        answer: "DHCP Spoofing"
    },
    {
        question: "An attacker wants to intercept network traffic between two systems on a local network. To achieve this, the attacker sends spoofed ARP messages to the victims to associate his MAC address with the victim's IP addresses. What is the name of this attack?",
        options: [
            "MAC Spoofing",
            "DNS Poisoning",
            "ARP Poisoning",
            "Man-in-the-Middle Attack"
        ],
        answer: "ARP Poisoning"
    },
    {
        question: "John, a penetration tester, uses a tool that listens to the network traffic on a shared Ethernet segment. He captures packets including user credentials and sensitive data. Which of the following attacks is John most likely performing?",
        options: [
            "DNS Spoofing",
            "Packet Sniffing",
            "MAC Spoofing",
            "TCP Session Hijacking"
        ],
        answer: "Packet Sniffing"
    },
    {
        question: "What is the primary function of a sniffing tool in a network security test?",
        options: [
            "To detect network intrusions",
            "To intercept and capture network traffic",
            "To block unauthorized traffic",
            "To scan for malware within packets"
        ],
        answer: "To intercept and capture network traffic"
    },
    {
        question: "During a penetration test, Max uses a tool to change the MAC address of his network interface. This allows him to bypass security mechanisms based on MAC addresses. What type of attack is Max performing?",
        options: [
            "MAC Spoofing",
            "ARP Poisoning",
            "DHCP Spoofing",
            "DNS Spoofing"
        ],
        answer: "MAC Spoofing"
    },
    {
        question: "Which of the following sniffing techniques can be used to intercept DNS traffic and return malicious IP addresses to the victim?",
        options: [
            "ARP Poisoning",
            "DNS Spoofing",
            "MAC Spoofing",
            "DHCP Spoofing"
        ],
        answer: "DNS Spoofing"
    },
    {
        question: "Sarah is performing a network sniffing attack and observes that an attacker has poisoned the local ARP cache, causing packets meant for another device to be forwarded to the attacker’s system instead. What kind of attack is being performed?",
        options: [
            "ARP Poisoning",
            "DNS Poisoning",
            "MAC Spoofing",
            "DHCP Spoofing"
        ],
        answer: "ARP Poisoning"
    },
    {
        question: "A penetration tester uses a tool to inject malicious DNS responses to the network clients, causing them to resolve specific domain names to an attacker’s IP address. What is the name of this attack?",
        options: [
            "DNS Spoofing",
            "ARP Poisoning",
            "DHCP Spoofing",
            "Packet Injection"
        ],
        answer: "DNS Spoofing"
    },
    {
        question: "An attacker is able to intercept and alter the communication between a client and a server by placing himself between them in the network path. What type of attack is being executed?",
        options: [
            "DHCP Spoofing",
            "ARP Poisoning",
            "Man-in-the-Middle Attack",
            "DNS Spoofing"
        ],
        answer: "Man-in-the-Middle Attack"
    },
    {
        question: "To avoid detection, an attacker implements a sniffing attack where the captured traffic is encrypted and stored remotely. Which of the following techniques is the attacker most likely using?",
        options: [
            "MAC Spoofing",
            "Data Exfiltration",
            "DNS Spoofing",
            "Packet Sniffing"
        ],
        answer: "Data Exfiltration"
    },
    {
        question: "In a sniffing attack, an attacker uses a tool to capture and analyze network packets. The tool allows the attacker to read plaintext information, such as passwords, in transit. Which of the following is a potential risk in such an attack?",
        options: [
            "Insecure SSL/TLS Encryption",
            "Weak Passwords",
            "Cleartext Transmission of Data",
            "All of the above"
        ],
        answer: "All of the above"
    },
    {
        question: "During a penetration test, a tester uses a tool to capture DHCP packets to reveal sensitive information, such as IP addresses and usernames. What kind of attack is being simulated?",
        options: [
            "DHCP Starvation",
            "DHCP Spoofing",
            "DNS Spoofing",
            "Packet Sniffing"
        ],
        answer: "Packet Sniffing"
    },
    {
        question: "Which of the following sniffing techniques involves sending forged ARP messages to a local network, associating the attacker’s MAC address with the IP address of a legitimate device?",
        options: [
            "ARP Poisoning",
            "MAC Spoofing",
            "DNS Poisoning",
            "DHCP Spoofing"
        ],
        answer: "ARP Poisoning"
    },
    {
        question: "In a network sniffing attack, the attacker is able to manipulate the victim's ARP cache by sending unsolicited ARP replies. What technique is this an example of?",
        options: [
            "MAC Spoofing",
            "ARP Poisoning",
            "DHCP Spoofing",
            "DNS Spoofing"
        ],
        answer: "ARP Poisoning"
    },
    {
        question: "An attacker uses a sniffing tool to inject false DNS responses into the victim's DNS cache, directing them to a malicious website. What type of attack is being carried out?",
        options: [
            "ARP Poisoning",
            "DNS Spoofing",
            "MAC Spoofing",
            "DHCP Spoofing"
        ],
        answer: "DNS Spoofing"
    },
    {
        question: "A company has implemented a security measure to detect and block sniffing attacks by monitoring for unusual ARP traffic. Which countermeasure is the company employing to prevent ARP poisoning attacks?",
        options: [
            "Static ARP Entries",
            "MAC Filtering",
            "DHCP Snooping",
            "Port Security"
        ],
        answer: "Static ARP Entries"
    },
    {
        question: "In an effort to secure a network against sniffing attacks, the IT department implements encrypted communication protocols to protect sensitive data. Which of the following protocols is most commonly used to secure data in transit?",
        options: [
            "FTP",
            "HTTP",
            "SSL/TLS",
            "SMTP"
        ],
        answer: "SSL/TLS"
    },
    {
        question: "Which of the following is NOT a countermeasure for sniffing attacks?",
        options: [
            "Encryption of sensitive data",
            "Use of VPNs",
            "Enabling ARP Spoofing",
            "Switching to secure protocols"
        ],
        answer: "Enabling ARP Spoofing"
    },
    {
        question: "A penetration tester has been tasked with securing a network against sniffing attacks. Which of the following tools would be most effective for detecting and preventing ARP poisoning attacks?",
        options: [
            "Snort",
            "Wireshark",
            "Cain and Abel",
            "Arpwatch"
        ],
        answer: "Arpwatch"
    },
    {
        question: "What is the primary purpose of using tools like Ettercap during sniffing attacks?",
        options: [
            "To intercept and modify traffic",
            "To scan for vulnerabilities",
            "To map network topology",
            "To prevent MAC spoofing"
        ],
        answer: "To intercept and modify traffic"
    },
    {
        question: "What type of sniffing tool is typically used to perform passive network analysis, capturing packets without actively participating in the communication process?",
        options: [
            "Active Sniffer",
            "Passive Sniffer",
            "Man-in-the-Middle",
            "Packet Injector"
        ],
        answer: "Passive Sniffer"
    },
    {
        question: "Which sniffing countermeasure involves dynamically assigning IP addresses and network configurations to clients, helping to avoid ARP poisoning attacks?",
        options: [
            "DHCP Spoofing",
            "DHCP Starvation",
            "DHCP Snooping",
            "Static IP Assignment"
        ],
        answer: "DHCP Snooping"
    },
    {
        question: "An attacker sends a forged ARP message to a network segment, associating their own MAC address with the IP address of the gateway. Which of the following best describes the result of this attack?",
        options: [
            "Man-in-the-Middle Attack",
            "DNS Spoofing",
            "Session Hijacking",
            "Packet Injection"
        ],
        answer: "Man-in-the-Middle Attack"
    },
    {
        question: "A penetration tester monitors the traffic on a network segment using a network tap to collect packets. Which of the following best describes this type of activity?",
        options: [
            "Passive Sniffing",
            "Active Sniffing",
            "Traffic Spoofing",
            "Packet Injection"
        ],
        answer: "Passive Sniffing"
    },
    {
        question: "When performing a sniffing attack, an attacker intercepts unencrypted HTTP traffic that contains login credentials in plaintext. Which technique can the attacker use to capture these credentials?",
        options: [
            "Session Fixation",
            "Man-in-the-Middle",
            "Password Cracking",
            "Data Exfiltration"
        ],
        answer: "Man-in-the-Middle"
    },
    {
        question: "Which type of sniffing attack is used when an attacker sends a specially crafted packet to a target system, manipulating its ARP cache to associate the attacker's MAC address with the target’s IP address?",
        options: [
            "ARP Poisoning",
            "MAC Spoofing",
            "DNS Spoofing",
            "TCP Session Hijacking"
        ],
        answer: "ARP Poisoning"
    },
    {
        question: "In which type of network environment would an attacker be most likely to successfully perform a passive sniffing attack, capturing network traffic from multiple devices?",
        options: [
            "Switching environment",
            "Hub-based network",
            "Firewall-protected network",
            "VPN-based network"
        ],
        answer: "Hub-based network"
    },
    {
        question: "Which of the following is a fundamental characteristic of a sniffing attack in a switched network?",
        options: [
            "The attacker must be on the same physical segment as the target",
            "The attacker must be using a VPN",
            "The attacker must spoof the gateway address",
            "The attacker must gain administrative access to the switch"
        ],
        answer: "The attacker must be on the same physical segment as the target"
    },
    {
        question: "John is performing a sniffing attack by capturing unencrypted packets on a network. He successfully obtains sensitive data, such as usernames and passwords. Which sniffing tool would most likely be used in this type of attack?",
        options: [
            "Wireshark",
            "Nmap",
            "Metasploit",
            "Nessus"
        ],
        answer: "Wireshark"
    },
    {
        question: "A network attack that allows an attacker to intercept and modify data being sent between two systems in an insecure environment is known as which of the following?",
        options: [
            "Man-in-the-Middle Attack",
            "Denial of Service Attack",
            "Brute Force Attack",
            "Dictionary Attack"
        ],
        answer: "Man-in-the-Middle Attack"
    },
    {
        question: "What is the primary purpose of a MAC address in a network, and how can it be exploited during a sniffing attack?",
        options: [
            "The MAC address uniquely identifies the device, and can be spoofed by an attacker to intercept traffic",
            "The MAC address is used for encryption and can be cracked to access encrypted data",
            "The MAC address is associated with IP addresses, and can be used for session hijacking",
            "The MAC address is a layer 3 address that identifies the physical location of devices"
        ],
        answer: "The MAC address uniquely identifies the device, and can be spoofed by an attacker to intercept traffic"
    },
    {
        question: "Which of the following protocols is commonly targeted in sniffing attacks due to the transmission of sensitive information in plaintext format?",
        options: [
            "HTTP",
            "SSH",
            "TLS",
            "IPSec"
        ],
        answer: "HTTP"
    },
    {
        question: "An attacker is able to intercept and capture the traffic of other devices in a local network by exploiting an insecure protocol that sends traffic in unencrypted packets. Which of the following is most likely the protocol being exploited?",
        options: [
            "HTTPS",
            "FTP",
            "SNMP",
            "SSH"
        ],
        answer: "FTP"
    },
    {
        question: "Which method can be used to capture network traffic without actively participating in communication, allowing the attacker to collect data silently?",
        options: [
            "Passive sniffing",
            "Active sniffing",
            "Packet Injection",
            "Port Scanning"
        ],
        answer: "Passive sniffing"
    },
    {
        question: "In a sniffing attack, an attacker uses a tool to capture all packets from a targeted network. However, the packets are not decrypted, and the data remains encrypted. What type of data will the attacker still be able to capture?",
        options: [
            "Encrypted login credentials",
            "Unencrypted metadata like source and destination IP addresses",
            "Unencrypted files transferred through FTP",
            "Encrypted SSL/TLS traffic"
        ],
        answer: "Unencrypted metadata like source and destination IP addresses"
    },
    {
        question: "In which scenario would sniffing be most effective in a switched network?",
        options: [
            "When the attacker is able to configure a switch to port mirror traffic",
            "When the attacker is on a remote network segment",
            "When the attacker uses a VPN to tunnel traffic",
            "When the attacker targets an encrypted network"
        ],
        answer: "When the attacker is able to configure a switch to port mirror traffic"
    },
    {
        question: "Which of the following is a key difference between passive and active sniffing?",
        options: [
            "Passive sniffing does not disrupt the network, while active sniffing requires participation in the communication",
            "Active sniffing is used to capture network traffic in unencrypted form, while passive sniffing captures encrypted data",
            "Active sniffing is used for traffic redirection, while passive sniffing is used for traffic analysis",
            "Passive sniffing always involves man-in-the-middle attacks, while active sniffing is more of a DoS attack"
        ],
        answer: "Passive sniffing does not disrupt the network, while active sniffing requires participation in the communication"
    },
    {
        question: "In a sniffing attack, an attacker captures packets and analyzes the data to extract sensitive information such as usernames and passwords. Which technique is being used to intercept the data?",
        options: [
            "Packet Sniffing",
            "Port Scanning",
            "Session Hijacking",
            "DNS Spoofing"
        ],
        answer: "Packet Sniffing"
    },
    {
        question: "Which of the following tools is used by network administrators to analyze and capture network traffic in order to troubleshoot network-related issues or diagnose performance bottlenecks?",
        options: [
            "Snort",
            "Wireshark",
            "Metasploit",
            "Nmap"
        ],
        answer: "Wireshark"
    },
    {
        question: "What kind of data can an attacker obtain from a sniffing attack when traffic is sent in cleartext and unencrypted?",
        options: [
            "Username and password",
            "Session tokens",
            "Cookies",
            "All of the above"
        ],
        answer: "All of the above"
    },
    {
        question: "Which of the following describes the primary goal of sniffing attacks?",
        options: [
            "Inject malicious packets into the network",
            "Intercept and capture network traffic",
            "Exploit unpatched vulnerabilities",
            "Bypass firewalls and IDS"
        ],
        answer: "Intercept and capture network traffic"
    },
    {
        question: "An attacker is able to capture network traffic, analyze packets, and modify data during transmission. What is the most likely type of attack the attacker is performing?",
        options: [
            "Replay Attack",
            "Man-in-the-Middle Attack",
            "DoS Attack",
            "Buffer Overflow Attack"
        ],
        answer: "Man-in-the-Middle Attack"
    },
    {
        question: "Which sniffing attack technique is used when an attacker captures and modifies the communication between two devices to make it appear as if they are communicating directly, without the victim being aware of the attack?",
        options: [
            "Man-in-the-Middle",
            "Session Fixation",
            "SQL Injection",
            "DNS Spoofing"
        ],
        answer: "Man-in-the-Middle"
    },
    {
        question: "In order to carry out a successful sniffing attack, an attacker must typically have access to which layer of the OSI model?",
        options: [
            "Layer 7 (Application)",
            "Layer 5 (Session)",
            "Layer 3 (Network)",
            "Layer 2 (Data Link)"
        ],
        answer: "Layer 2 (Data Link)"
    },
    {
        question: "Which tool is commonly used to detect and analyze ARP poisoning attacks in a local area network?",
        options: [
            "Wireshark",
            "Cain and Abel",
            "Arpwatch",
            "Metasploit"
        ],
        answer: "Arpwatch"
    },
    {
        question: "Which of the following sniffing tools is specifically designed to capture and analyze wireless traffic?",
        options: [
            "Wireshark",
            "Kismet",
            "Nmap",
            "Burp Suite"
        ],
        answer: "Kismet"
    },
    {
        question: "Max is using a network tool to passively sniff the packets sent over a local network, capturing sensitive information like passwords in plaintext. Which tool is Max most likely using?",
        options: [
            "Nmap",
            "Cain and Abel",
            "Wireshark",
            "Nessus"
        ],
        answer: "Wireshark"
    },
    {
        question: "An attacker uses a tool to create and inject malicious ARP packets into a network, poisoning the ARP cache of nearby devices. Which tool is the attacker most likely using for this purpose?",
        options: [
            "Ettercap",
            "Nmap",
            "Metasploit",
            "Netcat"
        ],
        answer: "Ettercap"
    },
    {
        question: "An attacker uses a tool to intercept and log all network traffic between a client and a server. The attacker is able to see all unencrypted data. Which of the following tools is most likely used for this attack?",
        options: [
            "Metasploit",
            "Wireshark",
            "Cain and Abel",
            "Nessus"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which of the following tools can be used to perform a sniffing attack on both wired and wireless networks?",
        options: [
            "NetStumbler",
            "Aircrack-ng",
            "Ettercap",
            "Wireshark"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which network tool would you use to identify and mitigate ARP poisoning on a switch?",
        options: [
            "Wireshark",
            "NetFlow",
            "ARPwatch",
            "Kismet"
        ],
        answer: "ARPwatch"
    },
    {
        question: "John uses a tool that captures network traffic and analyzes DNS queries to identify potential DNS spoofing. Which tool is John most likely using?",
        options: [
            "Cain and Abel",
            "Ettercap",
            "Wireshark",
            "Nessus"
        ],
        answer: "Wireshark"
    },
    {
        question: "An attacker uses a sniffing tool to analyze network traffic and inject malicious traffic into a connection. What type of tool would be used for this attack?",
        options: [
            "Network Injector",
            "Packet Sniffer",
            "Session Hijacker",
            "Man-in-the-Middle Tool"
        ],
        answer: "Network Injector"
    },
    {
        question: "Which of the following tools is primarily used to perform MITM (Man-in-the-Middle) attacks by injecting malicious content into network traffic?",
        options: [
            "Wireshark",
            "Cain and Abel",
            "Ettercap",
            "Burp Suite"
        ],
        answer: "Ettercap"
    },
    {
        question: "During a penetration test, a tool is used to perform a sniffing attack and capture all packets on the network. The tool is also capable of analyzing the captured packets. Which tool is being used?",
        options: [
            "Metasploit",
            "Ettercap",
            "Wireshark",
            "NetFlow"
        ],
        answer: "Wireshark"
    },
    {
        question: "What is the main function of a tool like Netcat in sniffing attacks?",
        options: [
            "Packet Capture",
            "Network Scanning",
            "Network Traffic Manipulation",
            "Port Scanning"
        ],
        answer: "Network Traffic Manipulation"
    },
    {
        question: "An attacker uses a sniffing tool to inject crafted packets into a network, causing disruptions and potential data loss. What is this type of attack called?",
        options: [
            "Denial of Service",
            "Session Hijacking",
            "Packet Injection",
            "Network Spoofing"
        ],
        answer: "Packet Injection"
    },
    {
        question: "During a sniffing attack, an attacker uses a tool to analyze traffic for insecure protocols like HTTP and FTP. Which tool would the attacker most likely use for this?",
        options: [
            "Cain and Abel",
            "Wireshark",
            "Nmap",
            "Burp Suite"
        ],
        answer: "Wireshark"
    },
    {
        question: "What is the primary objective of sniffing tools such as Wireshark and Ettercap in a penetration test?",
        options: [
            "Identifying vulnerable services",
            "Capturing and analyzing network traffic",
            "Performing brute force attacks",
            "Exploiting network vulnerabilities"
        ],
        answer: "Capturing and analyzing network traffic"
    },
    {
        question: "Which of the following is an effective countermeasure against sniffing attacks that involves restricting unauthorized users from accessing the physical layer of the network?",
        options: [
            "Port Security",
            "Packet Filtering",
            "Firewall Rules",
            "Encryption"
        ],
        answer: "Port Security"
    },
    {
        question: "A company implements the use of encrypted communication protocols such as HTTPS and SSH to protect sensitive data during transmission. What is this an example of?",
        options: [
            "Packet Filtering",
            "Port Security",
            "Encryption",
            "Intrusion Detection"
        ],
        answer: "Encryption"
    },
    {
        question: "Which of the following tools can be used to detect ARP poisoning on a network and prevent unauthorized ARP responses?",
        options: [
            "Snort",
            "Wireshark",
            "ARPwatch",
            "Nmap"
        ],
        answer: "ARPwatch"
    },
    {
        question: "To protect a wireless network from sniffing attacks, what is the most effective countermeasure that involves securing the wireless communication?",
        options: [
            "WPA2 Encryption",
            "WEP Encryption",
            "MAC Filtering",
            "SSID Hiding"
        ],
        answer: "WPA2 Encryption"
    },
    {
        question: "What is the primary purpose of using secure communication protocols like TLS and SSL in a network to mitigate sniffing attacks?",
        options: [
            "To enable faster data transfer",
            "To encrypt data in transit",
            "To authenticate network devices",
            "To block unauthorized traffic"
        ],
        answer: "To encrypt data in transit"
    },
    {
        question: "Which of the following methods prevents unauthorized sniffing on a network by ensuring that only authenticated devices are allowed to communicate with the switch?",
        options: [
            "Port Security",
            "DHCP Snooping",
            "Switch Port Mirroring",
            "Access Control Lists"
        ],
        answer: "Port Security"
    },
    {
        question: "A company configures its switches to use static MAC address tables and restricts dynamic learning. What countermeasure is this in place to prevent?",
        options: [
            "ARP Poisoning",
            "MAC Spoofing",
            "Port Scanning",
            "Session Hijacking"
        ],
        answer: "MAC Spoofing"
    },
    {
        question: "Which of the following is a valid countermeasure to prevent sniffing attacks in a switched network by preventing unnecessary broadcast traffic?",
        options: [
            "Port Security",
            "VLAN Segmentation",
            "MAC Filtering",
            "VPN Encryption"
        ],
        answer: "VLAN Segmentation"
    },
    {
        question: "Which of the following solutions prevents ARP poisoning by filtering ARP packets that are not explicitly allowed by the network's security policies?",
        options: [
            "Static ARP entries",
            "Dynamic ARP Inspection",
            "DHCP Spoofing Prevention",
            "Port Security"
        ],
        answer: "Dynamic ARP Inspection"
    },
    {
        question: "What is the purpose of implementing a Virtual Private Network (VPN) to protect against sniffing attacks?",
        options: [
            "To hide IP addresses",
            "To secure encrypted communication over untrusted networks",
            "To block unauthorized traffic",
            "To disable ARP attacks"
        ],
        answer: "To secure encrypted communication over untrusted networks"
    },
    {
        question: "In a scenario where an attacker intercepts and modifies DNS responses on a network, what technique is the attacker most likely using to carry out this attack?",
        options: [
            "DNS Spoofing",
            "TCP Hijacking",
            "ARP Poisoning",
            "DNS Amplification"
        ],
        answer: "DNS Spoofing"
    },
    {
        question: "A penetration tester captures a TCP handshake during a sniffing attack. The captured traffic includes a sequence of SYN, SYN-ACK, and ACK packets. What does this handshake indicate?",
        options: [
            "A session hijacking attempt",
            "An established TCP connection",
            "An ARP poisoning attack",
            "A DNS spoofing attempt"
        ],
        answer: "An established TCP connection"
    },
    {
        question: "What is the term for the technique that allows an attacker to intercept network traffic between two systems and silently modify the content without either party knowing?",
        options: [
            "Man-in-the-Middle Attack",
            "Replay Attack",
            "Session Hijacking",
            "TCP Injection"
        ],
        answer: "Man-in-the-Middle Attack"
    },
    {
        question: "Which type of attack involves the attacker intercepting the communication between a client and a server to inject malicious code, causing the server to perform unintended actions?",
        options: [
            "DNS Spoofing",
            "Session Fixation",
            "Man-in-the-Middle Attack",
            "Cross-Site Scripting (XSS)"
        ],
        answer: "Man-in-the-Middle Attack"
    },
    {
        question: "An attacker uses a sniffer to intercept communication between two devices on a network segment. The attacker then modifies the data, injecting malicious payloads into the data stream. What type of attack is this?",
        options: [
            "Packet Injection",
            "DoS Attack",
            "DNS Spoofing",
            "Session Fixation"
        ],
        answer: "Packet Injection"
    },
    {
        question: "An attacker successfully intercepts and decrypts HTTPS traffic between a client and a server. What type of attack does this demonstrate?",
        options: [
            "SSL Stripping",
            "TLS Downgrade Attack",
            "Man-in-the-Middle Attack",
            "Session Hijacking"
        ],
        answer: "SSL Stripping"
    },
    {
        question: "An attacker implements a sniffing attack in a network segment to capture traffic between devices on a Layer 2 switch. The attacker then forwards the sniffed traffic to an external IP address. What is the attacker using to achieve this?",
        options: [
            "VLAN Hopping",
            "MAC Flooding",
            "Port Mirroring",
            "ARP Poisoning"
        ],
        answer: "Port Mirroring"
    },
    {
        question: "Which of the following best describes an attacker who uses a packet injection tool to send spoofed ICMP packets that redirect traffic to the attacker’s system?",
        options: [
            "ICMP Flooding",
            "ARP Poisoning",
            "TCP Injection",
            "ICMP Redirect Attack"
        ],
        answer: "ICMP Redirect Attack"
    },
    {
        question: "What is the name of the attack that allows an attacker to forge ARP responses to associate their MAC address with the victim's IP address, leading to the interception of traffic?",
        options: [
            "ARP Spoofing",
            "DNS Spoofing",
            "Man-in-the-Middle Attack",
            "TCP Injection"
        ],
        answer: "ARP Spoofing"
    },
    {
        question: "Which of the following can be used to mitigate sniffing attacks in wireless networks by preventing unencrypted data transmission?",
        options: [
            "WEP Encryption",
            "WPA Encryption",
            "Static MAC Filtering",
            "VLAN Segmentation"
        ],
        answer: "WPA Encryption"
    },
    {
        question: "Which of the following is the most advanced method an attacker can use to circumvent encrypted communications and successfully intercept cleartext traffic?",
        options: [
            "SSL Stripping",
            "SSL Pinning",
            "Session Hijacking",
            "MITM on TLS Handshake"
        ],
        answer: "MITM on TLS Handshake"
    },
    {
        question: "In a switch-based network, an attacker successfully floods the switch's MAC address table with fake MAC addresses, causing the switch to forward all traffic to the attacker's device. Which attack is being executed?",
        options: [
            "ARP Spoofing",
            "MAC Flooding",
            "VLAN Hopping",
            "Port Scanning"
        ],
        answer: "MAC Flooding"
    },
    {
        question: "An attacker captures a series of packets between two devices in a TCP session. The attacker then uses the sequence number from an earlier packet to inject malicious data into the session. What is this attack called?",
        options: [
            "TCP Hijacking",
            "Packet Sniffing",
            "Session Fixation",
            "TCP Spoofing"
        ],
        answer: "TCP Hijacking"
    },
    {
        question: "An attacker uses a tool to monitor DNS traffic in a network, identifying and redirecting DNS requests to malicious servers. Which type of attack is the attacker executing?",
        options: [
            "DNS Spoofing",
            "ICMP Redirect Attack",
            "ARP Poisoning",
            "Session Fixation"
        ],
        answer: "DNS Spoofing"
    },
    {
        question: "Which protocol can be exploited during a sniffing attack to steal credentials from a victim due to its lack of encryption in transmitting sensitive information?",
        options: [
            "SMTP",
            "FTP",
            "IMAP",
            "SSH"
        ],
        answer: "FTP"
    },
    {
        question: "When an attacker intercepts encrypted traffic and downgrades it to an unencrypted protocol to read the contents, what type of attack is this known as?",
        options: [
            "TLS Downgrade Attack",
            "Man-in-the-Middle Attack",
            "Replay Attack",
            "Session Hijacking"
        ],
        answer: "TLS Downgrade Attack"
    },
    {
        question: "Which technique can an attacker use to prevent the victim from detecting their presence on the network when sniffing or injecting traffic?",
        options: [
            "MAC Spoofing",
            "TCP Sequence Number Prediction",
            "SSL/TLS Downgrade",
            "Session Fixation"
        ],
        answer: "MAC Spoofing"
    },
    {
        question: "In which scenario would an attacker leverage a sniffing attack to perform an on-path attack and silently modify data between the two communicating systems?",
        options: [
            "ARP Poisoning",
            "ICMP Redirect",
            "Port Scanning",
            "VLAN Hopping"
        ],
        answer: "ARP Poisoning"
    },
    {
        question: "Which layer of the OSI model does a sniffing attack target when an attacker intercepts traffic that flows through switches and performs packet sniffing?",
        options: [
            "Layer 2 (Data Link)",
            "Layer 3 (Network)",
            "Layer 4 (Transport)",
            "Layer 7 (Application)"
        ],
        answer: "Layer 2 (Data Link)"
    },
    {
        question: "An attacker uses a tool that can intercept network traffic, manipulate the data, and relay it to the intended destination without the victim's knowledge. Which tool is likely being used?",
        options: [
            "Ettercap",
            "Nessus",
            "Wireshark",
            "NetFlow"
        ],
        answer: "Ettercap"
    },
    {
        question: "Which of the following tools would be the best for a penetration tester to monitor and analyze network traffic, particularly for detecting sniffing or other traffic anomalies?",
        options: [
            "Metasploit",
            "Wireshark",
            "Burp Suite",
            "Nmap"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which command in `Ettercap` is used to launch an ARP poisoning attack in order to intercept traffic between the target machine and the router?",
        options: [
            "ettercap -M ARP",
            "ettercap -T -q -i eth0 -M ARP",
            "ettercap -T -M ARP:remote",
            "ettercap -M ARP:attack"
        ],
        answer: "ettercap -T -q -i eth0 -M ARP"
    },
    {
        question: "Which advanced sniffing tool is specifically designed for sniffing wireless network traffic and includes features such as capturing packets and cracking WEP keys?",
        options: [
            "Wireshark",
            "Aircrack-ng",
            "Cain and Abel",
            "Nessus"
        ],
        answer: "Aircrack-ng"
    },
    {
        question: "Which of the following tools is most commonly used to prevent ARP spoofing by monitoring and inspecting ARP requests and responses in a network?",
        options: [
            "Nmap",
            "Wireshark",
            "Arpwatch",
            "Ettercap"
        ],
        answer: "Arpwatch"
    },
    {
        question: "Which tool allows an attacker to sniff network traffic and reconstruct intercepted SSL/TLS sessions by using a forged certificate?",
        options: [
            "Ettercap",
            "SSLstrip",
            "Netcat",
            "Cain and Abel"
        ],
        answer: "SSLstrip"
    },
    {
        question: "Which tool can be used to generate and inject ICMP redirects into a network, potentially causing traffic to be routed through the attacker's machine?",
        options: [
            "Ettercap",
            "Cain and Abel",
            "Hping3",
            "Netcat"
        ],
        answer: "Hping3"
    },
    {
        question: "What tool can be used to perform a sniffing attack by capturing packets and performing DNS query analysis to detect DNS spoofing?",
        options: [
            "Wireshark",
            "Burp Suite",
            "Nmap",
            "Ettercap"
        ],
        answer: "Wireshark"
    },
    {
        question: "Which of the following techniques is best used to encrypt communications in order to protect against sniffing attacks, ensuring data confidentiality during transmission?",
        options: [
            "HTTPS",
            "WEP",
            "SSLv3",
            "TLS"
        ],
        answer: "TLS"
    },
    {
        question: "An organization implements IPSec VPNs to secure traffic between remote devices and their headquarters. Which sniffing countermeasure is this?",
        options: [
            "Port Security",
            "VPN Encryption",
            "WPA2 Encryption",
            "Dynamic ARP Inspection"
        ],
        answer: "VPN Encryption"
    },
    {
        question: "A company has implemented a network monitoring tool that logs any unauthorized ARP replies, making it easier to detect and mitigate ARP poisoning. What is the name of this countermeasure?",
        options: [
            "ARPwatch",
            "Nessus",
            "Port Security",
            "Wireshark"
        ],
        answer: "ARPwatch"
    },
    {
        question: "Which sniffing countermeasure is most effective for ensuring the confidentiality and integrity of traffic when using wireless networks?",
        options: [
            "WEP Encryption",
            "WPA2 Encryption",
            "SSL",
            "Static MAC Filtering"
        ],
        answer: "WPA2 Encryption"
    },
    {
        question: "Which of the following tools provides real-time ARP inspection to prevent man-in-the-middle (MITM) attacks?",
        options: [
            "Snort",
            "Nessus",
            "Dynamic ARP Inspection",
            "Ettercap"
        ],
        answer: "Dynamic ARP Inspection"
    },
    {
        question: "Which method helps prevent sniffing attacks by limiting the ability of a device to connect to the network based on MAC address?",
        options: [
            "Port Security",
            "Dynamic ARP Inspection",
            "WPA Encryption",
            "VPN Encryption"
        ],
        answer: "Port Security"
    },
    {
        question: "Which of the following protocols provides security against sniffing by encrypting traffic between two parties, preventing unauthorized interception?",
        options: [
            "SMTP",
            "TLS",
            "POP3",
            "SSH"
        ],
        answer: "TLS"
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
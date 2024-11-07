
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
        "question": "Alice is analyzing the RF spectrum around her office and identifies several Wi-Fi networks operating on channel 6. What is the potential issue with this situation?",
        "options": [
            "Increased range",
            "Signal interference",
            "Improved security",
            "Higher data rates"
        ],
        "answer": "Signal interference"
    },
    {
        "question": "During a site survey, Bob finds that several clients are connecting to the same SSID but have varying signal strengths. What could this indicate?",
        "options": [
            "The network is poorly configured.",
            "There are multiple access points.",
            "All clients are using outdated hardware.",
            "Encryption protocols are mismatched."
        ],
        "answer": "There are multiple access points."
    },
    {
        "question": "Charlie notices that a nearby wireless network uses an open SSID. What risks are associated with open wireless networks?",
        "options": [
            "Increased speed",
            "Data privacy issues",
            "Enhanced encryption",
            "Reduced signal strength"
        ],
        "answer": "Data privacy issues"
    },
    {
        "question": "David wants to implement a wireless network for a café. What is the most effective way to secure the network?",
        "options": [
            "Using WEP encryption",
            "Implementing WPA3 encryption",
            "Disabling SSID broadcasting",
            "Limiting access to MAC addresses"
        ],
        "answer": "Implementing WPA3 encryption"
    },
    {
        "question": "Eve discovers a device connected to her home Wi-Fi network that she does not recognize. What is the first step she should take to investigate?",
        "options": [
            "Change the SSID immediately.",
            "Disconnect the device from the network.",
            "Monitor network traffic.",
            "Perform a factory reset on the router."
        ],
        "answer": "Monitor network traffic."
    },
    {
        "question": "A penetration tester discovers a rogue access point mimicking the legitimate network. What type of attack is being executed?",
        "options": [
            "Man-in-the-middle attack",
            "Denial-of-Service attack",
            "Eavesdropping",
            "Session hijacking"
        ],
        "answer": "Man-in-the-middle attack"
    },
    {
        "question": "Frank is configuring a new wireless router. What setting should he prioritize to enhance the network's security?",
        "options": [
            "Changing the default password",
            "Enabling guest access",
            "Using an easily memorable SSID",
            "Disabling firewalls"
        ],
        "answer": "Changing the default password"
    },
    {
        "question": "Grace wants to implement network segmentation on her wireless network. What is a common approach to achieve this?",
        "options": [
            "Using VLANs",
            "Increasing transmit power",
            "Setting a long SSID",
            "Using WEP encryption"
        ],
        "answer": "Using VLANs"
    },
    {
        "question": "Heidi performs a wireless site survey and finds multiple overlapping networks. What potential impact could this have on her own network?",
        "options": [
            "Faster connection speeds",
            "Increased security risks",
            "Signal degradation",
            "Improved redundancy"
        ],
        "answer": "Signal degradation"
    },
    {
        "question": "Ivy is assessing her home network for vulnerabilities. Which tool would be most useful for identifying unauthorized devices?",
        "options": [
            "Packet sniffer",
            "Vulnerability scanner",
            "Network analyzer",
            "Wireless intrusion detection system"
        ],
        "answer": "Wireless intrusion detection system"
    },
    {
        "question": "Jack is troubleshooting a client’s Wi-Fi connection issues. What common problem could cause intermittent connectivity?",
        "options": [
            "Too many devices on the network",
            "High encryption standards",
            "Using 5 GHz frequency only",
            "Strong signal strength"
        ],
        "answer": "Too many devices on the network"
    },
    {
        "question": "A network administrator wants to prevent unauthorized access to the wireless network. Which method would be least effective?",
        "options": [
            "Using WPA2 encryption",
            "Disabling SSID broadcasting",
            "Implementing MAC address filtering",
            "Regularly changing passwords"
        ],
        "answer": "Implementing MAC address filtering"
    },
    {
        "question": "Liam finds that his wireless router is using WEP encryption. What is a primary risk associated with WEP?",
        "options": [
            "It's not compatible with most devices.",
            "It's easily cracked by attackers.",
            "It has no encryption capabilities.",
            "It slows down network speed."
        ],
        "answer": "It's easily cracked by attackers."
    },
    {
        "question": "Mia is analyzing her company's wireless traffic. What could indicate an active man-in-the-middle attack?",
        "options": [
            "Increased latency",
            "Unusual MAC addresses",
            "Multiple DHCP servers",
            "Frequent disconnects"
        ],
        "answer": "Multiple DHCP servers"
    },
    {
        "question": "Noah is using a wireless network analyzer. What information is he likely trying to capture?",
        "options": [
            "Unencrypted passwords",
            "Signal strength readings",
            "Wireless channel utilization",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "Olivia observes a significant increase in the number of connected devices to her Wi-Fi network. What should she check first?",
        "options": [
            "Router firmware updates",
            "Connected device logs",
            "Network encryption type",
            "Signal interference"
        ],
        "answer": "Connected device logs"
    },
    {
        "question": "Paul is setting up a Wi-Fi network in a high-security area. Which wireless security protocol should he prioritize?",
        "options": [
            "WPA2",
            "WEP",
            "WPA",
            "Open system authentication"
        ],
        "answer": "WPA2"
    },
    {
        "question": "Quinn's organization frequently changes the Wi-Fi password for security reasons. What practice should accompany this change?",
        "options": [
            "Notifying all employees",
            "Updating access control lists",
            "Reconfiguring all devices",
            "Enabling guest access"
        ],
        "answer": "Updating access control lists"
    },
    {
        "question": "Rita notices unusual spikes in data usage on her wireless network. What could be a likely cause?",
        "options": [
            "Software updates",
            "A rogue access point",
            "Increased user activity",
            "Faulty hardware"
        ],
        "answer": "A rogue access point"
    },
    {
        "question": "Sam is assessing the security of his office Wi-Fi. Which aspect should he consider most critically?",
        "options": [
            "Access point location",
            "SSID length",
            "Encryption type",
            "Number of devices connected"
        ],
        "answer": "Encryption type"
    },
    {
        "question": "Tina’s laptop is prompting her to connect to a network named 'Free Wi-Fi.' What should she consider before connecting?",
        "options": [
            "The strength of the signal",
            "The network's security risks",
            "The speed of the connection",
            "The number of connected devices"
        ],
        "answer": "The network's security risks"
    },
    {
        "question": "Ursula needs to connect her smartphone to a wireless printer. Which configuration should she prioritize for security?",
        "options": [
            "Using an open network",
            "Connecting through a VPN",
            "Disabling firewalls temporarily",
            "Using Bluetooth instead"
        ],
        "answer": "Connecting through a VPN"
    },
    {
        "question": "Victor's organization is experiencing network slowdowns. What should be his first step in troubleshooting?",
        "options": [
            "Check for firmware updates",
            "Analyze network traffic",
            "Increase bandwidth",
            "Change the SSID"
        ],
        "answer": "Analyze network traffic"
    },
    {
        "question": "Wendy is implementing a guest Wi-Fi network. What is a critical measure she should take to secure it?",
        "options": [
            "Sharing the same credentials as the main network",
            "Enforcing time limits on access",
            "Isolating the guest network from internal resources",
            "Using WEP encryption"
        ],
        "answer": "Isolating the guest network from internal resources"
    },
    {
        "question": "Xander finds a wireless signal in a public place that he wants to connect to. What is his best option to ensure security?",
        "options": [
            "Using the network without any precautions",
            "Connecting via a VPN",
            "Disabling his firewall",
            "Trusting the public network"
        ],
        "answer": "Connecting via a VPN"
    },
    {
        "question": "Yasmine is tasked with auditing the wireless security of a company. What is the first tool she should use?",
        "options": [
            "Network performance monitor",
            "Wireless vulnerability scanner",
            "Penetration testing toolkit",
            "Packet sniffer"
        ],
        "answer": "Wireless vulnerability scanner"
    },
    {
        "question": "Zach is reviewing the logs of his Wi-Fi network. What is a sign that a potential attack may be occurring?",
        "options": [
            "Frequent DHCP requests",
            "Stable connection times",
            "Consistent bandwidth usage",
            "Low latency"
        ],
        "answer": "Frequent DHCP requests"
    },
    {
        "question": "During a security assessment, an organization realizes their wireless network lacks proper encryption. What immediate risk does this pose?",
        "options": [
            "Faster data transmission",
            "Increased user satisfaction",
            "Potential data breaches",
            "Improved connection stability"
        ],
        "answer": "Potential data breaches"
    },
    {
        "question": "A wireless network is configured with both WPA and WEP. Which protocol offers better security?",
        "options": [
            "WPA",
            "WEP",
            "Both are equally secure",
            "Neither is secure"
        ],
        "answer": "WPA"
    },
    {
        "question": "An attacker uses a tool to capture packets from a public Wi-Fi network. What type of attack is this?",
        "options": [
            "Eavesdropping",
            "Denial of Service",
            "Rogue access point",
            "Session hijacking"
        ],
        "answer": "Eavesdropping"
    },
    {
        "question": "A company is using outdated wireless technology. What is a major risk of not upgrading?",
        "options": [
            "Improved compatibility",
            "Increased performance",
            "Exposure to vulnerabilities",
            "Better encryption"
        ],
        "answer": "Exposure to vulnerabilities"
    },
    {
        "question": "An employee connects their personal device to the corporate Wi-Fi without permission. What should the IT department do first?",
        "options": [
            "Disconnect the device immediately",
            "Inform the employee about the policy",
            "Change the Wi-Fi password",
            "Monitor the device activity"
        ],
        "answer": "Inform the employee about the policy"
    },
    {
        "question": "A security consultant is tasked with improving a wireless network's security. Which aspect is most critical?",
        "options": [
            "Increasing signal range",
            "Choosing the right frequency band",
            "Implementing strong encryption",
            "Optimizing network speed"
        ],
        "answer": "Implementing strong encryption"
    },
    {
        "question": "While conducting a penetration test, the tester discovers that an access point is using a weak password. What is the likely vulnerability?",
        "options": [
            "WEP encryption",
            "Weak SSID",
            "Default credentials",
            "Insecure protocols"
        ],
        "answer": "Default credentials"
    },
    {
        "question": "A network administrator discovers a device masquerading as a legitimate access point. What is the most likely type of attack?",
        "options": [
            "Rogue access point",
            "Packet sniffing",
            "DoS attack",
            "Man-in-the-middle attack"
        ],
        "answer": "Rogue access point"
    },
    {
        "question": "A company wants to implement Bluetooth technology for secure communications. What is a primary security consideration?",
        "options": [
            "Signal range limitations",
            "Frequency interference",
            "Device pairing security",
            "Public availability"
        ],
        "answer": "Device pairing security"
    },
    {
        "question": "When configuring a new wireless network, which type of encryption should be avoided due to its known vulnerabilities?",
        "options": [
            "WPA2",
            "WPA3",
            "WEP",
            "AES"
        ],
        "answer": "WEP"
    },
    {
        "question": "An attacker is attempting to capture packets from a wireless network. Which tool would they likely use?",
        "options": [
            "Nmap",
            "Aircrack-ng",
            "Burp Suite",
            "Wireshark"
        ],
        "answer": "Aircrack-ng"
    },
    {
        "question": "A wireless network utilizes EAP-TLS for authentication. What does this imply about the security configuration?",
        "options": [
            "It uses a shared password.",
            "It relies on client certificates.",
            "It's vulnerable to replay attacks.",
            "It requires user-level authentication."
        ],
        "answer": "It relies on client certificates."
    },
    {
        "question": "In the context of Bluetooth hacking, what is a common attack method?",
        "options": [
            "Bluejacking",
            "WEP cracking",
            "Rogue access point",
            "Packet injection"
        ],
        "answer": "Bluejacking"
    },
    {
        "question": "A user notices that their Bluetooth device keeps disconnecting. What could be a likely cause?",
        "options": [
            "Encryption mismatch",
            "Signal interference",
            "Device compatibility",
            "Outdated firmware"
        ],
        "answer": "Signal interference"
    },
    {
        "question": "A company is using a wireless system without proper authentication. What vulnerability does this create?",
        "options": [
            "Unauthorized access",
            "Enhanced performance",
            "Stronger encryption",
            "Improved network management"
        ],
        "answer": "Unauthorized access"
    },
    {
        "question": "While performing a wireless audit, a security analyst identifies several unencrypted access points. What is the immediate risk?",
        "options": [
            "Enhanced data privacy",
            "Potential data interception",
            "Improved network speed",
            "User-friendly connectivity"
        ],
        "answer": "Potential data interception"
    },
    {
        "question": "A penetration tester uses de-authentication attacks to capture WPA2 handshake packets. What is this technique primarily used for?",
        "options": [
            "To exploit weak encryption",
            "To obtain the network password",
            "To disrupt service",
            "To analyze traffic patterns"
        ],
        "answer": "To obtain the network password"
    },
    {
        "question": "During a Bluetooth security assessment, an employee discovers multiple unauthorized devices connected. What is the best immediate response?",
        "options": [
            "Disconnect all devices",
            "Investigate the devices' identities",
            "Change the Bluetooth settings",
            "Report to management"
        ],
        "answer": "Investigate the devices' identities"
    },
    {
        "question": "A wireless network is susceptible to various attacks. What countermeasure should be implemented to enhance security?",
        "options": [
            "Disable encryption",
            "Limit SSID visibility",
            "Use default credentials",
            "Regularly update firmware"
        ],
        "answer": "Regularly update firmware"
    },
    {
        "question": "An organization has implemented WPA3 encryption but still experiences issues with unauthorized access. What could be a cause?",
        "options": [
            "Weak passwords",
            "Outdated hardware",
            "Strong encryption algorithms",
            "Increased device compatibility"
        ],
        "answer": "Weak passwords"
    },
    {
        "question": "During a wireless security assessment, a tester finds that several users are connected to a rogue access point. What is the best mitigation strategy?",
        "options": [
            "Reconfigure the legitimate access point",
            "Disconnect all users immediately",
            "Implement network segmentation",
            "Use stronger encryption"
        ],
        "answer": "Implement network segmentation"
    },
    {
        "question": "A company is deploying a wireless network in a public area. What security measure should they prioritize?",
        "options": [
            "Open SSID for convenience",
            "Guest network isolation",
            "WEP encryption for compatibility",
            "Broadcasting the SSID"
        ],
        "answer": "Guest network isolation"
    },
    {
        "question": "A Bluetooth device is configured to be discoverable. What does this imply?",
        "options": [
            "It can be accessed by any nearby device.",
            "It is fully secure.",
            "It has strong authentication measures.",
            "It is hidden from unauthorized users."
        ],
        "answer": "It can be accessed by any nearby device."
    },
    {
        "question": "A hacker is exploiting vulnerabilities in outdated Bluetooth firmware. What type of attack might this represent?",
        "options": [
            "Exploiting known vulnerabilities",
            "Social engineering",
            "Man-in-the-middle attack",
            "Denial of Service"
        ],
        "answer": "Exploiting known vulnerabilities"
    },
    {
        "question": "An organization notices an increase in unauthorized access attempts to their wireless network. What is the first action they should take?",
        "options": [
            "Change the SSID",
            "Increase the encryption level",
            "Implement a captive portal",
            "Monitor network traffic"
        ],
        "answer": "Monitor network traffic"
    },
    {
        "question": "When assessing Bluetooth security, what is an important aspect to consider regarding device pairing?",
        "options": [
            "Public visibility",
            "Connection speed",
            "Authentication method",
            "Data encryption"
        ],
        "answer": "Authentication method"
    },
    {
        "question": "An organization implements WPA3 but allows guest access on the same network. What potential issue arises?",
        "options": [
            "Increased security for guests",
            "Exposure of internal resources",
            "Better network performance",
            "Easier connectivity"
        ],
        "answer": "Exposure of internal resources"
    },
    {
        "question": "A technician is trying to detect nearby Bluetooth devices. Which tool should they use?",
        "options": [
            "Network scanner",
            "Bluetooth sniffer",
            "Packet analyzer",
            "Wi-Fi analyzer"
        ],
        "answer": "Bluetooth sniffer"
    },
    {
        "question": "A wireless network is configured with a strong password but lacks encryption. What vulnerability does this present?",
        "options": [
            "Strong data privacy",
            "Potential data interception",
            "Improved user access",
            "None"
        ],
        "answer": "Potential data interception"
    },
    {
        "question": "During a security audit, an organization discovers that employees are using personal devices on the network. What policy should they enforce?",
        "options": [
            "Allow all devices for convenience",
            "Implement a Bring Your Own Device (BYOD) policy",
            "Disable wireless access",
            "Ignore the issue"
        ],
        "answer": "Implement a Bring Your Own Device (BYOD) policy"
    },
    {
        "question": "A security analyst wants to analyze the security of a wireless network. Which tool would best assist them?",
        "options": [
            "Wireshark",
            "Metasploit",
            "Burp Suite",
            "Nmap"
        ],
        "answer": "Wireshark"
    },
    {
        "question": "An employee accidentally connects to a rogue access point. What immediate risk do they face?",
        "options": [
            "Improved internet speed",
            "Data interception",
            "Better signal strength",
            "Reduced latency"
        ],
        "answer": "Data interception"
    },
    {
        "question": "A company deploys a captive portal for guest Wi-Fi access. What is a primary benefit of this approach?",
        "options": [
            "Increased bandwidth",
            "Enhanced security for internal networks",
            "User authentication before access",
            "Reduced signal interference"
        ],
        "answer": "User authentication before access"
    },
    {
        "question": "While performing a wireless security assessment, a tester uses a tool to crack WPA2 passwords. What is the primary method used?",
        "options": [
            "Brute force attack",
            "Social engineering",
            "Rogue access point",
            "Network sniffing"
        ],
        "answer": "Brute force attack"
    },
    {
        "question": "An organization wants to secure its Bluetooth devices. What is a best practice?",
        "options": [
            "Keep devices discoverable at all times",
            "Use strong, unique passkeys for pairing",
            "Disable encryption",
            "Pair devices in public areas"
        ],
        "answer": "Use strong, unique passkeys for pairing"
    },
    {
        "question": "A user is concerned about their Bluetooth device's security. Which of the following should they do?",
        "options": [
            "Keep Bluetooth enabled at all times",
            "Set the device to non-discoverable mode",
            "Share the device with others",
            "Use the same passkey for all connections"
        ],
        "answer": "Set the device to non-discoverable mode"
    },
    {
        "question": "A company is using a legacy system with outdated wireless security protocols. What is the most immediate action they should take?",
        "options": [
            "Upgrade to the latest security protocols",
            "Continue using the current system",
            "Limit the number of users",
            "Change the SSID"
        ],
        "answer": "Upgrade to the latest security protocols"
    },
    {
        "question": "During a penetration test, a consultant identifies several vulnerable Bluetooth devices. What type of risk does this pose?",
        "options": [
            "Increased compatibility",
            "Potential data breaches",
            "Improved connection speeds",
            "Enhanced user experience"
        ],
        "answer": "Potential data breaches"
    },
    {
        "question": "A network is configured for both 2.4 GHz and 5 GHz bands. What advantage does this provide?",
        "options": [
            "Greater signal interference",
            "Improved bandwidth allocation",
            "Reduced device compatibility",
            "Limited range"
        ],
        "answer": "Improved bandwidth allocation"
    },
    {
        "question": "While using a wireless pen-testing tool, the tester identifies a device with an insecure configuration. What should be their next step?",
        "options": [
            "Exploit the vulnerability",
            "Report the finding",
            "Change the device configuration",
            "Ignore the device"
        ],
        "answer": "Report the finding"
    },
    {
        "question": "A company is using WPA2 but has enabled a weak passphrase for their wireless network. What is the primary risk they face?",
        "options": [
            "Increased connection speed",
            "Exposure to dictionary attacks",
            "Reduced range of the signal",
            "Improved device compatibility"
        ],
        "answer": "Exposure to dictionary attacks"
    },
    {
        "question": "During a wireless penetration test, a tester successfully captures a handshake. What is the next step in cracking the password?",
        "options": [
            "Conducting a replay attack",
            "Using a rainbow table",
            "Performing a denial-of-service attack",
            "Sniffing for additional handshakes"
        ],
        "answer": "Using a rainbow table"
    },
    {
        "question": "A security analyst discovers a neighbor's access point using WPS. What vulnerability does this present?",
        "options": [
            "Weak encryption",
            "Brute force vulnerabilities",
            "Limited range",
            "Increased latency"
        ],
        "answer": "Brute force vulnerabilities"
    },
    {
        "question": "During a site survey, a penetration tester finds multiple APs with the same SSID but different MAC addresses. What attack might this indicate?",
        "options": [
            "Evil twin attack",
            "Packet sniffing",
            "Bluejacking",
            "DoS attack"
        ],
        "answer": "Evil twin attack"
    },
    {
        "question": "A company wants to implement 802.1X for its wireless security. What is the main benefit of this protocol?",
        "options": [
            "Dynamic IP allocation",
            "Port-based network access control",
            "Open network access",
            "Static MAC filtering"
        ],
        "answer": "Port-based network access control"
    },
    {
        "question": "An organization conducts a penetration test and finds a device using an outdated Bluetooth version. What is the primary concern?",
        "options": [
            "Increased compatibility",
            "Higher bandwidth",
            "Known security vulnerabilities",
            "Enhanced signal range"
        ],
        "answer": "Known security vulnerabilities"
    },
    {
        "question": "A wireless network is experiencing performance issues. What is a potential cause related to interference?",
        "options": [
            "Overlapping channels",
            "Strong encryption protocols",
            "Low device count",
            "Proper signal strength"
        ],
        "answer": "Overlapping channels"
    },
    {
        "question": "A user connects to a public Wi-Fi network and performs sensitive transactions. What risk is associated with this action?",
        "options": [
            "Enhanced security",
            "Data interception",
            "Improved speed",
            "Lower latency"
        ],
        "answer": "Data interception"
    },
    {
        "question": "During a security audit, a tester discovers that the company’s wireless devices are configured with default credentials. What risk does this present?",
        "options": [
            "Improved performance",
            "Easy unauthorized access",
            "Enhanced encryption",
            "Reduced attack surface"
        ],
        "answer": "Easy unauthorized access"
    },
    {
        "question": "A network analyst identifies an abnormal amount of traffic on the guest network. What could this indicate?",
        "options": [
            "Increased legitimate use",
            "Potential data exfiltration",
            "Better encryption practices",
            "Improved user authentication"
        ],
        "answer": "Potential data exfiltration"
    },
    {
        "question": "A security team notices that their wireless network is being targeted by a disassociation attack. What is this attack trying to achieve?",
        "options": [
            "To capture data packets",
            "To forcibly disconnect clients",
            "To exploit weak passwords",
            "To gain access to the router"
        ],
        "answer": "To forcibly disconnect clients"
    },
    {
        "question": "In a penetration test, an attacker successfully injects malicious code through a wireless connection. What type of attack is this?",
        "options": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection",
            "Man-in-the-middle attack",
            "Rogue access point"
        ],
        "answer": "Man-in-the-middle attack"
    },
    {
        "question": "During a Bluetooth assessment, a tester captures packets and identifies unencrypted data. What type of vulnerability does this represent?",
        "options": [
            "Weak encryption standards",
            "Unprotected pairing",
            "Insecure connections",
            "All of the above"
        ],
        "answer": "All of the above"
    },
    {
        "question": "An organization wants to prevent unauthorized access through Bluetooth. What measure is least effective?",
        "options": [
            "Disabling visibility",
            "Using pairing passkeys",
            "Regularly updating firmware",
            "Allowing open pairing"
        ],
        "answer": "Allowing open pairing"
    },
    {
        "question": "A technician finds that the AP’s firmware is outdated. What is the primary risk of not updating it?",
        "options": [
            "Improved network performance",
            "Increased vulnerability to exploits",
            "Better compatibility",
            "Enhanced signal strength"
        ],
        "answer": "Increased vulnerability to exploits"
    },
    {
        "question": "During a wireless assessment, an attacker uses an access point that impersonates a legitimate one. What is this attack called?",
        "options": [
            "Rogue AP attack",
            "Packet sniffing",
            "WPS attack",
            "DoS attack"
        ],
        "answer": "Rogue AP attack"
    },
    {
        "question": "A user is connecting to a corporate Wi-Fi network from a remote location. What is the best security practice to follow?",
        "options": [
            "Using a VPN",
            "Connecting directly without precautions",
            "Disabling firewalls",
            "Using public Wi-Fi"
        ],
        "answer": "Using a VPN"
    },
    {
        "question": "An organization implements MAC address filtering for their wireless network. What is a potential downside of this approach?",
        "options": [
            "Improved security",
            "Easier management",
            "Vulnerability to MAC spoofing",
            "Reduced connectivity"
        ],
        "answer": "Vulnerability to MAC spoofing"
    },
    {
        "question": "A penetration tester notices that an organization’s Wi-Fi network has not been changed from its default settings. What immediate action should be recommended?",
        "options": [
            "Ignore the default settings",
            "Change the SSID and password",
            "Reduce the signal strength",
            "Use open access"
        ],
        "answer": "Change the SSID and password"
    },
    {
        "question": "A company is using a captive portal for guest access. What is a critical security consideration for this implementation?",
        "options": [
            "Limiting guest bandwidth",
            "Capturing user credentials securely",
            "Making the portal public",
            "Using unencrypted connections"
        ],
        "answer": "Capturing user credentials securely"
    },
    {
        "question": "An employee reports unauthorized access to their device via Bluetooth. What could be a likely cause?",
        "options": [
            "Weak passkeys",
            "Strong encryption",
            "Non-discoverable mode",
            "Automatic pairing"
        ],
        "answer": "Weak passkeys"
    },
    {
        "question": "A security analyst is investigating a recent breach in a wireless network. What is a primary factor to consider during the investigation?",
        "options": [
            "Signal strength analysis",
            "User activity logs",
            "Firmware versions",
            "Bandwidth usage"
        ],
        "answer": "User activity logs"
    },
    {
        "question": "A network engineer implements VPN access for remote workers. What primary benefit does this provide?",
        "options": [
            "Direct access to internal servers",
            "Encrypted data transmission",
            "Faster internet speeds",
            "Reduced network latency"
        ],
        "answer": "Encrypted data transmission"
    },
    {
        "question": "A company is considering implementing a mesh network for better coverage. What is a potential downside?",
        "options": [
            "Increased redundancy",
            "Higher complexity in management",
            "Lower signal strength",
            "Reduced bandwidth"
        ],
        "answer": "Higher complexity in management"
    },
    {
        "question": "During a penetration test, an attacker uses an application to analyze Bluetooth traffic. What is the primary objective?",
        "options": [
            "To strengthen encryption",
            "To capture sensitive data",
            "To increase device compatibility",
            "To reduce latency"
        ],
        "answer": "To capture sensitive data"
    },
    {
        "question": "An organization finds that its guest network is not properly isolated from its internal network. What risk does this pose?",
        "options": [
            "Increased bandwidth",
            "Potential unauthorized access to internal resources",
            "Improved user experience",
            "Better data encryption"
        ],
        "answer": "Potential unauthorized access to internal resources"
    },
    {
        "question": "During a security assessment, a tester discovers an open Bluetooth connection on a device. What is the main risk?",
        "options": [
            "Improved connectivity",
            "Potential data theft",
            "Increased device performance",
            "None, it's secure"
        ],
        "answer": "Potential data theft"
    },
    {
        "question": "During a wireless security assessment, a penetration tester finds that several devices are using outdated Bluetooth profiles. What is a major risk associated with this?",
        "options": [
            "Increased device compatibility",
            "Potential exploitation of known vulnerabilities",
            "Improved signal range",
            "Lower power consumption"
        ],
        "answer": "Potential exploitation of known vulnerabilities"
    },
    {
        "question": "A company notices unusual traffic patterns originating from its wireless network. What might this indicate?",
        "options": [
            "Normal operation",
            "Possible data exfiltration or compromise",
            "Improved bandwidth usage",
            "User authentication issues"
        ],
        "answer": "Possible data exfiltration or compromise"
    },
    {
        "question": "An attacker uses a tool to conduct a replay attack on a WPA2 network. What is their primary goal?",
        "options": [
            "To capture the handshake",
            "To gain unauthorized access by replaying captured packets",
            "To disable the access point",
            "To sniff traffic"
        ],
        "answer": "To gain unauthorized access by replaying captured packets"
    },
    {
        "question": "During a security review, a network administrator finds that their wireless network allows clients to connect without authentication. What is the most serious implication?",
        "options": [
            "Improved network performance",
            "Potential for unauthorized access",
            "Better user experience",
            "Increased device compatibility"
        ],
        "answer": "Potential for unauthorized access"
    },
    {
        "question": "A wireless penetration tester identifies a device that uses a default SSID and password. What vulnerability does this primarily expose?",
        "options": [
            "Improved user access",
            "Increased risk of unauthorized access",
            "Better encryption",
            "Enhanced performance"
        ],
        "answer": "Increased risk of unauthorized access"
    },
    {
        "question": "During a security assessment, a tester discovers multiple clients connected to an unprotected access point. What immediate action should be taken?",
        "options": [
            "Leave the access point as is",
            "Disconnect all clients",
            "Secure the access point with encryption",
            "Monitor traffic for malicious activity"
        ],
        "answer": "Secure the access point with encryption"
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
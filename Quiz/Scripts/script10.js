
let currentQuestion = 0;
let correctAnswers = 0;
let wrongAnswers = 0;
const questions = [
    {
    question: "A DDoS attack occurs when multiple compromised systems are used to target a single system. Which of the following is the main objective of a DDoS attack?", 
    options: [
        "Unauthorized access to sensitive data", 
        "Disruption of availability by overwhelming the target", 
        "Manipulation of target data", 
        "Escalation of privileges on the target system"
    ], 
    answer: "Disruption of availability by overwhelming the target"
},
{
    question: "A company is experiencing a DDoS attack. The network bandwidth is being exhausted, causing legitimate users to be unable to access services. What type of DDoS attack is most likely in progress?", 
    options: [
        "Application layer attack", 
        "Volume-based attack", 
        "Protocol attack", 
        "Fragmentation attack"
    ], 
    answer: "Volume-based attack"
},
{
    question: "Which type of DDoS attack exploits weaknesses in the target system's network protocols to cause a denial of service?", 
    options: [
        "Application layer attack", 
        "Volume-based attack", 
        "Protocol attack", 
        "Botnet-based attack"
    ], 
    answer: "Protocol attack"
},
{
    question: "In a typical DDoS attack, the victim's resources are overwhelmed. Which of the following is NOT a target for a DDoS attack?", 
    options: [
        "Network bandwidth", 
        "Web server capacity", 
        "CPU of the client machine", 
        "DNS servers"
    ], 
    answer: "CPU of the client machine"
},
{
    question: "A hacker is able to successfully send a large volume of traffic to a target server using botnets and utilizes multiple systems to launch the attack. What is this type of attack called?", 
    options: [
        "Flood attack", 
        "Botnet-based DDoS", 
        "SYN Flood", 
        "Ping of Death"
    ], 
    answer: "Botnet-based DDoS"
},
{
    question: "What is the main reason why DDoS attacks are considered more severe than DoS attacks?", 
    options: [
        "DDoS attacks are easier to trace", 
        "DDoS attacks are distributed across multiple systems, making them harder to mitigate", 
        "DDoS attacks are usually directed at a single machine", 
        "DDoS attacks are less impactful"
    ], 
    answer: "DDoS attacks are distributed across multiple systems, making them harder to mitigate"
},
{
    question: "In which scenario would a DDoS attack be most effective in disrupting business operations?", 
    options: [
        "When the victim’s resources are configured to handle high loads", 
        "When the victim's systems are already compromised by malware", 
        "When the victim has redundant systems in place", 
        "When the victim relies heavily on availability and has no content delivery network"
    ], 
    answer: "When the victim relies heavily on availability and has no content delivery network"
},
{
    question: "Which DDoS attack type is most likely to target and disrupt a victim’s DNS service by flooding it with unnecessary requests?", 
    options: [
        "SYN Flood", 
        "DNS Amplification", 
        "ICMP Flood", 
        "UDP Flood"
    ], 
    answer: "DNS Amplification"
},
{
    question: "A DDoS attack is targeting a website that handles millions of requests per second. The attack is utilizing a significant amount of bandwidth. Which of the following would be the most common type of attack?", 
    options: [
        "ICMP Flood", 
        "DNS Reflection", 
        "Volume-based attack", 
        "SQL Injection"
    ], 
    answer: "Volume-based attack"
},
{
    question: "What is the key difference between DoS and DDoS attacks in terms of the number of attack sources?", 
    options: [
        "DoS attacks use a single attack source, while DDoS attacks use multiple sources", 
        "DoS attacks are more powerful than DDoS attacks", 
        "DoS attacks target local networks, while DDoS attacks target global networks", 
        "There is no significant difference between DoS and DDoS"
    ], 
    answer: "DoS attacks use a single attack source, while DDoS attacks use multiple sources"
},
{
    question: "A DDoS attack utilizes a large number of systems to generate traffic and overwhelm a target. These systems are often infected with malware. What is this collection of infected systems called?", 
    options: [
        "Zombie network", 
        "Botnet", 
        "RAT (Remote Access Trojan)", 
        "SQLi bot"
    ], 
    answer: "Botnet"
},
{
    question: "You are monitoring a network and notice an increase in SYN packets without corresponding ACK responses. What type of attack could this be?", 
    options: [
        "SYN Flood", 
        "UDP Flood", 
        "DNS Amplification", 
        "Ping Flood"
    ], 
    answer: "SYN Flood"
},
{
    question: "Which of the following is a method that attackers use to amplify the size of a DDoS attack by leveraging misconfigured third-party systems?", 
    options: [
        "DNS Amplification", 
        "SYN Flood", 
        "ICMP Flood", 
        "Brute Force Attack"
    ], 
    answer: "DNS Amplification"
},
{
    question: "An attacker launches a DDoS attack using a large number of infected IoT devices, such as cameras and routers. Which of the following would best describe this scenario?", 
    options: [
        "Botnet attack", 
        "Reflective attack", 
        "Amplification attack", 
        "Packet fragmentation attack"
    ], 
    answer: "Botnet attack"
},
{
    question: "A DDoS attack that involves the use of multiple compromised systems to target a specific system is typically known as:", 
    options: [
        "Application layer attack", 
        "SYN Flood", 
        "DDoS", 
        "ICMP Flood"
    ], 
    answer: "DDoS"
},
{
    question: "In a botnet-based DDoS attack, what is the typical role of the botmaster?", 
    options: [
        "Directs the botnet to perform attacks and commands the infected systems", 
        "Prepares the malware to infect vulnerable systems", 
        "Distributes antivirus software to compromised systems", 
        "Manages the network traffic to prevent detection"
    ], 
    answer: "Directs the botnet to perform attacks and commands the infected systems"
},
{
    question: "Which of the following best describes a ‘reflected DDoS’ attack?", 
    options: [
        "An attack where the traffic is directed to an intermediary system, which reflects it to the victim", 
        "An attack using direct requests to overload a server", 
        "An attack where the victim sends traffic to the attacker", 
        "An attack where the data is encrypted to hide the origin"
    ], 
    answer: "An attack where the traffic is directed to an intermediary system, which reflects it to the victim"
},
{
    question: "A DDoS attack is targeting a company's web application. The attackers are sending a high volume of HTTP requests to overwhelm the application’s web servers. This type of attack is an example of?", 
    options: [
        "Layer 7 DDoS Attack", 
        "SYN Flood", 
        "UDP Flood", 
        "Network-based DDoS"
    ], 
    answer: "Layer 7 DDoS Attack"
},
{
    question: "Which DDoS attack method exploits the behavior of DNS servers to send a massive response to the victim using a small request?", 
    options: [
        "DNS Reflection", 
        "ICMP Flood", 
        "SYN Flood", 
        "TCP Reset"
    ], 
    answer: "DNS Reflection"
},
{
    question: "An attacker utilizes a botnet to flood a web server with HTTP requests, consuming its CPU and memory resources, making it unavailable to legitimate users. What type of DDoS attack is being executed?", 
    options: [
        "Resource Depletion Attack", 
        "SYN Flood", 
        "UDP Flood", 
        "ICMP Flood"
    ], 
    answer: "Resource Depletion Attack"
},
{
    question: "A DDoS attack is causing a critical service disruption in your company’s data center. Which of the following would be the most effective countermeasure to block this attack?", 
    options: [
        "Install a firewall to filter incoming traffic", 
        "Deploy a content delivery network (CDN) to distribute traffic", 
        "Use CAPTCHA to validate traffic requests", 
        "Increase the size of the server’s bandwidth"
    ], 
    answer: "Deploy a content delivery network (CDN) to distribute traffic"
},
{
    question: "What is the most common reason for a DDoS attack against a company?", 
    options: [
        "The company has sensitive data", 
        "The company has a public-facing system with high traffic volume", 
        "The company has poor security measures", 
        "The company is hosting valuable intellectual property"
    ], 
    answer: "The company has a public-facing system with high traffic volume"
},
{
    question: "An attacker targets a web service with massive traffic to bring down its availability. What is the primary objective of this type of attack?", 
    options: [
        "To steal sensitive data", 
        "To disrupt service and cause financial loss", 
        "To install a backdoor for future attacks", 
        "To change the DNS configurations"
    ], 
    answer: "To disrupt service and cause financial loss"
},
{
    question: "You are analyzing a DDoS attack and suspect that the attacker is using a botnet to perform the attack. Which of the following is a characteristic of a botnet?",
    options: [
        "The botnet consists of a single compromised system", 
        "The botnet includes multiple compromised devices controlled by a single attacker", 
        "The botnet is always launched from the same geographic location", 
        "The botnet can only be used for phishing attacks"
    ], 
    answer: "The botnet includes multiple compromised devices controlled by a single attacker"
},
{
    question: "A botnet is composed of thousands of IoT devices that have been infected with malware. The attacker is controlling these devices to carry out a massive DDoS attack. What is the term used to describe this collection of infected devices?",
    options: [
        "RAT", 
        "Zombie network", 
        "Botnet", 
        "Trojan Horse"
    ], 
    answer: "Botnet"
},
{
    question: "Which type of malware is commonly used to create a botnet by compromising and controlling large numbers of systems?",
    options: [
        "Ransomware", 
        "Rootkit", 
        "Worm", 
        "Trojan"
    ], 
    answer: "Worm"
},
{
    question: "What is the main purpose of a botmaster in a botnet?",
    options: [
        "To infect vulnerable devices", 
        "To direct the botnet’s activities, including launching DDoS attacks", 
        "To patch vulnerabilities in compromised devices", 
        "To gather information from infected devices"
    ], 
    answer: "To direct the botnet’s activities, including launching DDoS attacks"
},
{
    question: "A botnet is used to send massive amounts of traffic to a target in a DDoS attack. Which of the following is the most common type of botnet used in modern DDoS attacks?",
    options: [
        "Mirai", 
        "Stuxnet", 
        "Emotet", 
        "Zeus"
    ], 
    answer: "Mirai"
},
{
    question: "Which of the following is a technique often used by botnets to avoid detection by traditional antivirus solutions?",
    options: [
        "Use of polymorphic malware", 
        "Use of brute force passwords", 
        "Infected machines immediately send data back to the attacker", 
        "System shutdown to evade traffic analysis"
    ], 
    answer: "Use of polymorphic malware"
},
{
    question: "What is the primary reason why IoT devices are often used in botnet-based DDoS attacks?",
    options: [
        "IoT devices have poor processing power", 
        "IoT devices are usually connected to private networks", 
        "IoT devices often have weak security and can be easily compromised", 
        "IoT devices use encrypted communication"
    ], 
    answer: "IoT devices often have weak security and can be easily compromised"
},
{
    question: "A botnet is responsible for sending millions of malicious requests to a target server, which results in a service outage. How can you determine if the traffic is originating from a botnet?",
    options: [
        "The traffic is coming from multiple geographic locations", 
        "The traffic is coming from a single source", 
        "The traffic is intermittent", 
        "The traffic is encrypted with SSL/TLS"
    ], 
    answer: "The traffic is coming from multiple geographic locations"
},
{
    question: "You receive a report indicating that several devices in your organization have been infected and are part of a botnet. Which of the following would be the best response to remove the devices from the botnet?",
    options: [
        "Deploy a patch management system", 
        "Use antivirus software to scan and clean the infected devices", 
        "Immediately disconnect the infected devices from the network", 
        "Update the system’s firewall settings"
    ], 
    answer: "Immediately disconnect the infected devices from the network"
},
{
    question: "A botnet uses a P2P (peer-to-peer) architecture for communication between infected devices. What is one potential advantage of using P2P over a centralized botnet?",
    options: [
        "Increased control by a single attacker", 
        "Easier to detect and shut down", 
        "More resilient to takedown, as there is no single point of failure", 
        "More effective at using encryption techniques"
    ], 
    answer: "More resilient to takedown, as there is no single point of failure"
},
{
    question: "Which of the following is a typical method used to recruit devices into a botnet?",
    options: [
        "Infected devices are updated with a legitimate patch", 
        "Compromised devices are instructed to download additional malware", 
        "Infected devices are kept isolated from the Internet", 
        "Compromised devices use encryption to communicate with the attacker"
    ], 
    answer: "Compromised devices are instructed to download additional malware"
},
{
    question: "A company notices that the performance of its systems is degrading due to a sudden spike in network traffic. Further investigation shows that many of the source IP addresses are from known IoT devices. What could this be a sign of?",
    options: [
        "A botnet-based DDoS attack", 
        "A phishing attack", 
        "A man-in-the-middle attack", 
        "A malware infection on the company’s internal systems"
    ], 
    answer: "A botnet-based DDoS attack"
},
{
    question: "Which of the following is a key indicator of a botnet being used in an attack?",
    options: [
        "Traffic originating from a small number of IP addresses", 
        "High traffic volume from a single device", 
        "Unusual, high-volume traffic from multiple devices with different IP addresses", 
        "Traffic patterns consistent with normal user behavior"
    ], 
    answer: "Unusual, high-volume traffic from multiple devices with different IP addresses"
},
{
    question: "Which of the following methods is commonly used to track the activities of botnets in the wild?",
    options: [
        "Using malware signatures to detect infected devices", 
        "Network traffic analysis and anomaly detection", 
        "Deploying DNS intercepts on known botnet domains", 
        "Examining infected devices' file system for indicators of compromise"
    ], 
    answer: "Network traffic analysis and anomaly detection"
},
{
    question: "What is the primary purpose of using a ‘command and control’ (C&C) server in a botnet?",
    options: [
        "To distribute malware updates to infected devices", 
        "To provide a central location for infected devices to report status", 
        "To maintain a list of known botnet victims", 
        "To manage and coordinate the actions of infected devices"
    ], 
    answer: "To manage and coordinate the actions of infected devices"
},
{
    question: "A botnet operates using a peer-to-peer structure to avoid detection. Which of the following would be a key advantage of this architecture?",
    options: [
        "Decentralization prevents takedown efforts", 
        "P2P botnets can only be used in application-layer DDoS attacks", 
        "P2P botnets are easier to identify and dismantle", 
        "P2P botnets can only infect IoT devices"
    ], 
    answer: "Decentralization prevents takedown efforts"
},
{
    question: "Which of the following strategies can help protect an organization’s devices from being recruited into a botnet?",
    options: [
        "Regularly patching devices to fix security vulnerabilities", 
        "Encrypting all outbound traffic", 
        "Limiting external access to IoT devices", 
        "All of the above"
    ], 
    answer: "All of the above"
},
{
    question: "A botnet master uses a peer-to-peer botnet structure to avoid detection and maintain control of infected systems. How can an organization detect and mitigate this type of botnet activity?",
    options: [
        "Implementing signature-based antivirus scanning", 
        "Blocking known botnet domains at the network perimeter", 
        "Monitoring for abnormal traffic patterns in the network", 
        "Performing regular system patching"
    ], 
    answer: "Monitoring for abnormal traffic patterns in the network"
},
{
    question: "An attacker sends a flood of traffic to a victim’s web server, using multiple different protocols in a coordinated effort. Which type of DDoS attack does this represent?",
    options: [
        "Volumetric Attack", 
        "Application Layer Attack", 
        "Multi-Vector Attack", 
        "Protocol Attack"
    ], 
    answer: "Multi-Vector Attack"
},
{
    question: "A DDoS attack is exploiting a vulnerability in the victim's network layer to consume its processing power, causing a service outage. Which attack technique is being used?",
    options: [
        "SYN Flood", 
        "DNS Reflection", 
        "UDP Flood", 
        "ICMP Flood"
    ], 
    answer: "SYN Flood"
},
{
    question: "You notice that a DDoS attack is sending numerous small packets to a target with an intention to overload the target’s CPU. What type of attack is this likely to be?",
    options: [
        "Ping of Death", 
        "SYN Flood", 
        "Smurf Attack", 
        "Slowloris"
    ], 
    answer: "Slowloris"
},
{
    question: "Which of the following DDoS attack techniques involves an attacker sending multiple spoofed IP addresses to a victim's server, forcing it to respond with ICMP echo replies?",
    options: [
        "Ping Flood", 
        "DNS Amplification", 
        "SYN Flood", 
        "Spoofing Attack"
    ], 
    answer: "Ping Flood"
},
{
    question: "An attacker sends excessive requests to a web server and exhausts the server’s available connections, causing a denial of service. What attack technique is being used?",
    options: [
        "HTTP Flood", 
        "DNS Amplification", 
        "TCP SYN Flood", 
        "SYN Spoofing"
    ], 
    answer: "HTTP Flood"
},
{
    question: "A large-scale DDoS attack targets a victim’s DNS server with requests, using vulnerable third-party DNS servers. Which DDoS attack technique does this represent?",
    options: [
        "DNS Amplification", 
        "DNS Spoofing", 
        "ICMP Flood", 
        "SYN Flood"
    ], 
    answer: "DNS Amplification"
},
{
    question: "A DDoS attack involves continuously sending malformed packets to a server’s connection port, which prevents the server from establishing any legitimate connections. What is this type of attack?",
    options: [
        "TCP SYN Flood", 
        "Ping Flood", 
        "UDP Flood", 
        "Fragmentation Attack"
    ], 
    answer: "Fragmentation Attack"
},
{
    question: "Which of the following DDoS attack techniques targets vulnerabilities in the victim's application layer by sending massive amounts of application-specific requests, such as HTTP requests?",
    options: [
        "TCP Flood", 
        "Layer 7 Attack", 
        "SYN Flood", 
        "ICMP Flood"
    ], 
    answer: "Layer 7 Attack"
},
{
    question: "A DDoS attack is being carried out using a botnet that is sending HTTP requests to exhaust server resources. What type of attack is this?",
    options: [
        "HTTP Flood", 
        "SYN Flood", 
        "DNS Amplification", 
        "UDP Flood"
    ], 
    answer: "HTTP Flood"
},
{
    question: "An attacker uses a botnet to send millions of requests to a server, causing it to crash. The attacker deliberately floods the server with requests using the HTTP protocol. What type of attack is this?",
    options: [
        "TCP Flood", 
        "HTTP Flood", 
        "DNS Flood", 
        "UDP Flood"
    ], 
    answer: "HTTP Flood"
},
{
    question: "A financial institution is facing a DDoS attack that targets its online banking system. The attack involves flooding the network with high volumes of traffic, and the system becomes unavailable to legitimate users. What is the most likely cause of this outage?",
    options: [
        "A DNS spoofing attack", 
        "A volume-based DDoS attack", 
        "A ransomware attack", 
        "A brute force attack"
    ], 
    answer: "A volume-based DDoS attack"
},
{
    question: "A large e-commerce website is experiencing slow performance during a high-traffic sales event. After investigation, you find that the site is under a Layer 7 DDoS attack, where attackers are sending HTTP requests to exhaust server resources. What would be an effective mitigation strategy?",
    options: [
        "Increase server bandwidth", 
        "Use CAPTCHA to filter legitimate traffic", 
        "Deploy a content delivery network (CDN)", 
        "Enable IP whitelisting for trusted users"
    ], 
    answer: "Deploy a content delivery network (CDN)"
},
{
    question: "A gaming company is targeted by a DDoS attack during the launch of a new multiplayer game. The attack uses a botnet to flood the company’s game servers with traffic. The company has identified the source IPs of the attack. What is the best approach for mitigating this attack?",
    options: [
        "Block the attacker's IP addresses at the firewall", 
        "Implement rate limiting and geo-blocking of non-game regions", 
        "Use a DDoS protection service that provides traffic scrubbing", 
        "Disable the servers until the attack ends"
    ], 
    answer: "Use a DDoS protection service that provides traffic scrubbing"
},
{
    question: "A government website is facing an ongoing DDoS attack that is causing a major service disruption. The attackers are leveraging botnets to send massive amounts of traffic. The IT team is considering deploying a WAF (Web Application Firewall) to mitigate the attack. What is the main advantage of using a WAF in this scenario?",
    options: [
        "WAF can block IP addresses", 
        "WAF can analyze and filter malicious traffic based on application layer rules", 
        "WAF can redirect traffic to a CDN", 
        "WAF can increase server bandwidth"
    ], 
    answer: "WAF can analyze and filter malicious traffic based on application layer rules"
},
{
    question: "A healthcare provider's web application is being targeted by a DDoS attack during a critical time, causing patient services to become unavailable. After analyzing the attack, it is determined that the attackers are sending a large number of small packets to the victim’s server. Which type of attack is being used?",
    options: [
        "SYN Flood", 
        "Ping Flood", 
        "DNS Amplification", 
        "TCP Reset"
    ], 
    answer: "SYN Flood"
},
{
    question: "A company is under attack from a DDoS botnet using DNS amplification to disrupt its online services. The DNS server is being used to flood the company's network. Which of the following mitigation techniques would best protect against DNS amplification attacks?",
    options: [
        "Implementing rate limiting on DNS requests", 
        "Blocking DNS queries on all inbound connections", 
        "Disabling all DNS traffic", 
        "Using two-factor authentication for DNS requests"
    ], 
    answer: "Implementing rate limiting on DNS requests"
},
{
    question: "During a DDoS attack against an online retailer, traffic is directed to the checkout page of the website, exhausting the server’s capacity and causing downtime. What is the most likely attack vector being exploited?",
    options: [
        "Layer 3 DDoS attack", 
        "Application Layer Attack (Layer 7)", 
        "Protocol Attack", 
        "Botnet Flood"
    ], 
    answer: "Application Layer Attack (Layer 7)"
},
{
    question: "An attacker is targeting an organization’s customer-facing website using a DDoS attack that causes high traffic volumes and service outages. The company’s incident response team suspects that the attack is using multiple types of techniques. What type of DDoS attack is most likely being employed?",
    options: [
        "Single-vector attack", 
        "Multi-vector attack", 
        "Application layer attack", 
        "SYN flood attack"
    ], 
    answer: "Multi-vector attack"
},
{
    question: "A cloud service provider’s website is under a DDoS attack. The attack is overwhelming the web server and preventing users from logging into their accounts. The security team analyzes the attack and finds that the web server is receiving legitimate HTTP requests, but it cannot process them all. What type of attack is most likely taking place?",
    options: [
        "SYN Flood", 
        "DNS Reflection", 
        "HTTP Flood", 
        "ICMP Flood"
    ], 
    answer: "HTTP Flood"
},
{
    question: "A financial institution is attacked by a DDoS botnet that floods its public-facing API, causing financial transactions to fail. After further investigation, the security team finds that the API is vulnerable to application-layer attacks, which allows the botnet to generate massive requests. What would be the most effective way to mitigate this attack?",
    options: [
        "Blocking the source IP addresses", 
        "Deploying an application firewall (WAF) to filter requests", 
        "Using a rate-limiting mechanism for API calls", 
        "Increasing the capacity of the API server"
    ], 
    answer: "Deploying an application firewall (WAF) to filter requests"
},
{
    question: "A DDoS attack is targeting your company's web application, and legitimate users are unable to access the services. What is the first step you should take in mitigating the attack?",
    options: [
        "Increase the network bandwidth", 
        "Analyze the attack traffic and identify the attack vector", 
        "Shut down the web server", 
        "Implement an antivirus solution on the web server"
    ], 
    answer: "Analyze the attack traffic and identify the attack vector"
},
{
    question: "To protect your company from future DDoS attacks, you decide to deploy a cloud-based DDoS mitigation service. Which of the following features is most important in a cloud-based mitigation solution?",
    options: [
        "Ability to reroute traffic through scrubbing centers", 
        "Providing IP whitelisting for internal resources", 
        "Improved anti-malware capabilities", 
        "Local firewall protections"
    ], 
    answer: "Ability to reroute traffic through scrubbing centers"
},
{
    question: "Which of the following is a common method to protect against DDoS attacks by distributing incoming traffic to multiple servers or data centers?",
    options: [
        "Content Delivery Network (CDN)", 
        "Proxy server", 
        "Network Intrusion Detection System (NIDS)", 
        "Virtual Private Network (VPN)"
    ], 
    answer: "Content Delivery Network (CDN)"
},
{
    question: "You are tasked with defending your company against DDoS attacks. What is a key feature of a Web Application Firewall (WAF) that makes it useful in mitigating DDoS attacks?",
    options: [
        "Filtering based on IP reputation", 
        "Layer 7 request filtering", 
        "Rate limiting of inbound traffic", 
        "Traffic rerouting through external servers"
    ], 
    answer: "Layer 7 request filtering"
},
{
    question: "To prevent a DDoS attack that targets your company’s DNS infrastructure, which of the following measures should be taken?",
    options: [
        "Implement DNS rate limiting and configure DNSSEC", 
        "Disable all DNS requests", 
        "Increase the DNS server’s bandwidth", 
        "Block all UDP traffic"
    ], 
    answer: "Implement DNS rate limiting and configure DNSSEC"
},
{
    question: "An attack is attempting to overload your company’s web server by sending massive amounts of traffic. Your team decides to deploy a mitigation solution. Which of the following would be the most effective strategy?",
    options: [
        "Scaling up the infrastructure by adding more resources", 
        "Enabling rate limiting for requests", 
        "Deploying a firewall that blocks all traffic", 
        "Using CAPTCHAs on all web pages"
    ], 
    answer: "Enabling rate limiting for requests"
},
{
    question: "A company is being targeted by an application-layer DDoS attack, where attackers are sending a massive number of HTTP requests to exhaust the server’s resources. What is the most effective countermeasure for this type of attack?",
    options: [
        "Deploy a WAF to filter malicious HTTP requests", 
        "Install a new load balancer", 
        "Increase the server's RAM and CPU capacity", 
        "Increase the network bandwidth"
    ], 
    answer: "Deploy a WAF to filter malicious HTTP requests"
},
{
    question: "In response to a DDoS attack targeting a critical online service, your company is considering using a cloud-based DDoS mitigation service. Which of the following benefits would a cloud-based solution offer?",
    options: [
        "Reduced infrastructure costs", 
        "Automated attack detection and traffic scrubbing", 
        "Local traffic monitoring", 
        "Increased network latency"
    ], 
    answer: "Automated attack detection and traffic scrubbing"
},
{
    question: "To prevent future DDoS attacks against your network, you decide to implement rate limiting. What is the primary goal of rate limiting in the context of DDoS mitigation?",
    options: [
        "Block all incoming traffic", 
        "Reduce the impact of the attack by limiting the number of requests", 
        "Disable the server during the attack", 
        "Increase bandwidth availability"
    ], 
    answer: "Reduce the impact of the attack by limiting the number of requests"
},
{
    question: "Which of the following strategies can help mitigate the impact of a DDoS attack targeting the application layer of your company’s web server?",
    options: [
        "Increase the bandwidth to handle more traffic", 
        "Deploy a reverse proxy", 
        "Implement DNSSEC to prevent DNS spoofing", 
        "Use SSL certificates for encryption"
    ], 
    answer: "Deploy a reverse proxy"
},
{
    question: "During a large-scale DDoS attack targeting your company’s API, you observe an increase in the rate of failed requests. What mitigation strategy should be implemented to minimize downtime and service disruption?",
    options: [
        "Block all incoming traffic", 
        "Deploy an API Gateway to filter out malicious requests", 
        "Use a VPN for internal traffic", 
        "Disable the API services temporarily"
    ], 
    answer: "Deploy an API Gateway to filter out malicious requests"
},
{
    question: "During a DDoS attack, you observe that the web application is being targeted by a flood of HTTP requests. You are considering deploying a Web Application Firewall (WAF) for protection. What rule-based technique would most effectively mitigate this type of attack without blocking legitimate traffic?",
    options: [
        "Rate limiting the number of requests per client IP", 
        "Blacklisting the source IP addresses", 
        "Implementing DNS filtering", 
        "Blocking requests that contain specific user-agent headers"
    ], 
    answer: "Rate limiting the number of requests per client IP"
},
{
    question: "A multi-national corporation is under a DDoS attack using a large botnet, sending a flood of TCP packets. The attack is causing resource exhaustion and slow server responses. What is the most effective countermeasure to mitigate this TCP flood at the network layer?",
    options: [
        "Enable SYN cookies to prevent SYN flood attacks", 
        "Deploy a DNS load balancer to distribute traffic", 
        "Use a cloud-based DDoS mitigation service", 
        "Block all inbound traffic until the attack subsides"
    ], 
    answer: "Enable SYN cookies to prevent SYN flood attacks"
},
{
    question: "Your company is experiencing a DDoS attack involving a large number of DNS requests, which is causing the DNS infrastructure to become overloaded. What is the most effective method for mitigating this DNS amplification attack?",
    options: [
        "Blocking DNS queries from external IP addresses", 
        "Deploying DNS rate limiting and using DNSSEC", 
        "Disabling the DNS service until the attack is over", 
        "Using DNS-over-HTTPS to encrypt DNS traffic"
    ], 
    answer: "Deploying DNS rate limiting and using DNSSEC"
},
{
    question: "A DDoS attack is overwhelming your company’s HTTP server, causing significant downtime. You have identified that the attack is coming from a large number of small HTTP requests designed to exhaust server resources. What mitigation technique would be most effective to filter this traffic?",
    options: [
        "Use CAPTCHA challenges to filter out bot traffic", 
        "Apply rate limiting based on client IP", 
        "Deploy a CDN to absorb the traffic", 
        "Use an application firewall with signature-based filtering"
    ], 
    answer: "Use CAPTCHA challenges to filter out bot traffic"
},
{
    question: "A financial service provider is under attack, with the goal of denying access to its online banking application. The attackers are targeting the application layer by sending massive numbers of transactions to overload the system. What is the most appropriate strategy to mitigate this Layer 7 attack?",
    options: [
        "Increase the server’s RAM and CPU", 
        "Deploy a reverse proxy to cache frequent requests", 
        "Configure application-level rate limiting", 
        "Block all traffic from foreign IP addresses"
    ], 
    answer: "Configure application-level rate limiting"
},
{
    question: "Your company’s cloud-based services are under attack from a botnet launching a DDoS attack. The attack is using multiple attack vectors, including HTTP flooding and DNS amplification. Which of the following mitigation strategies would best help defend against multi-vector attacks?",
    options: [
        "Deploying an IDS/IPS system", 
        "Using a hybrid DDoS protection solution that combines both on-premises and cloud-based mitigation", 
        "Implementing IP whitelisting", 
        "Disabling all external-facing servers temporarily"
    ], 
    answer: "Using a hybrid DDoS protection solution that combines both on-premises and cloud-based mitigation"
},
{
    question: "You are tasked with defending against DDoS attacks on an online service. You notice that the attacks are using DNS amplification, causing DNS servers to become overwhelmed. What is the most effective way to protect against DNS amplification attacks in the long term?",
    options: [
        "Configure DNS servers to only respond to trusted clients", 
        "Implement DNS rate limiting on authoritative servers", 
        "Block all DNS requests from foreign IP addresses", 
        "Increase DNS server bandwidth"
    ], 
    answer: "Configure DNS servers to only respond to trusted clients"
},
{
    question: "Your company has been targeted by a volumetric DDoS attack using botnets. Traffic is flooding your network, causing legitimate traffic to be dropped. What is the best immediate course of action to mitigate the attack while maintaining availability for critical services?",
    options: [
        "Block all inbound traffic to the network", 
        "Deploy a content delivery network (CDN) to distribute the traffic", 
        "Activate a cloud-based DDoS mitigation service that can filter the malicious traffic", 
        "Increase the bandwidth of the network"
    ], 
    answer: "Activate a cloud-based DDoS mitigation service that can filter the malicious traffic"
},
{
    question: "A hacker is launching a DDoS attack on your organization using botnets to send large numbers of requests to the company's online shopping platform. In response, you implement rate limiting for traffic and enable IP blacklisting. However, these methods are not sufficient. What additional countermeasure should you deploy to help mitigate the attack?",
    options: [
        "Enable CAPTCHA for all user logins", 
        "Use a Web Application Firewall (WAF) to filter out malicious requests", 
        "Upgrade the web server hardware", 
        "Deploy a DNS load balancer to handle DNS queries"
    ], 
    answer: "Use a Web Application Firewall (WAF) to filter out malicious requests"
},
{
    question: "Your organization is experiencing a slow degradation in performance due to an ongoing DDoS attack using fragmented UDP packets. What is the most appropriate strategy to mitigate a UDP fragmentation attack?",
    options: [
        "Enable firewall rules to block fragmented UDP packets", 
        "Deploy a WAF to filter out fragmented UDP packets", 
        "Increase the bandwidth of the network to handle the attack", 
        "Switch to using only IPv6 for network communication"
    ], 
    answer: "Enable firewall rules to block fragmented UDP packets"
},
{
    question: "You are tasked with mitigating a DDoS attack that is targeting your company’s API servers by sending a flood of HTTP POST requests. Which method would be the most effective to mitigate this type of application-layer DDoS attack?",
    options: [
        "Apply rate limiting based on IP addresses", 
        "Deploy a WAF to inspect and block suspicious POST requests", 
        "Increase server resources such as CPU and memory", 
        "Add additional API endpoints to distribute traffic"
    ], 
    answer: "Deploy a WAF to inspect and block suspicious POST requests"
},
{
    question: "Your company is under attack from a DDoS botnet using a reflection attack through NTP servers. You are tasked with mitigating this attack at the network perimeter. What would be the most effective approach?",
    options: [
        "Block NTP traffic on the perimeter firewall", 
        "Implement an IDS to monitor NTP traffic", 
        "Configure NTP servers to ignore requests from external sources", 
        "Deploy a WAF to filter NTP traffic"
    ], 
    answer: "Block NTP traffic on the perimeter firewall"
},
{
    question: "You are the network administrator of a company that is facing a DDoS attack causing degraded network performance and high latency. The attack involves large amounts of ICMP packets sent to the company's firewall. What is the most effective solution to prevent the ICMP flood from affecting your network?",
    options: [
        "Block all ICMP traffic at the firewall", 
        "Implement rate-limiting for ICMP traffic", 
        "Enable port scanning protection", 
        "Add a load balancer to the network"
    ], 
    answer: "Implement rate-limiting for ICMP traffic"
},
{
    question: "A healthcare organization is under a DDoS attack using botnets that are sending traffic to its patient portal, making it unavailable. You are tasked with ensuring the availability of critical services, such as patient records, during the attack. What is the best mitigation strategy?",
    options: [
        "Enable a global load balancer to distribute the traffic across multiple regions", 
        "Block all incoming traffic until the attack subsides", 
        "Increase the processing power of the web server", 
        "Use a VPN to restrict access to internal staff only"
    ], 
    answer: "Enable a global load balancer to distribute the traffic across multiple regions"
},
{
    question: "An attacker is exploiting a vulnerability in your company's DNS infrastructure by launching a DNS amplification attack, causing a denial of service. The company has already implemented DNS rate limiting. What additional measure could you take to mitigate this attack more effectively?",
    options: [
        "Deploy DNSSEC to ensure that DNS responses are authentic", 
        "Increase DNS server bandwidth to handle more requests", 
        "Use DNS filtering to block non-essential DNS queries", 
        "Implement a DNS proxy to obscure internal DNS servers"
    ], 
    answer: "Deploy DNSSEC to ensure that DNS responses are authentic"
},
{
    question: "Your company is facing an attack that uses malformed packets to flood a vulnerable network service. This attack is causing CPU exhaustion on the affected systems. Which of the following would be the most effective strategy to mitigate this type of attack?",
    options: [
        "Use an intrusion detection system (IDS) to block malformed packets", 
        "Apply a signature-based filtering rule at the firewall", 
        "Increase the CPU power of the affected systems", 
        "Use rate limiting for all incoming traffic"
    ], 
    answer: "Apply a signature-based filtering rule at the firewall"
},
{
    question: "In response to a DDoS attack on your company's web server, you deploy a Web Application Firewall (WAF) to mitigate the attack. However, the WAF is only blocking a small fraction of the malicious traffic, and many requests are still reaching the server. What could be an effective configuration to improve the WAF’s performance in filtering traffic?",
    options: [
        "Configure the WAF to use machine learning-based anomaly detection", 
        "Set up the WAF to log all traffic for further analysis", 
        "Increase the capacity of the WAF by adding more servers", 
        "Use a WAF that only blocks traffic based on IP address"
    ], 
    answer: "Configure the WAF to use machine learning-based anomaly detection"
},
{
    question: "During a DDoS attack on your company’s e-commerce website, you discover that a large number of requests are coming from a single region, causing your server to slow down. What would be the best method to mitigate this localized DDoS attack?",
    options: [
        "Deploy geolocation-based blocking to filter traffic from the affected region", 
        "Enable rate limiting for requests from that region", 
        "Increase the bandwidth to accommodate more traffic", 
        "Implement a VPN to route traffic through different regions"
    ], 
    answer: "Deploy geolocation-based blocking to filter traffic from the affected region"
},
{
    question: "A company is under attack from a DDoS botnet that is sending large volumes of UDP packets, which are overwhelming the network’s edge devices. What is the most effective method for mitigating this type of attack at the network perimeter?",
    options: [
        "Configure ACLs to block UDP traffic on the firewall", 
        "Use a DDoS protection service to filter UDP packets", 
        "Deploy rate-limiting on UDP traffic", 
        "Increase the bandwidth of the network to handle the attack"
    ], 
    answer: "Use a DDoS protection service to filter UDP packets"
},
{
    question: "During a DDoS attack, you observe that your server's CPU is reaching 100% utilization. What would be the most appropriate solution to alleviate CPU exhaustion and ensure the availability of your services during the attack?",
    options: [
        "Optimize the application code to handle requests more efficiently", 
        "Deploy a load balancer to distribute requests across multiple servers", 
        "Increase the server's CPU power", 
        "Block all incoming traffic from suspicious IP addresses"
    ], 
    answer: "Deploy a load balancer to distribute requests across multiple servers"
},
{
    question: "Your company is under attack by a DDoS botnet using multiple attack vectors, including SYN Flood, HTTP Flood, and DNS Amplification. What is the most effective countermeasure that would help mitigate all of these attack types in one solution?",
    options: [
        "Enable SYN cookies and rate limit DNS traffic", 
        "Use a hybrid DDoS mitigation solution with both on-premises and cloud-based filtering", 
        "Configure firewall rules to block SYN requests", 
        "Implement DNSSEC and load balancing"
    ], 
    answer: "Use a hybrid DDoS mitigation solution with both on-premises and cloud-based filtering"
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
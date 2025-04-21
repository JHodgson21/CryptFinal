# Man-in-the-Middle Credential Interception using Python & Ettercap

## Introduction  
This project is a Python-based credential sniffer that performs a Man-in-the-Middle (MitM) attack using ARP spoofing and HTTP traffic inspection. Ettercap is used to intercept packets, while a custom Python script monitors its output in real-time to extract usernames and passwords submitted through insecure login forms. Captured credentials are timestamped and stored in a log file, making this a lightweight and powerful demo of MitM attacks on unsecured networks.

## Features  
- Automatic Ettercap Launch: The Python script starts Ettercap automatically with appropriate flags.  
- Live Credential Monitoring: Captures common `username` and `password` fields from HTTP POST traffic.  
- Timestamped Logging: Logs harvested credentials to a file with timestamps for each entry.  
- Formatted Console Output: Neatly prints intercepted credentials to the terminal in real-time.  
- Graceful Shutdown: Exits cleanly and terminates Ettercap upon script interruption.

## Installation and Setup

### Prerequisites  
- Python 3.6 or higher  
- Ettercap (Text mode)  
- Sudo/root privileges  
- A working network interface (e.g., `eth0`, `wlan0`)  

## Step-by-Step Instructions

1. Open Kali and Windows Vm's:
- ping each other and make sure they are connected to the internet. 

2. Enable IP Forwarding:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

3. Run the Python Script:

```bash
python3 log_watcher.py
```

4. On the victim machine, visit a vulnerable HTTP login page such as:

```bash
http://testphp.vulnweb.com/login.php
```

Once credentials are submitted, they will appear in real time in your terminal and be logged in credentials.log.

 ## Usage
Credential Sniffing:
Run the Python script:

```bash
python3 log_watcher.py
```
This will:

- Launch Ettercap in text mode

- Begin sniffing network traffic

- Log any credentials it detects

## Log File:

Captured credentials are saved to:


```bash
credentials.log
```
Each log entry includes:

- Timestamp

- Username

- Password

- Referer (originating site)

## Troubleshooting
- Victim can’t access the internet:
Ensure IP forwarding is enabled:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
- Ettercap not starting:

   - Make sure your network interface (e.g., eth0) is correct

   - Use "ip a" to check your interface name

-  No credentials being captured:

   - Make sure the target site is HTTP, not HTTPS

   - Confirm Ettercap is actively sniffing and traffic is flowing

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

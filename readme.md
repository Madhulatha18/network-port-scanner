# Python Network Port Scanner

## Project Overview

The Python Network Port Scanner is a cybersecurity tool developed to identify open TCP ports on authorized network devices. It uses Python socket programming to establish TCP connections and determine the availability of ports.

## Features

- IP address validation
- Hostname resolution
- Common port scanning
- Custom port range scanning
- TCP connection testing
- Common service identification
- Multithreaded scanning
- Real-time scan progress indicator
- CSV report generation
- Error handling

## Technologies Used

- Python
- Socket Programming
- IP Address Validation
- Multithreading
- CSV Module

## How It Works

1. The user enters a target IP address or hostname.
2. The application validates the target.
3. The user selects common port scanning or a custom port range.
4. Python establishes TCP connection attempts to the selected ports.
5. The application identifies successful connections and associated common service names.
6. Results are displayed in the terminal.
7. Scan results can be exported into a CSV report.

## Installation and Execution

**Step 1:** Clone the repository.

```bash
git clone https://github.com/Madhulatha18/network-port-scanner.git
```

**Step 2:** Navigate to the project directory.

```bash
cd Python-Network-Port-Scanner
```

**Step 3:** Run the application.

```bash
python port_scanner.py
```

No external Python packages are required.

## Example Use Case

The application can be used by network administrators to check which TCP ports are accepting connections on devices they own or are authorized to assess.

## Learning Outcomes

- Understanding TCP communication
- Learning socket programming
- Understanding IP addresses and port numbers
- Implementing multithreading in Python
- Working with CSV files
- Applying basic network security concepts

## Ethical Usage

This project is intended for educational and authorized security testing only. Scan only systems and networks for which you have explicit permission.

## Future Enhancements

- Graphical user interface using Tkinter
- Scan history
- Detailed scan reports
- Additional service information

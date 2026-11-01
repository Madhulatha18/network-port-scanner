
import socket
import ipaddress
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common TCP service names
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT"
}

scan_results = []


# Resolve and validate the target
def validate_target(target):

    try:
        address = ipaddress.ip_address(target)

    except ValueError:
        try:
            address = ipaddress.ip_address(
                socket.gethostbyname(target)
            )
        except socket.gaierror:
            print("Unable to resolve hostname.")
            return None

    if address.version != 4:
        print("Only IPv4 targets are supported.")
        return None

    if not (address.is_private or address.is_loopback):
        print("Public IP addresses are not allowed in this version.")
        print("Use localhost or an authorized private network device.")
        return None

    return str(address)


# Identify common services
def identify_service(port):

    if port in COMMON_PORTS:
        return COMMON_PORTS[port]

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


# Scan an individual port
def scan_port(target, port, timeout):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            return {
                "port": port,
                "status": "OPEN",
                "service": identify_service(port)
            }

        return {
            "port": port,
            "status": "NOT OPEN / NO RESPONSE",
            "service": identify_service(port)
        }

    except OSError:
        return {
            "port": port,
            "status": "ERROR",
            "service": identify_service(port)
        }

    finally:
        sock.close()


# Perform port scanning
def start_scan(target, ports):

    global scan_results
    scan_results = []

    timeout = 0.5
    total = len(ports)

    print("\nStarting scan...")
    print("Target IP:", target)
    print("Total ports:", total)
    print("-" * 60)

    completed = 0

    with ThreadPoolExecutor(max_workers=50) as executor:

        tasks = {
            executor.submit(
                scan_port, target, port, timeout
            ): port
            for port in ports
        }

        for task in as_completed(tasks):

            result = task.result()
            completed += 1

            if result:
                scan_results.append(result)

            progress = (completed / total) * 100

            print(
                f"\rProgress: {progress:.1f}% "
                f"({completed}/{total})",
                end="",
                flush=True
            )

    print("\n\nSCAN RESULTS")
    print("=" * 60)

    open_ports = [
        item for item in scan_results
        if item["status"] == "OPEN"
    ]

    if open_ports:
        for item in sorted(open_ports, key=lambda x: x["port"]):
            print(
                f"Port: {item['port']} | "
                f"Status: {item['status']} | "
                f"Service: {item['service']}"
            )
    else:
        print("No open ports found.")

    print("-" * 60)
    print("Total ports scanned:", total)
    print("Open ports found:", len(open_ports))
    print("Scan completed!")


# Export results to CSV
def export_report():

    if not scan_results:
        print("No scan results available. Run a scan first.")
        return

    filename = "scan_report_" + datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    ) + ".csv"

    try:
        with open(filename, "w", newline="") as file:

            writer = csv.DictWriter(
                file,
                fieldnames=["port", "status", "service"]
            )

            writer.writeheader()
            writer.writerows(
                sorted(scan_results, key=lambda x: x["port"])
            )

        print("\nReport saved successfully:", filename)

    except OSError as error:
        print("Unable to save report:", error)


# Custom port scan
def custom_scan(target):

    try:
        start = int(input("Enter starting port: "))
        end = int(input("Enter ending port: "))

        if not (1 <= start <= end <= 65535):
            print("Invalid port range.")
            return

        if end - start + 1 > 1024:
            print("Maximum 1024 ports allowed per scan.")
            return

        ports = list(range(start, end + 1))
        start_scan(target, ports)

    except ValueError:
        print("Enter valid numbers.")


# Common port scan
def common_scan(target):

    ports = list(COMMON_PORTS.keys())
    start_scan(target, ports)


# Main application
def main():

    print("=" * 60)
    print("           PYTHON NETWORK PORT SCANNER")
    print("=" * 60)

    target_input = input(
        "Enter target IP or hostname: "
    ).strip()

    target = validate_target(target_input)

    if target is None:
        return

    print("\nTarget resolved to:", target)

    while True:

        print("\n========== MAIN MENU ==========")
        print("1. Scan common ports")
        print("2. Custom port range scan")
        print("3. Export scan report")
        print("4. Exit")
        print("===============================")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            common_scan(target)

        elif choice == "2":
            custom_scan(target)

        elif choice == "3":
            export_report()

        elif choice == "4":
            print("Thank you for using Network Port Scanner!")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()

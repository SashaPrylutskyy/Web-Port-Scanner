from flask import Flask, render_template, request
import socket
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Dictionary of common ports and services with potential vulnerabilities
service_ports = {
    21: ("FTP", ["Anonymous access", "Brute force", "Directory traversal"]),
    22: ("SSH", ["Brute force", "Weak encryption"]),
    25: ("SMTP", ["Open relay", "Email spoofing", "Brute force"]),
    80: ("HTTP", ["Unencrypted traffic", "Directory traversal", "Injection attacks"]),
    443: ("HTTPS", ["SSL vulnerabilities", "Man-in-the-middle"]),
    3389: ("RDP", ["Brute force", "Weak encryption"]),
    110: ("POP3", ["Unencrypted login", "Brute force"]),
    143: ("IMAP", ["Unencrypted login", "Brute force"]),
    873: ("Rsync", ["Data exposure", "Weak authentication"]),
    5985: ("WinRM", ["Weak authentication", "Brute force"]),
}

def scan_port(ip, port):
    # Scan a single port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set timeout for the socket
    result = sock.connect_ex((ip, port))  # 0 means the port is open
    sock.close()
    return port, result == 0

def scan_ports(ip, start_port, end_port):
    # Scan a range of ports on a given IP
    open_ports = []
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in futures:
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    return open_ports

def check_vulnerabilities(open_ports):
    # Check for potential vulnerabilities based on open ports
    vulnerabilities = {}
    for port in open_ports:
        if port in service_ports:
            service, vuln_list = service_ports[port]
            vulnerabilities[port] = (service, vuln_list)
    return vulnerabilities

@app.route('/', methods=['GET', 'POST'])
def index():
    scan_results = {}
    vulnerabilities_report = {}
    
    if request.method == 'POST':
        ips = request.form.get('ips').split(',')  # Handle multiple IPs
        start_port = int(request.form.get('start_port'))  # Get start port
        end_port = int(request.form.get('end_port'))  # Get end port

        # Scan each IP and collect open ports
        for ip in ips:
            open_ports = scan_ports(ip.strip(), start_port, end_port)
            scan_results[ip] = open_ports
            vulnerabilities_report[ip] = check_vulnerabilities(open_ports)

    return render_template('index.html', scan_results=scan_results, vulnerabilities_report=vulnerabilities_report)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)


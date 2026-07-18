import socket

# Common TCP ports to scan
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    2049: "NFS",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}


def scan_ports(host):
    """
    Scan common TCP ports on the specified host.

    Returns:
        list of tuples:
        (port, service, status)
    """

    results = []

    try:
        # Resolve hostname to IP
        socket.gethostbyname(host)

        for port, service in COMMON_PORTS.items():

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(1)

            try:
                result = sock.connect_ex((host, port))

                if result == 0:
                    status = "OPEN"
                else:
                    status = "CLOSED"

            except Exception:
                status = "ERROR"

            finally:
                sock.close()

            results.append((port, service, status))

    except socket.gaierror:
        raise Exception("Invalid hostname or IP address.")

    except Exception as e:
        raise Exception(str(e))

    return results
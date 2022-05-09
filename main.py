from subprocess import call
import socket
from IPy import IP


class portscanner:
    open_ports = []

    def __init__(self, target, port_num, logging=False):
        self.target = target
        self.port_num = port_num
        self.logging = logging

    def scan(self):
        for port in range(1, self.port_num):
            self.scan_port(port)

    def check_ip(self):
        try:
            IP(self.target)
            return(self.target)
        except ValueError:
            return socket.gethostbyname(self.target)

    def scan_port(self, port):
        try:
            converted_ip = self.check_ip()
            sock = socket.socket()
            sock.settimeout(0.5)
            # print(f"port {port}")
            sock.connect((converted_ip, port))
            print(f"port {port} - open")
            self.open_ports.append(port)
            sock.close()
        except Exception as e:
            if self.logging:
                if e.args[0] == 111:
                    print(f"port {port} - closed")
                else:
                    print(f"port {port} - filtered")
            pass


def print_menu():
    print("")
    print("1. Scan ports")
    print("2. Vulnerability scan")
    print("3. Hosts scan")

def host_option():
    ip = input("ip: ")
    call(["nmap", ip, "-sn"])

def scan_option():
    while True:
        print("\nPort scan options:")
        print("1. Using portscanner(tcp connect)")
        print("2. Using tcp syn")
        print("3. Using tcp connect")
        print("")
        option = input("Option: ")
        try:
            option = int(option)
            if (1 <= option <= 3):
                break
        except Exception:
            pass
        print("Wrong input\n")
    ip = input("ip: ")
    ports = input("ports: ")
    if ports == "all":
        ports = "-p-"
    else:
        ports = "-p " + ports
    if option == 1:
        port_num = 0
        try:
            port_num = int(ports)
        except Exception:
            print("Port convertion error. Portscanner accept only port number")
            return
        scanner = portscanner(ip, port_num)
    elif option == 2:
        call(["nmap", ip, ports, "-sS"])
    elif option == 3:
        call(["nmap", ip, ports, "-sT"])


def vul_option():
    while True:
        print("\nVulnerability scan options:")
        print("1. Using nmap vulners")
        print("2. Using nse scripts based on vuln")
        option = input("Option: ")
        try:
            option = int(option)
            if option == 1 or option == 2:
                break
        except Exception:
            pass
        print("Wrong input\n")
    ip = input("ip: ")
    ports = input("ports: ")
    if ports == "all":
        ports = "-p-"
    else:
        ports = "-p " + ports

    if option == 1:
        # nmap vulners
        call(["nmap", "-sV", "--script", "nmap-vulners", ip, ports])
    elif option == 2:
        # vuln
        call(["nmap", "-Pn", "--script", "vuln", ip, ports])


if __name__ == "__main__":
    while True:
        print_menu()
        option = input("Menu option: ")
        try:
            option = int(option)
        except Exception:
            print("Wrong input\n\n")
            continue
        if option == 1:
            scan_option()
        elif option == 2:
            vul_option()
        elif option == 3:
            host_option()

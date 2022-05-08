import socket 
import time
from IPy import IP
import threading


ports = []   #to store open port
banners =[]   #to store open port banner


def port_scanner(target,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)
        try:
            target_ip =IP(target)     #check if target is an IP address
        except:
            target_ip = socket.gethostbyname(target)     #check if the target is a domain name or locahost

        s.connect((target, port))
        try:
            #get banner name
            banner_name = banner(s).decode()
            ports.append(port)

            #store banner_name in banners list
            banners.append(banner_name.strip())
        except Exception as e:
            print(e)
            pass
    except Exception as e:
        # print(e)
        pass

#get the banner name
def banner(s):
    return s.recv(1024)

# target = input("Enter Target IP address, localhost or domain name eg www.eg.com: ")
target = "192.168.100.4"

#scan for first 5051
# start = time.time()

# for port in range(1,5051):
#     thread = threading.Thread(target =port_scanner, args=[target,port])
#     thread.start()

for port in range(1, 5051):
    port_scanner(target, port)

# end = time.time()
# elapsed_time = end - start
# print(f"Elapsed time {elapsed_time}s")

print(f"Banners {len(banners)}:")

for banner in banners:
    print(banner)

with open("vul_banners.txt", "r") as file:
    data = file.read()
    for i in range(len(banners)):
        if banners[i] in data:
            print(f"[!]Vulneribility found: {banners[i]} at port {ports[i]}")
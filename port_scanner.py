import socket
import termcolor

def scan(target, ports):
	print(termcolor.colored("\n[*] Scanning result for " + str(target)), 'blue')
	for port in range(0, ports):
		scan_port(target, port)

def scan_port(ipaddress, port):
	try:
		sock = socket.socket()
		sock.connect((ipaddress, port))
		print("Port Opened" + str(port))
	except:
		#print("Port Closed" + str(port))
		pass

target = input("[*] Enter the target ipaddress to scan (you can go for multiple target also just separate them with a ,) ")
ports = int(input("[*] Enter how many ports you want to scan "))

if "," in target:
	print("[*] Scanning the target!")
	for ip_addr in target.split(","):
		scan(ip_addr.strip(" "), ports)

else:
	scan(target, ports)

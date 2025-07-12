import socket
import click

def ScanPort(ip, port):
	s = socket.socket()
	try:
		s.connect((ip, port))
		click.secho(f"[+] Port open {ip}:{port}", fg = "blue")
	except:
		click.secho(f"[-] Port closed {ip}:{port}", fg = "red")

if __name__ == "__main__":
	ip = input("Enter the IP of victim: ")
	click.secho("Scanning the IP...", fg = "green")
	for Port in range(1, 65535):
		ScanPort(ip, Port)
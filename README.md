### ArpSpoofer
ARPer is a tool made in python that can be used to launch ARP spoofing attacks on a network. It allows the attacker to send fake ARP messages to the network, associating their own MAC address with the IP address of a legitimate host. This allows the attacker to intercept and modify traffic intended for the legitimate host. By continuously sending fake ARP messages to the target, the attacker can effectively stop the target from accessing the Internet by preventing them from communicating with the gateway.

### Usage
First you need to install the requirements:
```
pip install -r requirements.txt
```
Then you can run the script as follows:
```
python arper.py -i <interface> -t <target> -g <gateway>

# example:
python arper.py -i eth0 -t 192.168.1.199 -g 192.168.1.1

# you can also use subnet format for multiple targets or ip range: 
python arper.py -i eth0 -t 192.168.1.0/24 -g 192.168.1.1
# or
python arper.py -i eth0 -t 192.168.1.100-200 -g 192.168.1.1
```
You may need to run it as root since it uses raw sockets and needs permissions to do so.


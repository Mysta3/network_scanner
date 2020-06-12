#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) # sets the ARP.pdst field to the input ip
    # arp_request.show() # shows the details of object
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # create a Ethernet class for packet construction
    # scapy.ls(scapy.Ether())  <-- lists all fields that can be used
    arp_request_broadcast = broadcast/arp_request # scapy allows combining objects using /
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print a table
    print("IP\t\t\tMAC Address\n--------------------")
    for element in answered_list: # access each element in a list
        print(element[1].psrc + "\t\t" + element[1].hwsrc)



scan("10.0.2.1/24")

